/* Maglev Hashing scheduling module
 *
 * Authors for IPVS: Inju Song <inju.song@navercorp.com>
 *
 */

/* The mh algorithm is to assign a preference list of all the lookup
 * table positions to each destination and populate the table with
 * the most-preferred position of destinations. Then it is to select
 * destination with the hash key of source IP address through looking
 * up a the lookup table.
 *
 * The algorithm is detailed in:
 * [3.4 Consistent Hasing] 
 * https://www.usenix.org/system/files/conference/nsdi16/nsdi16-paper-eisenbud.pdf
 *
 */

/*
 * modified for OpenvSwitch 
 */

#include <errno.h>

#include "jhash.h"
#include "hash.h"
#include "maglev_hash_utils.h"
#include "maglev_hash.h"
#include "ofproto/ofproto-dpif.h"
#include "openvswitch/vlog.h"


//#define _USE_BUCKET_LIST 1

VLOG_DEFINE_THIS_MODULE(maglev_hash);

#define CONFIG_MH_TAB_INDEX	4 // zero based
static uint32_t mh_primes[] = {251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071};

static void mh_reset_state(struct maglev_state *s);
static int mh_get_dest_count(struct maglev_hash_service *svc);

///////////////////////////////////////////

static inline uint32_t mh_hash1(uint8_t *data, uint32_t len)
{
    return hash_bytes(data, len, 0);
}

static inline uint32_t mh_hash2(uint8_t *data, uint32_t len)
{
    return jhash_bytes(data, len, 0);
}

/* Helper function to determine if server is unavailable */
static inline uint32_t is_unavailable(struct maglev_dest *dest)
{
	return dest->weight <= 0 || dest->flags & MH_DEST_FLAG_DISABLE;
}

static int mh_permutate(struct maglev_state *s, struct maglev_hash_service *svc)
{
	struct maglev_dest_setup *ds;
	struct maglev_dest *dest;
	int lw;
	uint32_t hash_data = 0;

	/* If gcd is smaller then 1, number of dests or
	 * all last_weight of dests are zero. So, skip
	 * permutation for the dests.
	 */
	if (s->gcd < 1)
		return 0;

	/* Set dest_setup for the dests permutation */
	ds = &s->dest_setup[0];

    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
		hash_data = dest->dest_id;

		ds->offset = mh_hash2((uint8_t*)&hash_data, sizeof(hash_data)) % svc->table_size;
		ds->skip = mh_hash1((uint8_t*)&hash_data, sizeof(hash_data)) % (svc->table_size - 1) + 1;
		ds->perm = ds->offset;

		lw = dest->last_weight;
		ds->turns = ((lw / s->gcd) >> s->rshift) ? : (lw != 0);

		ds++;
	}

	return 0;
}

static int mh_populate(struct maglev_state *s, struct maglev_hash_service *svc)
{
	int n, c, dt_count;
	unsigned long *table;
	struct ovs_list *p;
	struct maglev_dest_setup *ds;
	struct maglev_dest *dest, *new_dest;

	/* If gcd is smaller then 1, number of dests or
	 * all last_weight of dests are zero. So, skip
	 * the population for the dests and reset lookup table.
	 */
	if (s->gcd < 1) {
		mh_reset_state(s);
		return 0;
	}

	table =  xcalloc(BITS_TO_LONGS(svc->table_size), sizeof(unsigned long));
	if (!table)
		return -ENOMEM;

	p = &svc->destinations;
	n = 0;
	dt_count = 0;
	while (n < svc->table_size) {
		if (p == &svc->destinations)
			p = p->next;

		ds = &s->dest_setup[0];
		while (p != &svc->destinations) {
			/* Ignore added server with zero weight */
			if (ds->turns < 1) {
				p = p->next;
				ds++;
				continue;
			}

			c = ds->perm;
			/* find the available slot */
			while (test_bit(c, table)) {
				/* Add skip, mod table_size */
				ds->perm += ds->skip;

				if (ds->perm >= svc->table_size)
					ds->perm -= svc->table_size;

				c = ds->perm;
			}

			set_bit(c, table);

			dest = s->lookup[c].dest;
			new_dest = CONTAINER_OF(p, struct maglev_dest, n_list);
			if (dest != new_dest) {
				s->lookup[c].dest =  new_dest;
			}

			if (++n == svc->table_size)
				goto out;

			if (++dt_count >= ds->turns) {
				dt_count = 0;
				p = p->next;
				ds++;
			}
		}
	}

out:
	free(table);
	return 0;
}

/* Get maglev_dest associated with supplied parameters. */
static struct maglev_dest* mh_lookup_dest(struct maglev_state *s,  uint32_t hash_data)
{
	if (!s) {
		return NULL;
	}

	unsigned int hash = hash_data % s->lookup_size;
	struct maglev_dest *dest = s->lookup[hash].dest;

	return (!dest || is_unavailable(dest)) ? NULL : dest;
}

/* As mh_lookup_dest, but with fallback if selected server is unavailable */
static inline struct maglev_dest *mh_lookup_dest_fallback(struct maglev_state *s, uint32_t hash_data)
{
	unsigned int offset, roffset;
	unsigned int hash, ihash;
	struct maglev_dest *dest;

	if (!s) {
		return NULL;
	}

	/* First try the dest it's supposed to go to */
	ihash = hash_data % s->lookup_size;
	dest = s->lookup[ihash].dest;
	if (!dest)
		return NULL;

	if (!is_unavailable(dest))
		return dest;

	dbg_print("selected unavailable server(id=%u), reselecting", dest->dest_id);

	/* If the original dest is unavailable, loop around the table
	 * starting from ihash to find a new dest
	 */
	for (offset = 0; offset < s->lookup_size; offset++) {
		roffset = offset + hash_data;
		hash = mh_hash1((uint8_t*)&roffset, sizeof(roffset)) % s->lookup_size;
		dest = s->lookup[hash].dest;
		if (!dest)
			break;

		if (!is_unavailable(dest))
			return dest;

		dbg_print("selected unavailable server(id=%u) (offset %u), reselecting", dest->dest_id, roffset);
	}

	return NULL;
}

/* Assign all the hash buckets of the specified table with the service. */
static int mh_build_lookup_table(struct maglev_state *s, struct maglev_hash_service *svc)
{
	int ret;
	int num_dests = mh_get_dest_count(svc);

	if (num_dests > svc->table_size)
		return -EINVAL;

	if (num_dests >= 1) {
		s->dest_setup = xcalloc(num_dests, sizeof(struct maglev_dest_setup));
		if (!s->dest_setup)
			return -ENOMEM;
	}

	mh_permutate(s, svc);

	ret = mh_populate(s, svc);
	if (ret < 0)
		goto out;

out:
	if (s->dest_setup) {
		free(s->dest_setup);
		s->dest_setup = NULL;
	}

	return ret;
}

static int mh_gcd_weight(struct maglev_hash_service *svc)
{
	struct maglev_dest *dest;
	int weight;
	int g = 0;

	LIST_FOR_EACH(dest, n_list, &svc->destinations) {
		weight = dest->last_weight;
		if (weight > 0) {
			if (g > 0)
				g = gcd(weight, g);
			else
				g = weight;
		}
	}

	return g;
}

/* To avoid assigning huge weight for the MH table,
 * calculate shift value with gcd.
 */
static int mh_shift_weight(struct maglev_hash_service *svc, int gcd)
{
	struct maglev_dest *dest;
	int new_weight, weight = 0;
	int mw, shift;

	/* If gcd is smaller then 1, number of dests or
	 * all last_weight of dests are zero. So, return
	 * shift value as zero.
	 */
	if (gcd < 1)
		return 0;

	LIST_FOR_EACH(dest, n_list, &svc->destinations) {
		new_weight = dest->last_weight;
		if (new_weight > weight)
			weight = new_weight;
	}

	/* Because gcd is greater than zero,
	 * the maximum weight and gcd are always greater than zero
	 */
	mw = weight / gcd;

	int tab_bits = bitlen(svc->table_size)/2;

	/* shift = occupied bits of weight/gcd - MH highest bits */
	shift = fls(mw) - tab_bits;
	return (shift >= 0) ? shift : 0;
}

static struct maglev_state* mh_alloc_state(uint32_t table_size)
{
	struct maglev_state *s;

	/* Allocate the MH table for this service */
	s = xcalloc(1, sizeof(struct maglev_state));
	if (!s)
		return NULL;

	s->lookup = xcalloc(table_size, sizeof(struct maglev_lookup));
	if (!s->lookup) {
		free(s);
		return NULL;
	}

	s->lookup_size = table_size;

	/* refcnt starts 1 */
	ovs_refcount_init(&s->refcnt);

	VLOG_INFO("Alloc Maglev State: state=%p, lookup_size=%u", s, table_size);

	return s;
}

static void mh_init_state(struct maglev_state *s, struct maglev_hash_service *svc)
{
	s->gcd = mh_gcd_weight(svc);
	s->rshift = mh_shift_weight(svc, s->gcd);
}

/* Reset all the hash buckets of the specified table. */
static void mh_reset_state(struct maglev_state *s)
{
	int i;

	if (!s || !s->lookup) {
		return;
	}

	for (i = 0; i < s->lookup_size; i++) {
		s->lookup[i].dest = NULL;
	}
}

static void mh_free_state(struct maglev_state *s)
{
	if (!s)
		return;

	VLOG_INFO("Free Maglev State: state=%p, lookup_size=%u", s, s->lookup_size);

	/* refcnt starts 1 */
	if (ovs_refcount_read(&s->refcnt) > 1) {
		VLOG_WARN("WARNING: Maglev State under referenced: refcnt=%d", ovs_refcount_read(&s->refcnt));
	}

	mh_reset_state(s);

	if (s->lookup) {
		free(s->lookup);
		s->lookup = NULL;
	}

	free(s);
}

static void mh_ref_state(struct maglev_state *s)
{
	ovs_refcount_ref(&s->refcnt);
}

static void mh_unref_state(struct maglev_state *s)
{
	/* 2 means the last reference because refcnt starts 1 */ 
	if (ovs_refcount_unref(&s->refcnt) == 2) {
		mh_free_state(s);
	}
}

static void mh_attach_state(struct maglev_state *s, struct maglev_hash_service *svc)
{
	struct maglev_state *old = svc->mh_state;
	if (old) {
		mh_unref_state(old);
	}

	if (s) {
		mh_ref_state(s);
	}

	svc->mh_state = s;
}

static struct maglev_state* mh_get_state(struct maglev_hash_service *svc)
{
	struct maglev_state *s = svc->mh_state;
	if (s) {
		mh_ref_state(s);
	}

	return s;
}

static void mh_put_state(struct maglev_state *s)
{
	if (s) {
		mh_unref_state(s);
	}
}

static void mh_free_dest(struct maglev_hash_service *svc) 
{
	struct maglev_dest *dest, *next;
	LIST_FOR_EACH_SAFE(dest, next, n_list, &svc->destinations) {
		ovs_list_remove(&dest->n_list);
		free(dest);
	}
}

static struct maglev_dest* mh_get_dest(uint32_t id, struct maglev_hash_service *svc) 
{
	struct maglev_dest *dest;

    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
		if (dest->dest_id == id) {
			return dest;
		}
	}

	return NULL;
}

static void mh_set_dest_weight(struct maglev_dest* dest, uint32_t weight)
{
	dest->weight = weight;
	dest->last_weight = weight;
}


static int mh_get_dest_count(struct maglev_hash_service *svc)
{
	int cnt=0;
	struct maglev_dest *dest;

    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
		cnt ++;
	}

	return cnt;
}

static struct maglev_hash_service* mh_alloc_service(uint32_t table_size) 
{
    struct maglev_hash_service* svc;

	svc = xcalloc(1, sizeof(struct maglev_hash_service));
	if (!svc) {
		VLOG_ERR("failed to alloc memory for Maglev Hash SVC (%lu bytes)", sizeof(struct maglev_hash_service));
		return NULL;
	}

    ovs_list_init(&svc->destinations);
	svc->table_size = table_size;

	/* refcnt starts 1 */
	ovs_refcount_init(&svc->refcnt);
	atomic_count_init(&svc->version, 1);

	VLOG_INFO("Alloc Maglev Hash SVC: svc=%p, table_size=%u", svc, table_size);
	return svc;
}

static void mh_free_service(struct maglev_hash_service* svc)
{
	VLOG_INFO("Free Maglev Hash SVC: svc=%p, table_size=%u", svc, svc->table_size);

	mh_attach_state(NULL, svc);
	mh_free_dest(svc);

	free(svc);
}

static void mh_inc_version(struct maglev_hash_service *svc) 
{
	atomic_count_inc(&svc->version);
}

static int mh_add_dest(uint32_t id, uint16_t weight, void *data, struct maglev_hash_service *svc)
{
	int ret = 0;
	struct maglev_dest* dest = mh_get_dest(id, svc);

	if (dest != NULL) {
		atomic_count_set(&dest->version, atomic_count_get(&svc->version));

		if ((uint16_t)dest->weight != weight) {
            dbg_print("changed weight: id=%u, weight: %u -> %u", 
					  dest->dest_id, dest->weight, weight);

			mh_set_dest_weight(dest, weight);
			ret = 1;

		}

		if (dest->data != data) {
			dest->data = data;
		}

		return ret;
	}

	dest = xcalloc(1, sizeof(struct maglev_dest));
	if (dest == NULL) {
		VLOG_ERR("failed to alloc memory for dest: size=%lu, id=%u, weight=%u", 
				 sizeof(struct maglev_dest), id, weight);

		return -ENOMEM;
	}

	ovs_list_init(&dest->n_list);
	atomic_count_set(&dest->version, atomic_count_get(&svc->version));

	dest->weight = weight;
	dest->last_weight = weight;
	dest->dest_id = id;
	dest->data = data;

	dbg_print("add dest: id=%u(%p), weight=%d", dest->dest_id, dest, dest->weight);

	ovs_list_push_back(&svc->destinations, &dest->n_list);

	return 1;
}

static int mh_cleanup_old_dest(struct maglev_hash_service *svc)
{
	struct maglev_dest *dest, *next;
	uint32_t ver = atomic_count_get(&svc->version);
	int cnt=0;

	LIST_FOR_EACH_SAFE(dest, next, n_list, &svc->destinations) {
		if (atomic_count_get(&dest->version) == ver) {
			continue;
		}

		dbg_print("free old dest: id=%u(%p), weight=%d", dest->dest_id, dest, dest->weight);

		/* old version */
		ovs_list_remove(&dest->n_list);
		free(dest);

		cnt ++;
	}

	return cnt;
}

static int mh_build_hash_table(struct maglev_hash_service *svc)
{
	int ret;
	struct maglev_state *s;
	int num_dests = mh_get_dest_count(svc);

    VLOG_INFO("Building Maglev Hash Lookup Table: svc=%p, table_size=%u, dest cnt=%d", 
              svc,
              svc->table_size, 
              num_dests);


	/* Allocate the MH table for this service */
	s =  mh_alloc_state(svc->table_size);
	if (!s)
		return -ENOMEM;

	mh_init_state(s, svc);

	dbg_print("lookup table (memory=%zdbytes) allocated for current service",
		  sizeof(struct maglev_lookup) * svc->table_size);

	/* Assign the lookup table with current dests */
	ret = mh_build_lookup_table(s, svc);
	if (ret < 0) {
		mh_free_state(s);
		return ret;
	}

	/* No more failures, attach state */
	/* the old one would be released if exists */
	mh_attach_state(s, svc);

	return 0;
}

static int mh_dump_lookup_table(struct maglev_hash_service *svc) 
{
	struct dump_cnt {
		uint32_t id;
		uint32_t weight;
		uint32_t cnt;
	};

	struct maglev_state *s = mh_get_state(svc);
	if (!s)
		return 0;

	int num_dests = mh_get_dest_count(svc);
	struct maglev_dest *dest;
	int i,j;
	struct dump_cnt *dcnt = xcalloc(num_dests, sizeof(struct dump_cnt));

	i=0;
    LIST_FOR_EACH (dest, n_list, &svc->destinations) {
		dcnt[i].id = (uint64_t)dest->dest_id;
		dcnt[i].weight = dest->weight;
		dcnt[i].cnt = 0;
		i ++;
	}

	for (i=0; i<svc->table_size; i++) {
		dest = svc->mh_state->lookup[i].dest;
		if (dest == NULL) {
			continue;
		}

		for (j=0; j<num_dests; j++) { 
			if (dest->dest_id == dcnt[j].id) {
				dcnt[j].cnt ++;
			}
		}
	}

	for (i=0; i<num_dests; i++) {
		dbg_print("Dest(%d): id=%u, weight=%u, lookup cnt=%u", 
				  i, dcnt[i].id, dcnt[i].weight, dcnt[i].cnt);
	}

	if (s)
		mh_put_state(s);

	free(dcnt);

	return 0;
}

static void mh_build(struct group_dpif *group)
{
    struct maglev_hash_service* mh_svc;
    struct ofputil_bucket *bucket;

    if (group->mh_svc) {
        mh_free_service(group->mh_svc);
    }

    group->mh_svc = NULL;

    mh_svc = mh_alloc_service(mh_primes[CONFIG_MH_TAB_INDEX]);
    if (mh_svc == NULL) {
        VLOG_ERR("failed to alloc a new Maglev Hash SVC: group=%d", group->up.group_id);
        return;
    }

    VLOG_INFO("Start building a new Maglev Hash SVC: group=%d, mh_svc=%p", group->up.group_id, mh_svc);

    LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
        mh_add_dest(bucket->bucket_id, bucket->weight, bucket, mh_svc);
    }

    int ret;
    ret = mh_build_hash_table(mh_svc);
    if (ret != 0) {
        VLOG_ERR("failed to build Maglev Hash Lookup Table: group=%d, mh_svc=%p", group->up.group_id, mh_svc);
        mh_free_service(mh_svc);
    }

    if (mh_svc) 
        mh_dump_lookup_table(mh_svc);

    // XXX: use refcnt
    group->mh_svc = mh_svc;
}

static void mh_modify(struct group_dpif *new, struct group_dpif *old)
{
    struct ofputil_bucket *bucket;
    uint32_t changed = 0;
    struct maglev_hash_service* mh_svc = old->mh_svc;

    VLOG_INFO("Start modifying the Maglev Hash SVC: group=%d, mh_svc=%p", 
              new->up.group_id, mh_svc);

    // XXX: use refcnt
    old->mh_svc = NULL;

    if (mh_svc == NULL) {
        VLOG_INFO("old Maglev Hash SVC is not available: group=%d, mh_svc=%p", old->up.group_id, old);
        return mh_build(new);
    }

    mh_inc_version(mh_svc);

    LIST_FOR_EACH (bucket, list_node, &new->up.buckets) {
        if (mh_add_dest(bucket->bucket_id, bucket->weight, bucket, mh_svc) > 0) {
            changed ++;
        }
    }

    if (mh_cleanup_old_dest(mh_svc) > 0) {
        changed ++;
    }

	/* for debug */
    LIST_FOR_EACH (bucket, list_node, &old->up.buckets) {
        VLOG_INFO("old group=%d(%p), bucket=%u(%p), weight=%u", 
                  old->up.group_id, old, bucket->bucket_id, bucket, bucket->weight);
    }

    if (changed > 0) {
        int ret;

        ret = mh_build_hash_table(mh_svc);
        if (ret != 0) {
            VLOG_ERR("failed to build Maglev Hash Lookup Table: group=%d, mh_svc=%p", new->up.group_id, mh_svc);
            mh_free_service(mh_svc);
            mh_svc = NULL;
        }
    }

    if (mh_svc)
        mh_dump_lookup_table(mh_svc);

    // XXX: use refcnt
    new->mh_svc = mh_svc;
}

/* Maglev Hashing lookup */
static struct maglev_dest* mh_lookup_(struct maglev_hash_service *svc, uint32_t hash_data)
{
	struct maglev_dest *dest = NULL;
	struct maglev_state *s;

	s = mh_get_state(svc);
	if (!s)
		goto out;

	if (svc->flags & MH_FLAG_FALLBACK)
		dest = mh_lookup_dest_fallback(s, hash_data);
	else
		dest = mh_lookup_dest(s, hash_data);

out:
	if (s)
		mh_put_state(s);

	return dest;
}

#ifdef _USE_BUCKET_LIST
static struct ofputil_bucket* mh_get_bucket_by_id(uint32_t id, struct group_dpif *group)
{
	struct ofputil_bucket* bucket;

	LIST_FOR_EACH (bucket, list_node, &group->up.buckets) {
		if (id == bucket->bucket_id) {
			return bucket;
		}
	}

	VLOG_INFO("MH: Not Found bucket: group-id=%u, bucket-id=%u", group->up.group_id, id);
	return NULL;
}
#endif


/////////////////////////////

void mh_construct(struct group_dpif *new_group, struct group_dpif *old_group)
{
	VLOG_INFO("Construct Maglev Hash: new group=%u(%p), old group=%p", 
			  new_group->up.group_id, 
			  new_group, old_group);

	if (old_group == NULL || old_group->mh_svc == NULL) {
		mh_build(new_group);
	}
	else {
		mh_modify(new_group, old_group);
	}
}

void mh_destruct(struct group_dpif *group)
{
	if (!group || group->mh_svc)
		return;

	struct maglev_hash_service *svc = group->mh_svc;

	VLOG_INFO("Destruct Maglev Hash: group=%d(%p), mh_svc=%p, method=%d", 
			  group->up.group_id, group, svc, group->selection_method);

	mh_free_service(group->mh_svc);
}

struct ofputil_bucket* mh_lookup(struct group_dpif *group, uint32_t hash_data)
{
	if (group == NULL) {
		return NULL;
	}

	struct maglev_dest *dest = mh_lookup_(group->mh_svc, hash_data);
	if (dest == NULL) {
		return NULL;
	}

#ifdef _USE_BUCKET_LIST
	struct ofputil_bucket *bucket = mh_get_bucket_by_id(dest->dest_id, group);
	return bucket;
#else
	return (struct ofputil_bucket *)dest->data;
#endif
}


