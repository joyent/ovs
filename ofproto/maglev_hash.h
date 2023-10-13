#ifndef __MAGLEV_HASH_H__
#define __MAGLEV_HASH_H__

#include "ovs-atomic.h"
#include "openvswitch/list.h"

#define MH_FLAG_FALLBACK     0x0001
#define MH_DEST_FLAG_DISABLE 0x0001
#define MH_DEST_FLAG_DIRTY	 0x0002

struct maglev_dest_setup {
    uint32_t    offset; /* starting offset */
    uint32_t    skip;   /* skip */
    uint32_t    perm;   /* next_offset */
    int         turns;  /* weight / gcd() and rshift */
};

struct maglev_dest {
    struct ovs_list     n_list;         /* for the dests in the service */
    struct atomic_count version;        /* version number */
    uint32_t            gid;            /* group id */
    uint32_t            dest_id;        /* destination ID */
    uint32_t            flags;          /* dest status flags */
    uint32_t            weight;         /* server weight. 0: disable */
    uint32_t            last_weight;    /* same with weight */
    void                *data;          /* user data */
};

struct maglev_dirty_dest {
    int num_dirty;
    struct maglev_dest **dirty;
};

struct maglev_lookup {
    struct maglev_dest  *dest[2];  /* real server (cache), [primary, secondary] */
};

struct maglev_state {
    struct ovs_refcount         refcnt;         /* init 1 */
    struct maglev_lookup        *lookup;
    uint32_t                    lookup_size;    /* same with table_size */
    struct maglev_dest_setup    *dest_setup;
    int                         gcd;
    int                         rshift;
};

struct maglev_hash_service {
    struct ovs_refcount refcnt;         /* init 1 */
    struct atomic_count version;        /* version number */
    uint32_t            flags;          /* service status flags */
    uint32_t            table_size;     /* should be prime numder */
    struct ovs_list     destinations;   /* real server d-linked list */
    struct maglev_state *mh_state; 
};

struct group_dpif;
struct ofputil_bucket;

////////////////////////////////////////

void                   mh_construct(struct group_dpif *new_group, struct group_dpif *old_group);
void                   mh_destruct(struct group_dpif *group);
struct ofputil_bucket* mh_lookup(struct group_dpif *group, uint32_t hash_data, uint8_t try_use_secondary);



#endif
