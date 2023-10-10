#ifndef __MAGLEV_HASH_UTILS_H__
#define __MAGLEV_HASH_UTILS_H__

#define MH_DEBUG 1
#ifdef MH_DEBUG
# define dbg_print(fmt, ...) do { \
        VLOG_INFO("%s:%d:%s: " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while(0)
#else
#  define dbg_print(fmt, ...) (void)0
#endif

#define BITS_PER_BYTE     8
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define swap(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

static inline int test_bit(int nr, const volatile void * addr)
{
    return (1UL & (((const int *) addr)[nr >> 5] >> (nr & 31))) != 0UL;
}

static inline void set_bit(unsigned long nr, volatile void * addr)
{
    int *m = ((int *) addr) + (nr >> 5);

    *m |= 1 << (nr & 31);
}

static inline int fls(int x)
{
    int r;

    /*
     * AMD64 says BSRL won't clobber the dest reg if x==0; Intel64 says the
     * dest reg is undefined if x==0, but their CPU architect says its
     * value is written to set it to the same as before, except that the
     * top 32 bits will be cleared.
     *
     * We cannot do this on 32 bits because at the very least some
     * 486 CPUs did not behave this way.
     */
    asm("bsrl %1,%0"
        : "=r" (r)
        : "rm" (x), "0" (-1));
    return r + 1;
}

static inline uint32_t count_of_leading_0_bits(const uint32_t x) {
    return (x == 0) ? 32 : __builtin_clz(x);
}

static inline uint32_t bitlen(const uint32_t x) {
    return 32 - count_of_leading_0_bits(x);
}

static inline unsigned long gcd(unsigned long a, unsigned long b)
{
    unsigned long r;

    if (a < b)
        swap(a, b);

    if (!b)
        return a;

    while ((r = a % b) != 0) {
        a = b;
        b = r;
    }

    return b;
}

#endif
