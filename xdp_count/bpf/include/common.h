#ifndef __BPF_CTX_COMMON_H_
#define __BPF_CTX_COMMON_H_

#define  __ctx_buff xdp_md 
#define PIN_GLOBAL_NS   2

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "stddef.h"

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) \
    (* NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef printk
#define printk(fmt, ...) \
    do {                 \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    } while (0)
#endif

static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);
static void *BPF_FUNC(map_lookup_elem, const void *map, const void *key);
static int BPF_FUNC(map_update_elem, const void *map, const void *key,
        const void *value, __u64 flags);

static __always_inline void *
ctx_data(const struct __ctx_buff *ctx)
{
    return (void *)(unsigned long)ctx->data;
}

static __always_inline void *
ctx_data_end(const struct __ctx_buff *ctx)
{
    return (void *)(unsigned long)ctx->data_end;
}

static __always_inline bool
__revalidate_data(struct __ctx_buff *ctx, void **data_, void **data_end_,
                  void **l3, const __u32 l3_len)
{
    void *data, *data_end;
    const __u32 total_len = ETH_HLEN + l3_len;

    data = ctx_data(ctx);
    data_end = ctx_data_end(ctx);
    if (data + total_len > data_end)
        return false;

    *data_ = data;
    *data_end_ = data_end;

    *l3 = data + ETH_HLEN;

    return true;
}

/* revalidate_data() initializes the provided pointers from the ctx.
 * Returns true if 'ctx' is long enough for an IP header of the provided type,
 * false otherwise.
 */
#define revalidate_data(ctx, data, data_end, ip)            \
    __revalidate_data(ctx, data, data_end, (void **)ip, sizeof(**ip))

#endif /* __BPF_CTX_COMMON_H_ */
