#include "include/common.h"

static __always_inline void init_stats();

struct v4_key {
	__u32 prefix;
	__u32 saddr;
};

struct v4_value {
	__u64 count;	
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 id;
    __u32 pinning;
	__u32 inner_id;
	__u32 inner_idx;
};


struct bpf_map_def __section("maps") src_count = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct v4_key),
	.value_size = sizeof(struct v4_value),
	.max_entries = 10000, 
	.pinning = PIN_GLOBAL_NS,
}; 
