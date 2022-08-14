#include <stdint.h> 

struct v4_key {
	uint32_t prefix;
	uint32_t saddr;
};

struct v4_value {
	uint64_t count;	
};

// struct bpf_map_def {
//     uint32_t type;
//     uint32_t key_size;
//     uint32_t value_size;
//     uint32_t max_entries;
//     uint32_t map_flags;
//     uint32_t id;
//     uint32_t pinning;
// 	uint32_t inner_id;
// 	uint32_t inner_idx;
// };

