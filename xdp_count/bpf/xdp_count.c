#include "xdp_count.h"

__section("prog_count") int get_count(struct xdp_md *ctx) {
	struct v4_key key = {0};
	struct v4_value value = {0};
	struct v4_value *stats = NULL;
	void *data = NULL;
	void *data_end = NULL;
	struct iphdr *iph = NULL;

	revalidate_data(ctx, &data, &data_end, &iph);
	if (iph == NULL) return XDP_PASS;
	
	init_stats();

	key.prefix = 32;
	key.saddr = iph->saddr;

	stats = map_lookup_elem(&src_count, (void*)&key);		
	if (stats == NULL) {
		value.count = 1;
		map_update_elem(&src_count, (void*)&key, (void*)&value, BPF_ANY);		
	} else {
		stats->count++;
	}

	return XDP_PASS;
}

static __always_inline void init_stats() {
	struct v4_key all_key = {0};
	struct v4_value all_value = {0};
	struct v4_value *all_stats = NULL;
	all_stats = map_lookup_elem(&src_count, (void*)&all_key);		
	if (all_stats == NULL) {
		map_update_elem(&src_count, (void*)&all_key, (void*)&all_value, BPF_ANY);		
	} else {
		all_stats->count++;
	}
	return;
}

char _license[] __section("license") = "GPL";
