#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "include/bpf.h"
#include "get_count.h"

#define LPM_MAP_PATH "/sys/fs/bpf/xdp/globals/src_count"

void get_stats() {
	struct v4_key key = {0}, next_key = {0};
	struct v4_value value = {0};
	char src_ip[256];
	int fd;

	fd = bpf_obj_get(LPM_MAP_PATH);
	if (fd < 0) {
		printf("Failed to get map obj!\n");
		return;
	}
	
	while (true) {
		if (inet_ntop(AF_INET, (struct in_addr*)&key.saddr, src_ip, sizeof(src_ip)) == NULL) {
			printf("Failed to inet_ntop!\n");	
			return;
		}
	 	if (bpf_map_lookup_elem(fd, (void*)&key, (void*)&value)) {
	 		if (errno == ENOENT) {
	 			printf("There is no entry!\n");
				return;
	 		} else {
	 			printf("Failed to lookup elem form map!\n");
				return;
	 		}
	 	} else {
	 		printf("src is %s, count is %" PRIu64 "\n", src_ip, value.count);
	 	}
		if (bpf_map_get_next_key(fd, (void*)&key, (void*)&next_key)) {
			if (errno == ENOENT) {
				break;
			}
		}
		key = next_key;
	}
	return;
}

int main() {
	get_stats();
	return 0;
}
