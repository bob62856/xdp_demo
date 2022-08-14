#include <linux/bpf.h>

/*
 * Comments from Linux Kernel:
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader.
 * End of comments

 * You can either use the helper header file below
 * so that you don't need to define it yourself:
 * #include <bpf/bpf_helpers.h> 
 */
#define SEC(NAME) __attribute__((section(NAME), used))

SEC("pass")
int xdp_pass(struct xdp_md *ctx) {
	__u64 now = get_ktime_ns();
	printk("now time is ")
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
