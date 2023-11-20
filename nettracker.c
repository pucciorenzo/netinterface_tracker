//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

SEC("kprobe/dev_alloc_name")
int kprobe_dev_alloc_name() {
	u32 key     = 0;
	u64 initval = 1;
    u64 *valp;

	// valp = bpf_map_lookup_elem(&kprobe_map, &key);
	// if (valp == NULL) {
	// 	bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
	// 	return 0;
	// }
	// __sync_fetch_and_add(valp, 1);

	bpf_printk("dev_alloc_name\n");

	return 0;
}