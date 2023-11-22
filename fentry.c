//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
	u8 comm[16];
    u8 name[16];
};
struct event *unused __attribute__((unused));

SEC("fentry/dev_alloc_name")
int BPF_PROG(dev_alloc_name, struct net_device *dev, const char *name) {


	struct event *new_netdev_info;
	new_netdev_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!new_netdev_info) {
		return 0;
	}

    // Copy the name of the new netdev into the event
    bpf_probe_read_kernel_str(new_netdev_info->name, 16, name);

	bpf_get_current_comm(&new_netdev_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(new_netdev_info, 0);

	return 0;
}