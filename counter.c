
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

SEC("xdp")

int count_packets(struct xdp_md *ctx){
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
       (*count)++;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
