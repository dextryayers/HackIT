#pragma once

/**
 * xdp_kern.h — eBPF / XDP kernel-program header.
 *
 * Shared definitions for the XDP datapath loaded into the kernel.
 * Every field is aligned to native eBPF access patterns.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ------------------------------------------------------------------ */
/*  XDP action constants (mirror <linux/bpf.h> for convenience)         */
/* ------------------------------------------------------------------ */
#ifndef XDP_ABORTED
#define XDP_ABORTED 0
#endif
#ifndef XDP_DROP
#define XDP_DROP    1
#endif
#ifndef XDP_PASS
#define XDP_PASS    2
#endif
#ifndef XDP_TX
#define XDP_TX      3
#endif

/* ------------------------------------------------------------------ */
/*  BPF map key types                                                  */
/* ------------------------------------------------------------------ */
struct xdp_config_key {
    __u32 ifindex;                       /* per-interface config slot   */
};

struct xdp_stats_key {
    __u32 cpu;                           /* per-CPU stats slot          */
};

/* ------------------------------------------------------------------ */
/*  Runtime configuration passed from user-space                        */
/* ------------------------------------------------------------------ */
struct xdp_config_t {
    __u32 action;                        /* default XDP action          */
    __u64 packet_count;                  /* packets to send (0 = +inf)  */
    __u32 target_ip;                     /* destination IPv4 (network)  */
    __u16 target_port;                   /* destination port (network)  */
    __u32 spoof_base_ip;                 /* base address for spoofing   */
    __u16 padding;                       /* natural alignment           */
};

/* ------------------------------------------------------------------ */
/*  Per-CPU statistics                                                 */
/* ------------------------------------------------------------------ */
struct xdp_stats_t {
    __u64 packets_sent;
    __u64 packets_dropped;
    __u64 bytes_sent;
};

/* ------------------------------------------------------------------ */
/*  BPF map definitions                                                */
/* ------------------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, struct xdp_config_key);
    __type(value, struct xdp_config_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_config_map __section("maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, struct xdp_stats_key);
    __type(value, struct xdp_stats_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} xdp_stats_map __section("maps");

/* ------------------------------------------------------------------ */
/*  Inline helpers — ethernet header parsing                           */
/* ------------------------------------------------------------------ */
static __always_inline struct ethhdr *
parse_eth(void *data, void *data_end)
{
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return NULL;
    return eth;
}

/* ------------------------------------------------------------------ */
/*  Inline helpers — IPv4 header parsing                               */
/* ------------------------------------------------------------------ */
static __always_inline struct iphdr *
parse_ip(void *data, void *data_end, struct ethhdr *eth)
{
    /* Only handle IPv4 */
    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return NULL;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
    if ((void *)(ip + 1) > data_end)
        return NULL;
    return ip;
}
