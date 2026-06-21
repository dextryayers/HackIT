#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <linux/filter.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "optimize.h"

#define MAX_PACKET_SIZE    65536
#define MAX_STATS_SLOTS    256
#define SNAPLEN            65535
#define STATS_INTERVAL_MS  1000
#define HISTOGRAM_BUCKETS  11

static const int BUCKET_LIMITS[HISTOGRAM_BUCKETS] = {
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
};

typedef struct {
    long long   timestamp;
    int         packet_size;
    uint8_t     protocol;
    uint16_t    src_port;
    uint16_t    dst_port;
    char        src_ip[64];
    char        dst_ip[64];
    uint8_t     ttl;
    uint8_t     tcp_flags;
} PacketInfo;

typedef struct {
    atomic_llong total_packets;
    atomic_llong total_bytes;
    atomic_llong ip_packets;
    atomic_llong tcp_packets;
    atomic_llong udp_packets;
    atomic_llong icmp_packets;
    atomic_llong other_packets;
    atomic_llong size_histogram[HISTOGRAM_BUCKETS];
    atomic_llong protocol_counts[256];
    double      current_rate;
    double      peak_rate;
    long long   last_stats_time;
    long long   interval_bytes;
    long long   interval_packets;
} PacketStats;

typedef struct {
    char        iface[64];
    int         sock;
    int         promiscuous;
    int         timeout_s;
    int         max_packets;
    int         filter_port;
    char        filter_proto[16];
    bool        summary_only;
    bool        running;
    PacketStats stats;
    atomic_int  packet_count;
    long long   start_time;
} InspectContext;

static const char* proto_name(uint8_t proto) {
    switch (proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 89: return "OSPF";
        case 132: return "SCTP";
        default: return "OTHER";
    }
}

static const char* tcp_flags_str(uint8_t flags) {
    static char buf[16];
    buf[0] = 0;
    if (flags & 0x02) strcat(buf, "SYN ");
    if (flags & 0x10) strcat(buf, "ACK ");
    if (flags & 0x01) strcat(buf, "FIN ");
    if (flags & 0x04) strcat(buf, "RST ");
    if (flags & 0x08) strcat(buf, "PSH ");
    if (flags & 0x20) strcat(buf, "URG ");
    if (buf[0] == 0) strcpy(buf, "NONE");
    return buf;
}

static int create_promiscuous_socket(const char* iface, int promiscuous) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (unlikely(sock < 0)) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        return sock;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (promiscuous) {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
            ifr.ifr_flags |= IFF_PROMISC;
            ioctl(sock, SIOCSIFFLAGS, &ifr);
        }
    }

    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct timeval tv = { 1, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (iface && iface[0]) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = if_nametoindex(iface);
        if (sll.sll_ifindex == 0) {
            fprintf(stderr, "Interface not found: %s\n", iface);
            close(sock);
            return -1;
        }
        bind(sock, (struct sockaddr*)&sll, sizeof(sll));
    }

    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));

    return sock;
}

static int compile_bpf_filter(struct sock_fprog* fprog, const char* proto, int port) {
    if (!proto || !proto[0]) return 0;

    static struct sock_filter bpf_code[32];
    int len = 0;

#define BPF_BLOCK(c_, jt_, jf_, k_) do { \
    bpf_code[len].code = (uint16_t)(c_); \
    bpf_code[len].jt = (uint8_t)(jt_); \
    bpf_code[len].jf = (uint8_t)(jf_); \
    bpf_code[len].k = (uint32_t)(k_); \
    len++; } while(0)

    if (strcasecmp(proto, "tcp") == 0) {
        BPF_BLOCK(BPF_LD | BPF_B | BPF_ABS, 0, 0, 9);
        BPF_BLOCK(BPF_JMP | BPF_JEQ | BPF_K, 0, 4, 6);
        if (port > 0) {
            BPF_BLOCK(BPF_LD | BPF_H | BPF_ABS, 0, 0, 20);
            BPF_BLOCK(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (uint32_t)htons((uint16_t)port));
            BPF_BLOCK(BPF_LD | BPF_H | BPF_ABS, 0, 0, 22);
            BPF_BLOCK(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (uint32_t)htons((uint16_t)port));
        }
        BPF_BLOCK(BPF_RET | BPF_K, 0, 0, SNAPLEN);
        BPF_BLOCK(BPF_RET | BPF_K, 0, 0, 0);
    } else if (strcasecmp(proto, "udp") == 0) {
        BPF_BLOCK(BPF_LD | BPF_B | BPF_ABS, 0, 0, 9);
        BPF_BLOCK(BPF_JMP | BPF_JEQ | BPF_K, 0, 4, 17);
        if (port > 0) {
            BPF_BLOCK(BPF_LD | BPF_H | BPF_ABS, 0, 0, 20);
            BPF_BLOCK(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (uint32_t)htons((uint16_t)port));
            BPF_BLOCK(BPF_LD | BPF_H | BPF_ABS, 0, 0, 22);
            BPF_BLOCK(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (uint32_t)htons((uint16_t)port));
        }
        BPF_BLOCK(BPF_RET | BPF_K, 0, 0, SNAPLEN);
        BPF_BLOCK(BPF_RET | BPF_K, 0, 0, 0);
    } else if (strcasecmp(proto, "icmp") == 0) {
        BPF_BLOCK(BPF_LD | BPF_B | BPF_ABS, 0, 0, 9);
        BPF_BLOCK(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 1);
        BPF_BLOCK(BPF_RET | BPF_K, 0, 0, SNAPLEN);
        BPF_BLOCK(BPF_RET | BPF_K, 0, 0, 0);
    } else {
        return 0;
    }
#undef BPF_BLOCK

    fprog->filter = bpf_code;
    fprog->len = len;
    return len;
}

HOT static int parse_ethernet(const uint8_t* pkt, int len, char** payload, int* payload_len, uint16_t* eth_type) {
    if (len < (int)sizeof(struct ethhdr)) return -1;
    struct ethhdr* eth = (struct ethhdr*)pkt;
    *eth_type = ntohs(eth->h_proto);
    *payload = (char*)(pkt + sizeof(struct ethhdr));
    *payload_len = len - sizeof(struct ethhdr);
    if (*eth_type == 0x8100 && *payload_len > 4) {
        *eth_type = ntohs(*(uint16_t*)(*payload + 2));
        *payload += 4;
        *payload_len -= 4;
    }
    return 0;
}

HOT static int parse_ip(const uint8_t* pkt, int len, PacketInfo* pi, char** payload, int* payload_len) {
    if (len < (int)sizeof(struct iphdr)) return -1;
    struct iphdr* ip = (struct iphdr*)pkt;
    int iphl = ip->ihl * 4;
    if (iphl < 20 || iphl > len) return -1;

    pi->protocol = ip->protocol;
    pi->ttl = ip->ttl;

    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;
    strncpy(pi->src_ip, inet_ntoa(src), sizeof(pi->src_ip) - 1);
    strncpy(pi->dst_ip, inet_ntoa(dst), sizeof(pi->dst_ip) - 1);

    *payload = (char*)pkt + iphl;
    *payload_len = len - iphl;
    return 0;
}

HOT static int parse_tcp(const uint8_t* pkt, int len, PacketInfo* pi) {
    if (len < (int)sizeof(struct tcphdr)) return -1;
    struct tcphdr* tcp = (struct tcphdr*)pkt;
    pi->src_port = ntohs(tcp->source);
    pi->dst_port = ntohs(tcp->dest);
    pi->tcp_flags = 0;
    if (tcp->syn) pi->tcp_flags |= 0x02;
    if (tcp->ack) pi->tcp_flags |= 0x10;
    if (tcp->fin) pi->tcp_flags |= 0x01;
    if (tcp->rst) pi->tcp_flags |= 0x04;
    if (tcp->psh) pi->tcp_flags |= 0x08;
    if (tcp->urg) pi->tcp_flags |= 0x20;
    return 0;
}

HOT static int parse_udp(const uint8_t* pkt, int len, PacketInfo* pi) {
    if (len < (int)sizeof(struct udphdr)) return -1;
    struct udphdr* udp = (struct udphdr*)pkt;
    pi->src_port = ntohs(udp->source);
    pi->dst_port = ntohs(udp->dest);
    return 0;
}

HOT static int parse_icmp(const uint8_t* pkt, int len, PacketInfo* pi) {
    if (len < 8) return -1;
    uint8_t type = pkt[0];
    uint8_t code = pkt[1];
    (void)type;
    (void)code;
    return 0;
}

HOT static void update_stats(PacketStats* stats, int size, uint8_t protocol) {
    atomic_fetch_add(&stats->total_packets, 1);
    atomic_fetch_add(&stats->total_bytes, size);
    atomic_fetch_add(&stats->interval_packets, 1);
    atomic_fetch_add(&stats->interval_bytes, size);
    atomic_fetch_add(&stats->protocol_counts[protocol], 1);

    switch (protocol) {
        case 6: atomic_fetch_add(&stats->tcp_packets, 1); break;
        case 17: atomic_fetch_add(&stats->udp_packets, 1); break;
        case 1: atomic_fetch_add(&stats->icmp_packets, 1); break;
        default: atomic_fetch_add(&stats->other_packets, 1); break;
    }
    atomic_fetch_add(&stats->ip_packets, 1);

    for (int i = 0; i < HISTOGRAM_BUCKETS; i++) {
        if (size <= BUCKET_LIMITS[i]) {
            atomic_fetch_add(&stats->size_histogram[i], 1);
            break;
        }
    }
}

static void print_stats(PacketStats* stats, long long elapsed) {
    long long total = atomic_load(&stats->total_packets);
    long long bytes = atomic_load(&stats->total_bytes);
    long long tcp = atomic_load(&stats->tcp_packets);
    long long udp = atomic_load(&stats->udp_packets);
    long long icmp = atomic_load(&stats->icmp_packets);
    long long other = atomic_load(&stats->other_packets);

    double rate = elapsed > 0 ? (double)total / (elapsed / 1000.0) : 0.0;
    double mbps = elapsed > 0 ? (double)bytes * 8.0 / (elapsed / 1000.0) / 1000000.0 : 0.0;

    printf("{\"type\":\"summary\",\"total_packets\":%lld,\"total_bytes\":%lld,"
           "\"tcp\":%lld,\"udp\":%lld,\"icmp\":%lld,\"other\":%lld,"
           "\"rate_pps\":%.1f,\"rate_mbps\":%.1f,\"elapsed_s\":%.1f}\n",
           total, bytes, tcp, udp, icmp, other, rate, mbps, elapsed / 1000.0);

    fprintf(stderr, "INSPECT: pkts=%lld bytes=%lld tcp=%lld udp=%lld icmp=%lld other=%lld rate=%.1f pps %.1f mbps elapsed=%.1fs\n",
        total, bytes, tcp, udp, icmp, other, rate, mbps, elapsed / 1000.0);
}

static void print_packet_json(PacketInfo* pi) {
    printf("{\"timestamp\":%lld,\"src\":\"%s\",\"dst\":\"%s\","
           "\"proto\":\"%s\",\"src_port\":%d,\"dst_port\":%d,"
           "\"size\":%d,\"ttl\":%d,\"tcp_flags\":\"%s\"}\n",
           pi->timestamp, pi->src_ip, pi->dst_ip,
           proto_name(pi->protocol), pi->src_port, pi->dst_port,
           pi->packet_size, pi->ttl, tcp_flags_str(pi->tcp_flags));
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  -i <iface>      Interface to listen on (default: first non-loopback)\n");
    fprintf(stderr, "  -p <port>       Filter by port\n");
    fprintf(stderr, "  -P <proto>      Filter by protocol (tcp, udp, icmp)\n");
    fprintf(stderr, "  -t <seconds>    Capture timeout (default: 0 = infinite)\n");
    fprintf(stderr, "  -n <count>      Max packets to capture (default: 0 = unlimited)\n");
    fprintf(stderr, "  -s              Summary only (no per-packet JSON)\n");
    fprintf(stderr, "  --promisc       Enable promiscuous mode\n");
}

static int find_default_iface(char* iface, int iface_size) {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) < 0) return -1;

    int found = 0;
    for (struct ifaddrs* ifa = ifaddr; ifa && !found; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET &&
            strcmp(ifa->ifa_name, "lo") != 0) {
            strncpy(iface, ifa->ifa_name, iface_size - 1);
            found = 1;
        }
    }
    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SIG_IGN);

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 1;
    }

    InspectContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.timeout_s = 0;
    ctx.max_packets = 0;
    ctx.promiscuous = 1;

    ctx.iface[0] = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
            strncpy(ctx.iface, argv[++i], sizeof(ctx.iface) - 1);
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            ctx.filter_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc)
            strncpy(ctx.filter_proto, argv[++i], sizeof(ctx.filter_proto) - 1);
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            ctx.timeout_s = atoi(argv[++i]);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            ctx.max_packets = atoi(argv[++i]);
        else if (strcmp(argv[i], "-s") == 0)
            ctx.summary_only = true;
        else if (strcmp(argv[i], "--promisc") == 0)
            ctx.promiscuous = 1;
    }

    if (!ctx.iface[0]) {
        if (find_default_iface(ctx.iface, sizeof(ctx.iface)) < 0) {
            fprintf(stderr, "No interface found\n");
            return 1;
        }
    }

    ctx.sock = create_promiscuous_socket(ctx.iface, ctx.promiscuous);
    if (ctx.sock < 0) {
        fprintf(stderr, "Failed to create capture socket (need root?)\n");
        return 1;
    }

    struct sock_fprog fprog;
    memset(&fprog, 0, sizeof(fprog));
    if (compile_bpf_filter(&fprog, ctx.filter_proto, ctx.filter_port) > 0) {
        if (setsockopt(ctx.sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
            fprintf(stderr, "BPF filter attach failed\n");
        }
    }

    fprintf(stderr, "PACKET_INSPECTOR interface=%s promisc=%d proto=%s port=%d timeout=%ds max=%d\n",
        ctx.iface, ctx.promiscuous,
        ctx.filter_proto[0] ? ctx.filter_proto : "all",
        ctx.filter_port, ctx.timeout_s, ctx.max_packets);

    ctx.start_time = now_ms();
    ctx.running = true;
    ctx.stats.last_stats_time = ctx.start_time;

    long long deadline = ctx.timeout_s > 0 ? ctx.start_time + (long long)ctx.timeout_s * 1000 : 0;

    while (ctx.running) {
        if (deadline > 0 && now_ms() >= deadline) break;
        if (ctx.max_packets > 0 && atomic_load(&ctx.packet_count) >= ctx.max_packets) break;

        uint8_t buf[MAX_PACKET_SIZE];
        struct sockaddr_ll from;
        socklen_t fl = sizeof(from);

        int n = recvfrom(ctx.sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (unlikely(n < 0)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        if (n < (int)sizeof(struct ethhdr)) continue;

        atomic_fetch_add(&ctx.packet_count, 1);

        PacketInfo pi;
        memset(&pi, 0, sizeof(pi));
        pi.timestamp = now_ms();
        pi.packet_size = n;

        char* payload = NULL;
        int payload_len = 0;
        uint16_t eth_type = 0;

        if (parse_ethernet(buf, n, &payload, &payload_len, &eth_type) < 0)
            continue;

        if (eth_type != 0x0800) continue;

        if (parse_ip((uint8_t*)payload, payload_len, &pi, &payload, &payload_len) < 0)
            continue;

        switch (pi.protocol) {
            case 6:
                parse_tcp((uint8_t*)payload, payload_len, &pi);
                break;
            case 17:
                parse_udp((uint8_t*)payload, payload_len, &pi);
                break;
            case 1:
                parse_icmp((uint8_t*)payload, payload_len, &pi);
                break;
        }

        if (ctx.filter_port > 0) {
            if (pi.src_port != ctx.filter_port && pi.dst_port != ctx.filter_port)
                continue;
        }

        update_stats(&ctx.stats, n, pi.protocol);

        if (!ctx.summary_only) {
            print_packet_json(&pi);
        }

        long long now = now_ms();
        if (now - ctx.stats.last_stats_time >= STATS_INTERVAL_MS) {
            ctx.stats.last_stats_time = now;
        }
    }

    close(ctx.sock);
    long long elapsed = now_ms() - ctx.start_time;
    print_stats(&ctx.stats, elapsed);

    return 0;
}
// vim: ts=4 sw=4 et tw=80
