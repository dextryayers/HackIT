/*
 * syn_scanner_v2.c - Mass SYN scanner using raw sockets
 * Compile: gcc -O3 -o ../bin/syn_scanner_v2 syn_scanner_v2.c -lpthread
 * Requires root/CAP_NET_RAW
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include "optimize.h"

#define MAX_PORTS     65536
#define MAX_WORKERS   256
#define MAX_BANNER    8192
#define MAX_RESULTS   65536
#define BATCH_STEAL   64

typedef struct PACKED {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} PseudoHeader;

typedef struct {
    int  port;
    bool synack;
    bool rst;
    bool icmp_unreach;
    int  ttl;
    int  window;
    long long rtt_us;
} ProbeResponse;

typedef struct {
    char        target[256];
    uint32_t    target_ip;
    int         ports[MAX_PORTS];
    int         port_count;
    int         timeout_ms;
    int         workers;
    int         source_port;
    int         ttl;
    atomic_int  next_idx;
    atomic_int  result_count;
    ProbeResponse results[MAX_RESULTS];
    long long   start_time;
    int         raw_sock;
    int         send_socks[MAX_WORKERS];
    int         send_sock_count;
    uint32_t    src_ip;
    bool        running;
} ScanContext;

static uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; ++i) sum += buf[i];
    if (len & 1) sum += (uint16_t)((unsigned char*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(struct tcphdr* tcp, int tcp_len, uint32_t saddr, uint32_t daddr) {
    PseudoHeader pseudo;
    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.saddr = saddr;
    pseudo.daddr = daddr;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(tcp_len);
    char buf[sizeof(PseudoHeader) + tcp_len];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &pseudo, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), tcp, tcp_len);
    return checksum((uint16_t*)buf, sizeof(PseudoHeader) + tcp_len);
}

static uint32_t resolve_ip(const char* hostname) {
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) return addr.s_addr;
    struct hostent* he = gethostbyname(hostname);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static uint32_t get_source_ip(uint32_t dst) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return htonl(0x01010101);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = dst;
    sa.sin_port = htons(80);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(s); return htonl(0x01010101); }
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(s, (struct sockaddr*)&local, &len);
    close(s);
    return local.sin_addr.s_addr;
}

static void build_syn_packet(char* pkt, int* plen, uint32_t src, uint32_t dst, int sp, int dp, int ttl_val) {
    memset(pkt, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));
    struct iphdr* ip = (struct iphdr*)pkt;
    struct tcphdr* tcp = (struct tcphdr*)(pkt + sizeof(struct iphdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = 0;
    ip->ttl = ttl_val > 0 ? ttl_val : 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src;
    ip->daddr = dst;
    tcp->source = htons((uint16_t)sp);
    tcp->dest = htons((uint16_t)dp);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(65535);
    tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);
    *plen = sizeof(struct iphdr) + sizeof(struct tcphdr);
}

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int parse_ports(const char* spec, int* ports, int max) {
    int count = 0;
    if (!spec) return 0;
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    if (strcmp(buf, "top100") == 0 || strcmp(buf, "top:100") == 0) {
        int top[] = {7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49154,0};
        for (int i = 0; top[i] && count < max; ++i) ports[count++] = top[i];
        return count;
    }
    if (strcmp(buf, "all") == 0) { for (int p = 1; p <= 65535 && count < max; p++) ports[count++] = p; return count; }
    char* t = strtok(buf, ",");
    while (t && count < max) {
        char* d = strchr(t, '-');
        if (d) {
            int s = atoi(t), e = atoi(d + 1);
            if (s < 1) s = 1;
            if (e > 65535) e = 65535;
            for (int p = s; p <= e && count < max; p++) ports[count++] = p;
        } else {
            int p = atoi(t);
            if (p >= 1 && p <= 65535) ports[count++] = p;
        }
        t = strtok(NULL, ",");
    }
    return count;
}

static void* worker_send(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    int tid = 0;
    for (int i = 0; i < ctx->send_sock_count; ++i) {
        if (ctx->send_socks[i] >= 0) { tid = i; break; }
    }
    int rs = ctx->send_socks[tid];
    uint32_t src = ctx->src_ip;
    srand((unsigned int)(time(NULL) ^ (uintptr_t)pthread_self()));
    int sp = ctx->source_port > 0 ? ctx->source_port : (20000 + (rand() % 45535));
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ctx->target_ip;
    while (1) {
        int start = atomic_fetch_add(&ctx->next_idx, BATCH_STEAL);
        if (start >= ctx->port_count) break;
        int end = start + BATCH_STEAL;
        if (end > ctx->port_count) end = ctx->port_count;
        for (int i = start; i < end; i++) {
            char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
            int len;
            build_syn_packet(pkt, &len, src, ctx->target_ip, sp + (i % 1000), ctx->ports[i], ctx->ttl);
            sendto(rs, pkt, len, 0, (struct sockaddr*)&to, sizeof(to));
        }
    }
    return NULL;
}

static void* worker_listen(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    int rs = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rs < 0) rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rs < 0) return NULL;
    struct timeval tv = {0, 100000};
    setsockopt(rs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[65536];
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    long long deadline = now_ms() + ctx->timeout_ms + 1000;
    while (now_ms() < deadline) {
        int n = recvfrom(rs, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (n <= 0) continue;
        if (n < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
        struct iphdr* ip = (struct iphdr*)buf;
        if (ip->protocol != IPPROTO_TCP || ip->saddr != ctx->target_ip) continue;
        int iphl = ip->ihl * 4;
        if (iphl + (int)sizeof(struct tcphdr) > n) continue;
        struct tcphdr* tcp = (struct tcphdr*)(buf + iphl);
        int dport = ntohs(tcp->dest);
        if ((tcp->syn && tcp->ack) || tcp->rst) {
            for (int i = 0; i < ctx->port_count; ++i) {
                if (ctx->results[i].port == dport) {
                    if (tcp->syn && tcp->ack) {
                        ctx->results[i].synack = true;
                        ctx->results[i].ttl = ip->ttl;
                        ctx->results[i].window = ntohs(tcp->window);
                    }
                    if (tcp->rst) ctx->results[i].rst = true;
                    break;
                }
            }
        }
    }
    close(rs);
    return NULL;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (geteuid() != 0) {
        fprintf(stderr, "Warning: SYN scan requires root/CAP_NET_RAW\n");
    }
    char* target = NULL;
    char* ports_str = NULL;
    int timeout_ms = 3000;
    int workers = 16;
    int source_port = 0;
    int ttl = 64;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) workers = atoi(argv[++i]);
        else if (strcmp(argv[i], "--source-port") == 0 && i + 1 < argc) source_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) ttl = atoi(argv[++i]);
        else if (target == NULL) target = argv[i];
        else if (ports_str == NULL) ports_str = argv[i];
        else if (timeout_ms == 3000) timeout_ms = atoi(argv[i]);
        else if (workers == 16) workers = atoi(argv[i]);
    }
    if (!target || !ports_str) {
        fprintf(stderr, "Usage: %s --target <host> --ports <ports> [--timeout ms] [--workers n] [--source-port p] [--ttl n]\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s 192.168.1.1 22,80,443\n", argv[0]);
        fprintf(stderr, "  %s --target 10.0.0.1 --ports 1-1000 --workers 32\n", argv[0]);
        return 1;
    }
    ScanContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
    ctx.target_ip = resolve_ip(target);
    if (ctx.target_ip == 0) { fprintf(stderr, "Failed to resolve target: %s\n", target); return 1; }
    ctx.port_count = parse_ports(ports_str, ctx.ports, MAX_PORTS);
    if (ctx.port_count <= 0) { fprintf(stderr, "No valid ports specified\n"); return 1; }
    ctx.timeout_ms = timeout_ms;
    ctx.workers = workers;
    ctx.source_port = source_port;
    ctx.ttl = ttl;
    ctx.src_ip = get_source_ip(ctx.target_ip);
    ctx.start_time = now_ms();
    for (int i = 0; i < ctx.port_count; ++i) ctx.results[i].port = ctx.ports[i];
    fprintf(stderr, "SYN_SCANNER_V2 target=%s ports=%d timeout=%dms workers=%d\n",
        target, ctx.port_count, timeout_ms, workers);
    int nt = workers;
    if (nt > MAX_WORKERS) nt = MAX_WORKERS;
    if (nt > ctx.port_count) nt = ctx.port_count;
    if (nt < 1) nt = 1;
    ctx.send_sock_count = nt;
    for (int i = 0; i < nt; ++i) {
        ctx.send_socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (ctx.send_socks[i] < 0) {
            ctx.send_socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (ctx.send_socks[i] >= 0) { int one = 1; setsockopt(ctx.send_socks[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)); }
        }
        if (ctx.send_socks[i] < 0) { fprintf(stderr, "Failed to create raw socket (need root)\n"); nt = i; break; }
    }
    if (nt <= 0) return 1;
    pthread_t send_threads[MAX_WORKERS];
    for (int i = 0; i < nt; ++i)
        pthread_create(&send_threads[i], NULL, worker_send, &ctx);
    pthread_t listen_thread;
    pthread_create(&listen_thread, NULL, worker_listen, &ctx);
    for (int i = 0; i < nt; ++i)
        pthread_join(send_threads[i], NULL);
    pthread_join(listen_thread, NULL);
    for (int i = 0; i < nt; ++i)
        if (ctx.send_socks[i] >= 0) close(ctx.send_socks[i]);
    long long elapsed = now_ms() - ctx.start_time;
    int open_count = 0;
    for (int i = 0; i < ctx.port_count; ++i) {
        if (ctx.results[i].synack) {
            open_count++;
            printf("RESULT:{\"port\":%d,\"status\":\"open\",\"service\":\"%s\",\"ttl\":%d,\"window\":%d,\"protocol\":\"tcp\",\"response_time_ms\":%.1f}\n",
                ctx.ports[i], "unknown", ctx.results[i].ttl, ctx.results[i].window, (double)ctx.results[i].rtt_us / 1000.0);
            fflush(stdout);
        }
    }
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"open\":%d,\"elapsed_ms\":%lld}\n",
        target, ctx.port_count, open_count, elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
