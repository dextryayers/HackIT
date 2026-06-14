#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#define MAX_PORTS        131072
#define MAX_BANNER       4096
#define UDP_TIMEOUT_MS   2000
#define MAX_WORKERS      16
#define SOCKET_BATCH     512

typedef struct {
    int   port;
    int   state;
    char  service[64];
    char  banner[MAX_BANNER];
    int   rtt_ms;
    bool  icmp_unreachable;
} UDPResult;

typedef struct {
    const char* hostname;
    uint32_t    ip;
    int*        ports;
    int         port_count;
    int         timeout_ms;
    int         workers;
    UDPResult   results[MAX_PORTS];
    int         result_count;
    int         open_count;
    int         icmp_sock;
    long long   start_time;
    pthread_mutex_t lock;
} UDPContext;

static const char* udp_probes[] = {
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
};

typedef struct { int port; const char* probe; int len; } UDPProbe;

static const UDPProbe PROBES[] = {
    {53,   "\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x68\x69\x00\x00\x01\x00\x01", 21},
    {67,   "\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 0},
    {123,  "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 48},
    {161,  "\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00", 39},
    {500,  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32},
    {514,  "\x30\x0f\x02\x01\x01\x04\x08\x73\x79\x73\x6c\x6f\x67\x64\x00\x00", 16},
    {520,  "\x02\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 24},
    {1194, "\x38\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 24},
    {1900, "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n", 0},
    {4500, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 28},
    {5351, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12},
    {5353, "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x5f\x73\x65\x72\x76\x69\x63\x65\x73\x07\x5f\x64\x6e\x73\x2d\x73\x64\x04\x5f\x75\x64\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01", 41},
    {5683, "\x40\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00", 12},
    {3702, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 36},
    {0, NULL, 0}
};

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint32_t resolve_ip(const char* host) {
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) == 1) return addr.s_addr;
    struct hostent* he = gethostbyname(host);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static int parse_ports(const char* spec, int* ports, int max) {
    int count = 0;
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    if (strcmp(buf, "top100") == 0) {
        int top[] = {53,67,68,69,123,137,138,161,162,389,500,514,520,631,1194,1701,1900,4500,5351,5353,5683,3702,0};
        for (int i = 0; top[i] && count < max; i++) ports[count++] = top[i];
        return count;
    }
    if (strcmp(buf, "all") == 0) {
        for (int p = 1; p <= 65535 && count < max; p++) ports[count++] = p;
        return count;
    }
    char* token = strtok(buf, ",");
    while (token && count < max) {
        char* dash = strchr(token, '-');
        if (dash) {
            int s = atoi(token), e = atoi(dash + 1);
            if (s < 1) s = 1; if (e > 65535) e = 65535;
            for (int p = s; p <= e && count < max; p++) ports[count++] = p;
        } else { int p = atoi(token); if (p >= 1 && p <= 65535) ports[count++] = p; }
        token = strtok(NULL, ",");
    }
    return count;
}

static int send_udp_probe(int sock, uint32_t ip, int port) {
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons((uint16_t)port);
    to.sin_addr.s_addr = ip;
    const char* probe = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    int plen = 16;
    for (int i = 0; PROBES[i].port; i++) {
        if (PROBES[i].port == port) {
            if (PROBES[i].len > 0) { probe = PROBES[i].probe; plen = PROBES[i].len; }
            break;
        }
    }
    return sendto(sock, probe, plen, 0, (struct sockaddr*)&to, sizeof(to));
}

static int create_icmp_listener(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock >= 0) {
        struct timeval tv = {0, 500000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return sock;
}

static void listen_icmp_unreach(UDPContext* ctx, long long deadline) {
    char buf[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    while (now_ms() < deadline) {
        int n = recvfrom(ctx->icmp_sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&from, &from_len);
        if (n <= 0) { usleep(500); continue; }
        if (n < (int)sizeof(struct icmphdr)) continue;
        struct iphdr* outer_ip = (struct iphdr*)buf;
        if (outer_ip->protocol != IPPROTO_ICMP) continue;
        int icmp_hdr_start = outer_ip->ihl * 4;
        struct icmphdr* icmp = (struct icmphdr*)(buf + icmp_hdr_start);
        if (icmp->type == 3) {
            int inner_ip_start = icmp_hdr_start + 8;
            if (inner_ip_start + (int)sizeof(struct iphdr) >= n) continue;
            struct iphdr* inner_ip = (struct iphdr*)(buf + inner_ip_start);
            if (inner_ip->protocol != IPPROTO_UDP) continue;
            int inner_udp_start = inner_ip_start + inner_ip->ihl * 4;
            if (inner_udp_start + 2 >= n) continue;
            uint16_t dst_port = ntohs(*(uint16_t*)(buf + inner_udp_start + 2));
            pthread_mutex_lock(&ctx->lock);
            for (int i = 0; i < ctx->result_count; i++) {
                if (ctx->results[i].port == (int)dst_port) {
                    ctx->results[i].state = 0;
                    ctx->results[i].icmp_unreachable = true;
                    break;
                }
            }
            pthread_mutex_unlock(&ctx->lock);
        }
    }
}

static void* udp_worker(void* arg) {
    UDPContext* ctx = (UDPContext*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return NULL;
    struct timeval tv = {0, 200000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char recv_buf[MAX_BANNER];
    for (int pi = 0; pi < ctx->port_count; pi++) {
        int port = ctx->ports[pi];
        send_udp_probe(sock, ctx->ip, port);
        long long start = now_ms();
        bool got_response = false;
        while (now_ms() < start + ctx->timeout_ms) {
            int n = recvfrom(sock, recv_buf, sizeof(recv_buf) - 1, MSG_DONTWAIT, (struct sockaddr*)&from, &from_len);
            if (n > 0 && from.sin_addr.s_addr == ctx->ip && ntohs(from.sin_port) == (uint16_t)port) {
                recv_buf[n] = 0;
                pthread_mutex_lock(&ctx->lock);
                if (ctx->result_count < MAX_PORTS) {
                    UDPResult* r = &ctx->results[ctx->result_count++];
                    r->port = port;
                    r->state = 1;
                    r->rtt_ms = (int)(now_ms() - start);
                    int out = 0;
                    for (int si = 0; si < n && out < MAX_BANNER - 1; si++) {
                        unsigned char c = (unsigned char)recv_buf[si];
                        if (c >= 32 && c <= 126) recv_buf[out++] = c;
                    }
                    recv_buf[out] = 0;
                    strncpy(r->banner, recv_buf, sizeof(r->banner) - 1);
                    ctx->open_count++;
                }
                pthread_mutex_unlock(&ctx->lock);
                printf("RESULT:{\"port\":%d,\"state\":1,\"rtt_ms\":%d,\"banner\":\"%s\"}\n",
                    port, (int)(now_ms() - start), recv_buf);
                fflush(stdout);
                got_response = true;
                break;
            }
            usleep(1000);
        }
        if (!got_response) {
            printf("RESULT:{\"port\":%d,\"state\":0,\"rtt_ms\":%d}\n", port, ctx->timeout_ms);
            fflush(stdout);
        }
    }
    close(sock);
    return NULL;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <ports> [timeout_ms] [workers]\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.1 53,123,161,500 2000 4\n", argv[0]);
        return 1;
    }
    UDPContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.hostname = argv[1];
    ctx.ip = resolve_ip(ctx.hostname);
    if (ctx.ip == 0) { fprintf(stderr, "Failed to resolve\n"); return 1; }
    int ports[MAX_PORTS];
    int port_count = parse_ports(argv[2], ports, MAX_PORTS);
    if (port_count <= 0) { fprintf(stderr, "No valid ports\n"); return 1; }
    ctx.ports = ports;
    ctx.port_count = port_count;
    ctx.timeout_ms = argc > 3 ? atoi(argv[3]) : UDP_TIMEOUT_MS;
    ctx.workers = argc > 4 ? atoi(argv[4]) : 4;
    if (ctx.workers < 1) ctx.workers = 1;
    if (ctx.workers > MAX_WORKERS) ctx.workers = MAX_WORKERS;
    pthread_mutex_init(&ctx.lock, NULL);
    ctx.icmp_sock = create_icmp_listener();
    struct in_addr ia; ia.s_addr = ctx.ip;
    fprintf(stderr, "UDP_SCANNER target=%s ip=%s ports=%d timeout=%dms workers=%d\n",
        ctx.hostname, inet_ntoa(ia), port_count, ctx.timeout_ms, ctx.workers);
    ctx.start_time = now_ms();
    pthread_t threads[MAX_WORKERS];
    for (int i = 0; i < ctx.workers; i++)
        pthread_create(&threads[i], NULL, udp_worker, &ctx);
    long long icmp_deadline = ctx.start_time + ctx.timeout_ms + 1000;
    listen_icmp_unreach(&ctx, icmp_deadline);
    for (int i = 0; i < ctx.workers; i++)
        pthread_join(threads[i], NULL);
    long long elapsed = now_ms() - ctx.start_time;
    if (ctx.icmp_sock >= 0) close(ctx.icmp_sock);
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"open\":%d,\"elapsed_ms\":%lld}\n",
        ctx.hostname, port_count, ctx.open_count, elapsed);
    return 0;
}
