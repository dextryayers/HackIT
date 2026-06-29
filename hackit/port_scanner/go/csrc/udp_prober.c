/*
 * udp_prober.c - UDP protocol prober
 * Compile: gcc -O3 -o ../bin/udp_prober udp_prober.c -lpthread
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
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include "optimize.h"

#define MAX_PORTS    65536
#define MAX_WORKERS  128
#define BANNER_SIZE  8192

typedef struct {
    int port;
    const char* probe;
    int probe_len;
    const char* service;
} UDPProbeDef;

static const UDPProbeDef UDP_PROBES[] = {
    {53,    "\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01", 29, "DNS"},
    {161,   "\x30\x1a\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x0d\x02\x02\x01\xe8\x02\x01\x00\x02\x01\x00\x30\x00", 28, "SNMP"},
    {162,   "\x30\x1a\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x0d\x02\x02\x01\xe8\x02\x01\x00\x02\x01\x00\x30\x00", 28, "SNMP-Trap"},
    {123,   "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 48, "NTP"},
    {67,    "\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 80, "DHCP"},
    {68,    "", 0, "DHCP-Client"},
    {69,    "\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 28, "TFTP"},
    {514,   "", 0, "Syslog"},
    {520,   "", 0, "RIP"},
    {521,   "", 0, "RIPng"},
    {5353,  "", 0, "mDNS"},
    {1900,  "", 0, "UPnP-SSDP"},
    {3702,  "", 0, "WS-Discovery"},
    {3784,  "", 0, "VDO"},
    {3785,  "", 0, "VDO"},
    {4500,  "", 0, "IPsec-NAT-T"},
    {500,   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 28, "ISAKMP"},
    {518,   "", 0, "ntalk"},
    {517,   "", 0, "talk"},
    {546,   "", 0, "DHCPv6-Client"},
    {547,   "", 0, "DHCPv6-Server"},
    {623,   "", 0, "IPMI"},
    {6343,  "", 0, "sFlow"},
    {2055,  "", 0, "IPFIX"},
    {4739,  "", 0, "IPFIX"},
    {3310,  "", 0, "ClamAV"},
    {10000, "", 0, "NDMP"},
    {0, NULL, 0, NULL}
};

typedef struct {
    char      target[256];
    uint32_t  target_ip;
    int       ports[MAX_PORTS];
    int       port_count;
    int       timeout_ms;
    int       workers;
    atomic_int next_idx;
    long long start_time;
} UDPContext;

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

static const char* get_udp_service(int port) {
    for (int i = 0; UDP_PROBES[i].service; ++i)
        if (UDP_PROBES[i].port == port) return UDP_PROBES[i].service;
    return "unknown";
}

static int probe_udp_port(uint32_t ip, int port, int timeout_ms, char* banner, int bs, const char* probe, int plen) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 2;
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;
    if (probe && plen > 0)
        sendto(sock, probe, plen, 0, (struct sockaddr*)&addr, sizeof(addr));
    else {
        unsigned char def_probe[8] = {0};
        sendto(sock, def_probe, 8, 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    char buf[BANNER_SIZE];
    memset(buf, 0, sizeof(buf));
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    int n = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&from, &fl);
    close(sock);
    if (n > 0) {
        buf[n] = 0;
        int out = 0;
        for (int i = 0; i < n && out < bs - 1; ++i) {
            char c = buf[i];
            if (c >= 32 && c < 127) banner[out++] = c;
        }
        banner[out] = 0;
        return 1;
    }
    if (errno == ECONNREFUSED || errno == ECONNRESET) return 0;
    return n > 0 ? 1 : 2;
}

static void* udp_worker(void* arg) {
    UDPContext* ctx = (UDPContext*)arg;
    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;
        int port = ctx->ports[idx];
        const char* probe = NULL;
        int plen = 0;
        for (int i = 0; UDP_PROBES[i].service; ++i) {
            if (UDP_PROBES[i].port == port) {
                probe = UDP_PROBES[i].probe;
                plen = UDP_PROBES[i].probe_len;
                break;
            }
        }
        char banner[BANNER_SIZE] = {0};
        long long t0 = now_ms();
        int state = probe_udp_port(ctx->target_ip, port, ctx->timeout_ms, banner, BANNER_SIZE, probe, plen);
        long long rtt = now_ms() - t0;
        const char* svc = get_udp_service(port);
        printf("RESULT:{\"port\":%d,\"status\":\"%s\",\"service\":\"%s\",\"banner\":\"%s\",\"protocol\":\"udp\",\"response_time_ms\":%lld}\n",
            port,
            state == 1 ? "open" : (state == 0 ? "closed" : "filtered"),
            svc, banner, rtt);
        fflush(stdout);
    }
    return NULL;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    char* target = NULL;
    char* ports_str = NULL;
    int timeout_ms = 3000;
    int workers = 8;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) workers = atoi(argv[++i]);
        else if (target == NULL) target = argv[i];
        else if (ports_str == NULL) ports_str = argv[i];
        else if (timeout_ms == 3000) timeout_ms = atoi(argv[i]);
        else if (workers == 8) workers = atoi(argv[i]);
    }
    if (!target || !ports_str) {
        fprintf(stderr, "Usage: %s --target <host> --ports <ports> [--timeout ms] [--workers n]\n", argv[0]);
        fprintf(stderr, "  %s 192.168.1.1 53,161,123\n", argv[0]);
        return 1;
    }
    UDPContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
    ctx.target_ip = resolve_ip(target);
    if (ctx.target_ip == 0) { fprintf(stderr, "Failed to resolve target\n"); return 1; }
    ctx.port_count = parse_ports(ports_str, ctx.ports, MAX_PORTS);
    if (ctx.port_count <= 0) { fprintf(stderr, "No valid ports\n"); return 1; }
    ctx.timeout_ms = timeout_ms;
    ctx.workers = workers;
    ctx.start_time = now_ms();
    fprintf(stderr, "UDP_PROBER target=%s ports=%d timeout=%dms workers=%d\n",
        target, ctx.port_count, timeout_ms, workers);
    pthread_t threads[MAX_WORKERS];
    int nt = workers;
    if (nt > MAX_WORKERS) nt = MAX_WORKERS;
    if (nt > ctx.port_count) nt = ctx.port_count;
    if (nt < 1) nt = 1;
    for (int i = 0; i < nt; ++i) pthread_create(&threads[i], NULL, udp_worker, &ctx);
    for (int i = 0; i < nt; ++i) pthread_join(threads[i], NULL);
    long long elapsed = now_ms() - ctx.start_time;
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"elapsed_ms\":%lld}\n",
        target, ctx.port_count, elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
