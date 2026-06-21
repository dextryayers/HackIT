/* icmp_discovery.c — ICMP Host Discovery & Distance Estimation
#define _GNU_SOURCE
 * Compile: gcc -O3 -o ../bin/icmp_discovery icmp_discovery.c -lpthread
 * Requires: root / CAP_NET_RAW
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "optimize.h"

#define MAX_TARGETS 65536
static char targets[MAX_TARGETS][256];
static int n_targets = 0, idx = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static struct in_addr resolve(const char *host) {
    struct in_addr addr = {.s_addr = INADDR_NONE};
    struct hostent *he = gethostbyname(host);
    if (he) memcpy(&addr, he->h_addr_list[0], he->h_length);
    return addr;
}

static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b; unsigned int sum = 0;
    for (int i = 0; i < len; i += 2) sum += *buf++;
    if (len & 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16);
    return (unsigned short)~sum;
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static HOT void ping_host(const char *RESTRICT host, int timeout_ms) {
    long long start, elapsed;
    struct in_addr addr;
    int sock, n, ttl, distance;
    struct timeval tv;
    struct icmp icmp_pkt;
    struct sockaddr_in dest;
    unsigned char buf[512];
    struct sockaddr_in from;
    socklen_t fromlen;
    struct ip *ip_hdr;
    struct icmp *icmp_resp;
    char outbuf[512];
    int olen;

    start = now_ms();
    addr = resolve(host);
    if (unlikely(addr.s_addr == INADDR_NONE)) return;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (unlikely(sock < 0)) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (unlikely(sock < 0)) return;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memset(&icmp_pkt, 0, sizeof(icmp_pkt));
    icmp_pkt.icmp_type = ICMP_ECHO;
    icmp_pkt.icmp_code = 0;
    icmp_pkt.icmp_id = getpid() & 0xFFFF;
    icmp_pkt.icmp_seq = 1;
    icmp_pkt.icmp_cksum = checksum(&icmp_pkt, sizeof(icmp_pkt));
    dest.sin_family = AF_INET;
    dest.sin_addr = addr;
    dest.sin_port = 0;
    if (unlikely(sendto(sock, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr*)&dest, sizeof(dest)) <= 0))
        { close(sock); return; }
    fromlen = sizeof(from);
    n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
    elapsed = now_ms() - start;
    close(sock);
    if (likely(n > 0)) {
        ip_hdr = (struct ip *)buf;
        icmp_resp = (struct icmp *)(buf + (ip_hdr->ip_hl << 2));
        ttl = ip_hdr->ip_ttl;
        if (icmp_resp->icmp_type == ICMP_ECHOREPLY && icmp_resp->icmp_id == (getpid() & 0xFFFF)) {
            distance = (64 - ttl > 0) ? 64 - ttl : (128 - ttl > 0 ? 128 - ttl : 0);
            olen = snprintf(outbuf, sizeof(outbuf),
                "RESULT:{\"host\":\"%s\",\"ip\":\"%s\",\"status\":\"alive\",\"ttl\":%d,"
                "\"rtt_ms\":%lld,\"distance_est\":%d}\n",
                host, inet_ntoa(addr), ttl, elapsed, distance);
            fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
        }
    }
}

static char *pop_target() {
    pthread_mutex_lock(&mtx);
    char *r = NULL;
    if (idx < n_targets) { r = targets[idx++]; }
    pthread_mutex_unlock(&mtx);
    return r;
}

static void *worker(void *arg) {
    int to = *(int *)arg;
    char *h;
    while ((h = pop_target())) { if (*h) ping_host(h, to); }
    return NULL;
}

static int fast_atoi(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9')
        n = n * 10 + (*s++ - '0');
    return n;
}

HOT int main(int argc, char **argv) {
    int i, timeout, workers, a, b, c, d, mask;
    unsigned int base, net, bc, ip;
    unsigned char *p;
    char target_str[65536];
    pthread_t th[256];

    memset(target_str, 0, sizeof(target_str));
    timeout = 2000;
    workers = 20;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) strncpy(target_str, argv[++i], sizeof(target_str) - 1);
        else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) timeout = fast_atoi(argv[++i]);
        else if (!strcmp(argv[i], "--workers") && i + 1 < argc) workers = fast_atoi(argv[++i]);
    }
    if (unlikely(!target_str[0])) { fprintf(stderr, "Usage: %s --target <host/cidr> [--timeout ms] [--workers N]\n", argv[0]); return 1; }
    if (strchr(target_str, '/')) {
        sscanf(target_str, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &mask);
        base = (unsigned int)((a << 24) | (b << 16) | (c << 8) | d);
        net = base & (0xFFFFFFFF << (32 - mask));
        bc = net | ~(0xFFFFFFFF << (32 - mask));
        for (ip = net + 1; ip < bc && n_targets < MAX_TARGETS; ip++) {
            p = (unsigned char *)&ip;
            snprintf(targets[n_targets++], 256, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
        }
    } else {
        strncpy(targets[n_targets++], target_str, 255);
    }
    for (i = 0; i < workers && i < 256; ++i) pthread_create(&th[i], NULL, worker, &timeout);
    for (i = 0; i < workers && i < 256; ++i) pthread_join(th[i], NULL);
    printf("FINAL:{\"module\":\"icmp_discovery\",\"total_targets\":%d}\n", n_targets);
    fflush(stdout);
    return 0;
}

// vim: ts=4 sw=4 et tw=80
