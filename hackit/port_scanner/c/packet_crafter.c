/* packet_crafter.c — Custom Packet Crafting Engine
#define _GNU_SOURCE
 * Compile: gcc -O3 -o ../bin/packet_crafter packet_crafter.c -lpthread
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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include <errno.h>

#include "optimize.h"

#define MAX_PORTS 65536
typedef struct { char host[256]; struct in_addr addr; int port; int flags; int ttl; int timeout; } job_t;
static job_t jobs[MAX_PORTS];
static int n_jobs = 0, idx = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static unsigned short csum(void *b, int len) {
    unsigned short *buf = b; unsigned int sum = 0;
    for (int i = 0; i < len; i += 2) sum += *buf++;
    if (len & 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16);
    return (unsigned short)~sum;
}

static unsigned short tcp_csum(struct in_addr src, struct in_addr dst, unsigned short len, void *tcp_hdr) {
    struct { unsigned src; unsigned dst; char zeros; char proto; unsigned short len; } psd;
    psd.src = src.s_addr; psd.dst = dst.s_addr; psd.zeros = 0; psd.proto = 6; psd.len = htons(len);
    char buf[sizeof(psd) + len];
    memcpy(buf, &psd, sizeof(psd)); memcpy(buf + sizeof(psd), tcp_hdr, len);
    return csum(buf, sizeof(psd) + len);
}

static job_t get_job() {
    pthread_mutex_lock(&mtx); job_t j = {.port = 0};
    if (idx < n_jobs) j = jobs[idx++];
    pthread_mutex_unlock(&mtx); return j;
}

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char *flag_str(int flags) {
    switch (flags) {
        case 2: return "SYN"; case 16: return "ACK"; case 18: return "SYN-ACK";
        case 4: return "RST"; case 1: return "FIN"; case 20: return "FIN-ACK";
        case 0: return "NULL"; case 41: return "XMAS";
        default: { static char buf[32]; snprintf(buf, 32, "FLAGS_%d", flags); return buf; }
    }
}

static void send_packet(job_t *j) {
    long long start = now_ms();
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { fprintf(stderr, "[!] Root required for raw sockets\n"); return; }
    int val = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));
    if (j->ttl > 0) setsockopt(sock, IPPROTO_IP, IP_TTL, &j->ttl, sizeof(j->ttl));
    char packet[4096] = {0};
    struct ip *ip_hdr = (struct ip *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));
    ip_hdr->ip_hl = 5; ip_hdr->ip_v = 4; ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_hdr->ip_id = htons(getpid() & 0xFFFF);
    ip_hdr->ip_off = 0; ip_hdr->ip_ttl = j->ttl > 0 ? j->ttl : 64;
    ip_hdr->ip_p = IPPROTO_TCP; ip_hdr->ip_sum = 0;
    inet_aton("127.0.0.1", &ip_hdr->ip_src);
    ip_hdr->ip_dst = j->addr;
    tcp_hdr->th_sport = htons(12345 + (j->port % 50000));
    tcp_hdr->th_dport = htons(j->port);
    tcp_hdr->th_seq = htonl(1000); tcp_hdr->th_ack = 0;
    tcp_hdr->th_off = 5; tcp_hdr->th_flags = j->flags;
    tcp_hdr->th_win = htons(65535); tcp_hdr->th_sum = 0; tcp_hdr->th_urp = 0;
    tcp_hdr->th_sum = tcp_csum(ip_hdr->ip_src, ip_hdr->ip_dst, sizeof(struct tcphdr), tcp_hdr);
    ip_hdr->ip_sum = csum(ip_hdr, sizeof(struct ip) + sizeof(struct tcphdr));
    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_addr = j->addr};
    if (sendto(sock, packet, ntohs(ip_hdr->ip_len), 0, (struct sockaddr*)&dest, sizeof(dest)) > 0) {
        long long elapsed = now_ms() - start;
        printf("RESULT:{\"port\":%d,\"status\":\"sent\",\"protocol\":\"tcp\",\"flags\":\"%s\","
               "\"ttl\":%d,\"response_time_ms\":%lld}\n",
               j->port, flag_str(j->flags), ip_hdr->ip_ttl, elapsed);
        fflush(stdout);
    }
    close(sock);
}

static void *worker(void *arg) { (void)arg; job_t j;
    while ((j = get_job()).port > 0) send_packet(&j);
    return NULL; }

int main(int argc, char **argv) {
    char target[256] = {0}, ports_str[4096] = {0};
    int flags = 2, ttl = 64, timeout = 2000, workers = 10;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) strncpy(target, argv[++i], 255);
        else if (!strcmp(argv[i], "--ports") && i + 1 < argc) strncpy(ports_str, argv[++i], 4095);
        else if (!strcmp(argv[i], "--flags") && i + 1 < argc) {
            char *f = argv[++i];
            if (!strcasecmp(f, "syn")) flags = 2; else if (!strcasecmp(f, "ack")) flags = 16;
            else if (!strcasecmp(f, "fin")) flags = 1; else if (!strcasecmp(f, "rst")) flags = 4;
            else if (!strcasecmp(f, "null")) flags = 0; else if (!strcasecmp(f, "xmas")) flags = 41;
            else if (!strcasecmp(f, "fin-ack")) flags = 20; else flags = atoi(f);
        }
        else if (!strcmp(argv[i], "--ttl") && i + 1 < argc) ttl = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--workers") && i + 1 < argc) workers = atoi(argv[++i]);
    }
    if (!target[0] || !ports_str[0]) {
        fprintf(stderr, "Usage: %s --target <host> --ports <ports> [--flags syn|ack|fin|null|xmas] [--ttl N]\n", argv[0]);
        return 1;
    }
    struct hostent *he = gethostbyname(target);
    if (!he) { fprintf(stderr, "[!] Unknown host: %s\n", target); return 1; }
    int ports[MAX_PORTS], n_ports = 0;
    if (strchr(ports_str, '-')) {
        int a, b; sscanf(ports_str, "%d-%d", &a, &b);
        for (int i = a; i <= b && n_ports < MAX_PORTS; i++) ports[n_ports++] = i;
    } else {
        char *tok = strtok(ports_str, ",");
        while (tok && n_ports < MAX_PORTS) { ports[n_ports++] = atoi(tok); tok = strtok(NULL, ","); }
    }
    for (int i = 0; i < n_ports && n_jobs < MAX_PORTS; ++i) {
        snprintf(jobs[n_jobs].host, 256, "%s", target);
        memcpy(&jobs[n_jobs].addr, he->h_addr_list[0], he->h_length);
        jobs[n_jobs].port = ports[i]; jobs[n_jobs].flags = flags;
        jobs[n_jobs].ttl = ttl; jobs[n_jobs].timeout = timeout; n_jobs++;
    }
    pthread_t th[256];
    for (int i = 0; i < workers && i < 256; ++i) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < workers && i < 256; ++i) pthread_join(th[i], NULL);
    printf("FINAL:{\"target\":\"%s\",\"total\":%d,\"module\":\"packet_crafter\"}\n", target, n_jobs);
    fflush(stdout);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
