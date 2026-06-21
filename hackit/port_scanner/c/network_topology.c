#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "optimize.h"

#define MAX_HOPS 64
#define MAX_TARGETS 4096
#define TIMEOUT_S 2
#define PROBE_COUNT 3
#define CIDR_MAX_BITS 24

typedef struct {
    char ip[64];
    int hop;
    double rtt_ms;
    char method[16];
    int alive;
} HopInfo;

typedef struct {
    char target[256];
    char method[16];
    HopInfo hops[MAX_HOPS];
    int hop_count;
    int nat_detected;
    int firewall_detected;
    pthread_mutex_t lock;
} TracerouteResult;

typedef struct {
    char subnet[64];
    int prefix;
    unsigned long base_ip;
    unsigned long mask;
    char gateway[64];
    int host_count;
    int alive_count;
    pthread_mutex_t lock;
} SubnetResult;

static unsigned long ip_to_long(const char *ip) {
    unsigned char b[4];
    sscanf(ip, "%hhu.%hhu.%hhu.%hhu", &b[0], &b[1], &b[2], &b[3]);
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

static void long_to_ip(unsigned long n, char *buf, int len) {
    snprintf(buf, len, "%lu.%lu.%lu.%lu",
             (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF);
}

static unsigned short in_cksum(unsigned short *addr, int len) {
    unsigned long sum = 0;
    for (int i = 0; i < len / 2; ++i) sum += addr[i];
    if (len & 1) sum += ((unsigned char*)addr)[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)(~sum & 0xFFFF);
}

static int icmp_probe(const char *dst, int ttl, int ident, double *rtt) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) return -1;
    struct timeval tv = {1, 500000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    char pkt[64] = {0};
    struct icmphdr *icmp = (struct icmphdr *)pkt;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(ident);
    icmp->checksum = in_cksum((unsigned short*)pkt, sizeof(pkt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, dst, &addr.sin_addr);
    struct timespec ts1, ts2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    if (sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    char buf[256];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    close(fd);
    if (n <= 0) return 0;
    *rtt = (ts2.tv_sec - ts1.tv_sec) * 1000.0 + (ts2.tv_nsec - ts1.tv_nsec) / 1000000.0;
    return 1;
}

static int udp_probe(const char *dst, int port, int ttl, int ident, double *rtt) {
    (void)ident;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, dst, &addr.sin_addr);
    struct timespec ts1, ts2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    sendto(fd, "x", 1, 0, (struct sockaddr*)&addr, sizeof(addr));
    char buf[256];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct timeval tv = {1, 500000};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    if (rc > 0) recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
    close(fd);
    if (rc <= 0) return 0;
    *rtt = (ts2.tv_sec - ts1.tv_sec) * 1000.0 + (ts2.tv_nsec - ts1.tv_nsec) / 1000000.0;
    return 1;
}

static int tcp_syn_probe(const char *dst, int port, int ttl, double *rtt) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, dst, &addr.sin_addr);
    struct timespec ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    struct epoll_event ev;
    int epfd = epoll_create1(0);
    ev.events = EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd, events, 1, TIMEOUT_S * 1000);
    struct timespec ts2;
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    close(epfd);
    close(fd);
    if (nfds <= 0) return 0;
    *rtt = (ts2.tv_sec - ts1.tv_sec) * 1000.0 + (ts2.tv_nsec - ts1.tv_nsec) / 1000000.0;
    return 1;
}

static void *traceroute_thread(void *arg) {
    TracerouteResult *tr = (TracerouteResult *)arg;
    tr->hop_count = 0;
    tr->nat_detected = 0;
    tr->firewall_detected = 0;
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        double best_rtt = 999999;
        int any_reply = 0;
        for (int probe = 0; probe < PROBE_COUNT; probe++) {
            double rtt = 0;
            int rc = 0;
            if (strcmp(tr->method, "icmp") == 0)
                rc = icmp_probe(tr->target, ttl, probe + ttl * 10, &rtt);
            else if (strcmp(tr->method, "udp") == 0)
                rc = udp_probe(tr->target, 33434 + ttl, ttl, probe + ttl * 10, &rtt);
            else if (strcmp(tr->method, "tcp_syn") == 0 || strcmp(tr->method, "tcp_ack") == 0)
                rc = tcp_syn_probe(tr->target, 80, ttl, &rtt);
            else
                rc = icmp_probe(tr->target, ttl, probe + ttl * 10, &rtt);
            if (rc > 0) {
                any_reply = 1;
                if (rtt < best_rtt) best_rtt = rtt;
            }
        }
        HopInfo hop;
        memset(&hop, 0, sizeof(hop));
        snprintf(hop.ip, sizeof(hop.ip), "%s", any_reply ? tr->target : "*");
        hop.hop = ttl;
        hop.rtt_ms = any_reply ? best_rtt : 0;
        hop.alive = any_reply;
        strncpy(hop.method, tr->method, sizeof(hop.method) - 1);
        if (tr->hop_count < MAX_HOPS)
            tr->hops[tr->hop_count++] = hop;
        printf("RESULT:{\"type\":\"hop\",\"hop\":%d,\"ip\":\"%s\",\"rtt_ms\":%.2f,\"alive\":%d}\n",
               ttl, hop.ip, hop.rtt_ms, hop.alive);
        if (any_reply) {
            unsigned long ip = ip_to_long(hop.ip);
            unsigned long prev_ip = ip_to_long(tr->target);
            if (ip != prev_ip) tr->nat_detected = 1;
        }
        { struct timespec ts = {0, 10000000}; nanosleep(&ts, NULL); }
    }
    printf("FINAL:{\"type\":\"traceroute\",\"target\":\"%s\",\"method\":\"%s\",\"hops\":%d,"
           "\"nat\":%d,\"firewall\":%d}\n",
           tr->target, tr->method, tr->hop_count, tr->nat_detected, tr->firewall_detected);
    return NULL;
}

static void *subnet_scan_thread(void *arg) {
    SubnetResult *sr = (SubnetResult *)arg;
    unsigned long start = sr->base_ip;
    unsigned long end = start | (~sr->mask);
    sr->alive_count = 0;
    for (unsigned long ip = start + 1; ip < end && sr->alive_count < 256; ip++) {
        char ip_str[64];
        long_to_ip(ip, ip_str, sizeof(ip_str));
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, ip_str, &addr.sin_addr);
        connect(fd, (struct sockaddr*)&addr, sizeof(addr));
        struct epoll_event ev;
        int epfd = epoll_create1(0);
        ev.events = EPOLLOUT | EPOLLERR;
        ev.data.fd = fd;
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
        struct epoll_event events[1];
        int nfds = epoll_wait(epfd, events, 1, 500);
        int alive = 0;
        if (nfds > 0) {
            int err = 0; socklen_t elen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err == 0) alive = 1;
        }
        close(epfd);
        close(fd);
        if (alive) {
            sr->alive_count++;
            printf("RESULT:{\"type\":\"host\",\"ip\":\"%s\",\"status\":\"alive\"}\n", ip_str);
        }
    }
    printf("FINAL:{\"type\":\"subnet_scan\",\"subnet\":\"%s/%d\",\"hosts\":%d,\"alive\":%d}\n",
           sr->subnet, sr->prefix, sr->host_count, sr->alive_count);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    char *target = NULL;
    char *method = "icmp";
    char *subnet = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "t:m:s:p:")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'm': method = optarg; break;
            case 's': subnet = optarg; break;
            case 'p': break;
        }
    }
    if (target) {
        TracerouteResult tr;
        memset(&tr, 0, sizeof(tr));
        strncpy(tr.target, target, sizeof(tr.target) - 1);
        strncpy(tr.method, method, sizeof(tr.method) - 1);
        pthread_mutex_init(&tr.lock, NULL);
        traceroute_thread(&tr);
        pthread_mutex_destroy(&tr.lock);
    }
    if (subnet) {
        SubnetResult sr;
        memset(&sr, 0, sizeof(sr));
        strncpy(sr.subnet, subnet, sizeof(sr.subnet) - 1);
        char *slash = strchr(subnet, '/');
        if (slash) {
            *slash = 0;
            sr.prefix = atoi(slash + 1);
        } else {
            sr.prefix = 24;
        }
        sr.base_ip = ip_to_long(subnet);
        sr.mask = (sr.prefix == 0) ? 0 : htonl(~((1 << (32 - sr.prefix)) - 1));
        sr.mask = ntohl(sr.mask);
        sr.host_count = 1 << (32 - sr.prefix);
        pthread_mutex_init(&sr.lock, NULL);
        subnet_scan_thread(&sr);
        pthread_mutex_destroy(&sr.lock);
    }
    if (!target && !subnet)
        fprintf(stderr, "Usage: %s -t target [-m icmp|udp|tcp_syn|tcp_ack] [-s subnet/prefix]\n", argv[0]);
    return 0;
}
