#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include "optimize.h"

typedef struct {
    int count;
    char **hosts;
    int alive_count;
} HostResult;

static pthread_mutex_t ping_print_lock = PTHREAD_MUTEX_INITIALIZER;

static uint16_t icmp_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) sum += buf[i];
    if (len & 1) sum += (uint16_t)((unsigned char *)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

int ping_icmp(const char *target, int timeout_ms) {
    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) != 1) {
        struct hostent *he = gethostbyname(target);
        if (!he || !he->h_addr_list[0]) return 0;
        memcpy(&addr, he->h_addr_list[0], 4);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return 0;
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char pkt[64];
    memset(pkt, 0, sizeof(pkt));
    struct icmphdr *icmp = (struct icmphdr *)pkt;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons((uint16_t)(getpid() & 0xFFFF));
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = icmp_checksum((uint16_t *)pkt, sizeof(pkt));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr = addr;

    if (sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        close(sock);
        return 0;
    }

    unsigned char reply[256];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int n = (int)recvfrom(sock, reply, sizeof(reply), 0, (struct sockaddr *)&from, &fromlen);
    close(sock);
    if (n < (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr)) return 0;

    struct icmphdr *ricmp = (struct icmphdr *)(reply + sizeof(struct iphdr));
    return (ricmp->type == ICMP_ECHOREPLY && ricmp->un.echo.id == icmp->un.echo.id) ? 1 : 0;
}

int ping_tcp(const char *target, int port, int timeout_ms) {
    struct in_addr addr;
    if (inet_pton(AF_INET, target, &addr) != 1) {
        struct hostent *he = gethostbyname(target);
        if (!he || !he->h_addr_list[0]) return 0;
        memcpy(&addr, he->h_addr_list[0], 4);
    }

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return 0;

    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    dst.sin_addr = addr;

    connect(sock, (struct sockaddr *)&dst, sizeof(dst));

    struct pollfd pf = {.fd = sock, .events = POLLOUT | POLLERR};
    int n = poll(&pf, 1, timeout_ms);
    int alive = 0;
    if (n > 0 && (pf.revents & POLLOUT)) {
        int so_err = 0;
        socklen_t el = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
        if (so_err == 0 || so_err == ECONNREFUSED) alive = 1;
    }
    close(sock);
    return alive;
}

typedef struct {
    volatile int next_host;
    int total_hosts;
    uint32_t *host_ips;
    char **host_strs;
    int *results;
    int timeout_ms;
    const char *method;
    pthread_mutex_t *lock;
} PingShared;

static void *ping_worker(void *arg) {
    PingShared *sh = (PingShared *)arg;
    for (;;) {
        pthread_mutex_lock(sh->lock);
        int idx = sh->next_host;
        if (idx >= sh->total_hosts) { pthread_mutex_unlock(sh->lock); break; }
        sh->next_host = idx + 1;
        pthread_mutex_unlock(sh->lock);

        char ip[INET_ADDRSTRLEN];
        struct in_addr a;
        a.s_addr = sh->host_ips[idx];
        inet_ntop(AF_INET, &a, ip, sizeof(ip));

        int alive = 0;
        if (strcmp(sh->method, "icmp") == 0) {
            alive = ping_icmp(ip, sh->timeout_ms);
        } else {
            alive = ping_tcp(ip, 80, sh->timeout_ms);
            if (!alive) alive = ping_tcp(ip, 443, sh->timeout_ms);
            if (!alive) alive = ping_tcp(ip, 22, sh->timeout_ms);
        }
        sh->results[idx] = alive;
    }
    return NULL;
}

static int cidr_to_range(const char *cidr, uint32_t *base_out, uint32_t *mask_out) {
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = 0;
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return -1;
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;
    uint32_t mask = prefix == 0 ? 0 : htonl(~((1 << (32 - prefix)) - 1));
    *base_out = ntohl(addr.s_addr) & ntohl(mask);
    *mask_out = ntohl(mask);
    return 0;
}

HostResult discover_hosts(const char *cidr, const char *method, int timeout_ms) {
    HostResult res = {0, NULL, 0};
    if (!cidr || !method) return res;

    uint32_t base, mask;
    if (cidr_to_range(cidr, &base, &mask) < 0) return res;

    uint32_t network = base & mask;
    uint32_t broadcast = network | ~mask;
    int total = (int)(broadcast - network - 1);
    if (total <= 0 || total > 65536) return res;

    uint32_t *ips = calloc(total, sizeof(uint32_t));
    char **strs = calloc(total, sizeof(char *));
    int *results = calloc(total, sizeof(int));
    if (!ips || !strs || !results) {
        free(ips); free(strs); free(results);
        return res;
    }

    int idx = 0;
    for (uint32_t ip = network + 1; ip < broadcast; ip++) {
        ips[idx] = htonl(ip);
        struct in_addr a;
        a.s_addr = ips[idx];
        strs[idx] = strdup(inet_ntoa(a));
        idx++;
    }

    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    PingShared sh;
    sh.next_host = 0;
    sh.total_hosts = total;
    sh.host_ips = ips;
    sh.host_strs = strs;
    sh.results = results;
    sh.timeout_ms = timeout_ms;
    sh.method = method;
    sh.lock = &lock;

    int nthreads = total < 64 ? total : 64;
    pthread_t *threads = calloc(nthreads, sizeof(pthread_t));
    if (!threads) { free(ips); free(strs); free(results); return res; }

    for (int i = 0; i < nthreads; i++) pthread_create(&threads[i], NULL, ping_worker, &sh);
    for (int i = 0; i < nthreads; i++) pthread_join(threads[i], NULL);

    int alive_count = 0;
    for (int i = 0; i < total; i++) if (results[i]) alive_count++;

    res.count = total;
    res.hosts = strs;
    res.alive_count = alive_count;

    free(ips);
    free(results);
    free(threads);
    pthread_mutex_destroy(&lock);
    return res;
}

void host_result_free(HostResult *res) {
    if (!res) return;
    if (res->hosts) {
        for (int i = 0; i < res->count; i++) free(res->hosts[i]);
        free(res->hosts);
    }
    memset(res, 0, sizeof(HostResult));
}
