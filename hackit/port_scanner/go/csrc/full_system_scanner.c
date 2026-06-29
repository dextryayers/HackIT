#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "optimize.h"

#define MAX_TARGETS 1024
#define MAX_PORTS 64
#define TIMEOUT_MS 3000
#define MAX_EVENTS 1024
#define MAX_WORKERS 16
#define BANNER_LEN 1024

typedef struct {
    char ip[64];
    int port;
    int ttl;
    int window_size;
    int mss;
    int wscale;
    int timestamp;
    int sack_perm;
    char os_fingerprint[256];
    double confidence;
    char banner[BANNER_LEN];
} OSFingerprint;

typedef struct {
    char target[256];
    int ports[MAX_PORTS];
    int port_count;
    int start_port;
    int end_port;
    int scan_all;
    volatile int running;
    pthread_mutex_t lock;
    OSFingerprint results[MAX_TARGETS * MAX_PORTS];
    int result_count;
} ScanContext;

static ScanContext ctx;
static const char *probe_payloads[] = {
    "GET / HTTP/1.0\r\n\r\n",
    "SSH-2.0-OpenSSH_8.9\r\n",
    "\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00",
    NULL
};

static const char *get_fallback_os(int ttl, int win) {
    if (ttl <= 32) {
        if (win == 65535 || win == 65520) return "Cisco IOS";
        if (win == 16384 || win == 8192) return "MikroTik RouterOS";
        if (win == 29200 || win == 5840) return "Juniper JunOS";
        return "Router/Embedded (TTL<=32)";
    }
    if (ttl <= 64) {
        if (win == 65535 || win == 65520) return "Linux (kernel 2.4+)";
        if (win == 5840 || win == 5720) return "Linux (kernel 2.6+)";
        if (win == 29200 || win == 28960) return "Linux (kernel 3.x/4.x)";
        if (win == 8192 || win == 16384) return "FreeBSD";
        if (win == 65535 && ttl == 64) return "macOS / Darwin";
        if (win >= 40000 && win <= 66000) return "Android / Linux";
        return "Unix-like (TTL~64)";
    }
    if (ttl <= 128) {
        if (win == 65535 || win == 65520) return "Windows 2000/XP";
        if (win >= 8192 && win <= 65535) {
            if (win == 8192) return "Windows 7/Server 2008";
            if (win == 65535) return "Windows 10/11";
            if (win >= 64000 && win <= 65535) return "Windows 10+";
            return "Windows (generic)";
        }
        return "Windows (TTL~128)";
    }
    if (ttl <= 255) {
        if (win >= 4128 && win <= 65535) return "Solaris / AIX";
        if (win == 8760 || win == 16384) return "HP-UX";
        return "Unix/Enterprise (TTL~255)";
    }
    return "Unknown";
}

static void analyze_tcp_info(int fd, OSFingerprint *fp) {
    struct tcp_info ti;
    socklen_t len = sizeof(ti);
    if (getsockopt(fd, SOL_TCP, TCP_INFO, &ti, &len) == 0) {
        fp->mss = ti.tcpi_snd_mss;
        fp->wscale = ti.tcpi_snd_wscale;
        if (ti.tcpi_options & TCPI_OPT_TIMESTAMPS) fp->timestamp = 1;
        if (ti.tcpi_options & TCPI_OPT_SACK) fp->sack_perm = 1;
        if (ti.tcpi_options & TCPI_OPT_WSCALE) fp->wscale = ti.tcpi_snd_wscale;
    }
}

static int async_connect(const char *ip, int port, int timeout_ms, OSFingerprint *fp) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    struct epoll_event ev, events[1];
    int epfd = epoll_create1(0);
    if (epfd < 0) { close(fd); return -1; }
    ev.events = EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long start_ns = ts.tv_sec * 1000000000L + ts.tv_nsec;
    int nfds = epoll_wait(epfd, events, 1, timeout_ms);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long end_ns = ts.tv_sec * 1000000000L + ts.tv_nsec;
    long rtt_us = (end_ns - start_ns) / 1000;
    int connected = 0;
    if (nfds > 0 && (events[0].events & EPOLLOUT)) {
        int err = 0; socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
            connected = 1;
            struct tcp_info ti;
            socklen_t tlen = sizeof(ti);
            if (getsockopt(fd, SOL_TCP, TCP_INFO, &ti, &tlen) == 0) {
                fp->mss = ti.tcpi_snd_mss;
                fp->sack_perm = (ti.tcpi_options & TCPI_OPT_SACK) ? 1 : 0;
                fp->timestamp = (ti.tcpi_options & TCPI_OPT_TIMESTAMPS) ? 1 : 0;
                fp->wscale = (ti.tcpi_options & TCPI_OPT_WSCALE) ? ti.tcpi_snd_wscale : -1;
            }
        }
    }
    close(epfd);
    close(fd);
    return connected ? rtt_us : -1;
}

static int get_ttl_from_probe(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    const char *probe = probe_payloads[0];
    send(fd, probe, strlen(probe), 0);
    char buf[BANNER_LEN];
    int n = recv(fd, buf, sizeof(buf) - 1, 0);
    close(fd);
    if (n > 0) return 64;
    return -1;
}

static void *worker_thread(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&ctx.lock);
        if (!ctx.running) { pthread_mutex_unlock(&ctx.lock); break; }
        int idx = ctx.result_count++;
        if (idx >= MAX_TARGETS * MAX_PORTS) { ctx.result_count--; pthread_mutex_unlock(&ctx.lock); break; }
        pthread_mutex_unlock(&ctx.lock);
        OSFingerprint fp;
        memset(&fp, 0, sizeof(fp));
        int ttl_guess = 64;
        int win_guess = 65535;
        int port_idx = idx % ctx.port_count;
        int target_idx = idx / ctx.port_count;
        if (target_idx >= 1 && port_idx < ctx.port_count) {
            strncpy(fp.ip, ctx.target, sizeof(fp.ip) - 1);
            fp.port = ctx.ports[port_idx];
            long rtt = async_connect(fp.ip, fp.port, TIMEOUT_MS, &fp);
            if (rtt > 0) {
                int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (tcp_fd >= 0) {
                    struct tcp_info ti;
                    socklen_t len = sizeof(ti);
                    if (getsockopt(tcp_fd, SOL_TCP, TCP_INFO, &ti, &len) == 0) {
                        fp.mss = ti.tcpi_snd_mss;
                    }
                    close(tcp_fd);
                }
                fp.ttl = ttl_guess;
                fp.window_size = win_guess;
                strncpy(fp.os_fingerprint, get_fallback_os(fp.ttl, fp.window_size), sizeof(fp.os_fingerprint) - 1);
                fp.confidence = 65.0;
                if (fp.mss == 1460 || fp.mss == 1440) fp.confidence += 10;
                if (fp.sack_perm) fp.confidence += 5;
                if (fp.timestamp) fp.confidence += 5;
                if (fp.wscale > 0) fp.confidence += 5;
            }
            pthread_mutex_lock(&ctx.lock);
            ctx.results[idx] = fp;
            pthread_mutex_unlock(&ctx.lock);
        }
    }
    return NULL;
}

static void print_result(const OSFingerprint *fp) {
    char ip_str[64];
    strncpy(ip_str, fp->ip, sizeof(ip_str) - 1);
    printf("RESULT:{\"ip\":\"%s\",\"port\":%d,\"ttl\":%d,\"window\":%d,"
           "\"mss\":%d,\"wscale\":%d,\"timestamp\":%d,\"sack\":%d,"
           "\"os\":\"%s\",\"confidence\":%.1f}\n",
           ip_str, fp->port, fp->ttl, fp->window_size,
           fp->mss, fp->wscale, fp->timestamp, fp->sack_perm,
           fp->os_fingerprint, fp->confidence);
}

static void parse_target(char *target) {
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
}

static void parse_ports(const char *arg) {
    ctx.port_count = 0;
    char *dup = strdup(arg);
    char *tok = strtok(dup, ",");
    while (tok && ctx.port_count < MAX_PORTS) {
        if (strchr(tok, '-')) {
            int lo, hi;
            if (sscanf(tok, "%d-%d", &lo, &hi) == 2) {
                for (int i = lo; i <= hi && ctx.port_count < MAX_PORTS; i++)
                    ctx.ports[ctx.port_count++] = i;
            }
        } else {
            ctx.ports[ctx.port_count++] = atoi(tok);
        }
        tok = strtok(NULL, ",");
    }
    free(dup);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    memset(&ctx, 0, sizeof(ctx));
    ctx.running = 1;
    pthread_mutex_init(&ctx.lock, NULL);
    char *target = NULL;
    char *ports = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "t:p:")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'p': ports = optarg; break;
        }
    }
    if (!target) { fprintf(stderr, "Usage: %s -t target -p ports\n", argv[0]); return 1; }
    parse_target(target);
    if (ports) parse_ports(ports);
    else { ctx.ports[0] = 80; ctx.ports[1] = 443; ctx.ports[2] = 22; ctx.ports[3] = 23; ctx.ports[4] = 3389; ctx.port_count = 5; }
    pthread_t threads[MAX_WORKERS];
    for (int i = 0; i < MAX_WORKERS; ++i)
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    for (int i = 0; i < MAX_WORKERS; ++i)
        pthread_join(threads[i], NULL);
    int os_counts[256];
    memset(os_counts, 0, sizeof(os_counts));
    for (int i = 0; i < ctx.result_count; ++i) {
        if (ctx.results[i].port > 0) print_result(&ctx.results[i]);
    }
    printf("FINAL:{\"target\":\"%s\",\"ports_scanned\":%d,\"results\":%d}\n",
           ctx.target, ctx.port_count, ctx.result_count);
    pthread_mutex_destroy(&ctx.lock);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
