/*
 * os_fingerprint_v2.c - Advanced OS fingerprinting via TCP/IP
 * Compile: gcc -O3 -o ../bin/os_fingerprint_v2 os_fingerprint_v2.c -lpthread
 */
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
#include <math.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <poll.h>

#include "optimize.h"

#define MAX_PROBES 16
#define BANNER_SZ  8192

typedef struct {
    const char* os_name;
    const char* os_version;
    float       confidence;
    int         ttl;
    int         window;
    int         mss;
    int         wscale;
    bool        df;
    bool        ts;
    bool        sack;
    int         seq;
    char        banner[256];
} OSFingerprintResult;

typedef struct {
    const char* name;
    const char* version;
    float conf;
    int ttl_min, ttl_max;
    int win_min, win_max;
    int mss_min, mss_max;
    int wscale_min, wscale_max;
    bool df_required;
    bool ts_expected;
    bool sack_expected;
} OSSignature;

static const OSSignature OS_SIGS[] = {
    {"Linux", "2.6.x", 85, 60, 64, 5840, 29200, 1400, 1500, 0, 7, true, true, true},
    {"Linux", "3.x", 90, 60, 64, 28960, 65535, 1400, 1500, 0, 7, true, true, true},
    {"Linux", "4.x/5.x", 92, 60, 64, 65535, 65535, 1440, 1500, 3, 7, true, true, true},
    {"Linux", "6.x", 93, 60, 64, 65535, 65535, 1440, 1500, 3, 7, true, true, true},
    {"Linux", "Embedded/Android", 75, 60, 64, 16384, 32768, 1360, 1500, 0, 7, true, true, true},
    {"Windows", "7/Server2008R2", 90, 120, 128, 8192, 16384, 1400, 1460, 0, 8, true, true, true},
    {"Windows", "8/Server2012", 90, 120, 128, 8192, 65535, 1380, 1460, 0, 8, true, true, true},
    {"Windows", "10/Server2016", 95, 120, 128, 64240, 65535, 1460, 1460, 6, 8, true, true, true},
    {"Windows", "10/Server2019", 93, 120, 128, 65520, 65520, 1460, 1460, 6, 8, true, true, true},
    {"Windows", "11/Server2022", 94, 120, 128, 65536, 65536, 1380, 1460, 6, 8, true, true, true},
    {"Windows", "XP/2003", 85, 120, 128, 65535, 65535, 1460, 1460, 0, 5, false, false, true},
    {"Windows", "Vista/2008", 85, 120, 128, 16384, 16384, 1460, 1460, 0, 7, true, true, true},
    {"macOS", "Ventura+", 88, 60, 64, 65535, 65535, 1360, 1440, 3, 7, true, true, true},
    {"macOS", "Sonoma+", 90, 60, 64, 65536, 65536, 1360, 1440, 3, 7, true, true, true},
    {"macOS", "Legacy (10.x)", 80, 60, 64, 65535, 65535, 1440, 1460, 0, 5, true, true, true},
    {"FreeBSD", "Modern", 85, 60, 64, 65536, 65536, 1440, 1460, 3, 7, true, true, true},
    {"FreeBSD", "Legacy", 80, 60, 64, 65535, 65535, 1440, 1460, 0, 5, true, true, true},
    {"OpenBSD", "Modern", 82, 60, 64, 16384, 65535, 1440, 1460, 3, 7, true, true, true},
    {"NetBSD", "Modern", 80, 60, 64, 32768, 65535, 1440, 1460, 3, 7, true, true, true},
    {"Solaris", "11", 78, 60, 64, 32768, 65535, 1440, 1460, 0, 5, true, true, true},
    {"Solaris", "10", 75, 60, 64, 32768, 32768, 1460, 1460, 0, 5, true, false, true},
    {"AIX", "Modern", 72, 55, 64, 16384, 65535, 1400, 1460, 0, 7, true, false, true},
    {"HP-UX", "Modern", 70, 60, 64, 32768, 65535, 1400, 1460, 0, 5, true, false, false},
    {"Cisco IOS", "12.x+", 85, 250, 255, 4128, 16384, 1400, 1500, 0, 3, false, false, false},
    {"Cisco IOS-XE", "Modern", 82, 250, 255, 16384, 65535, 1400, 1460, 3, 5, true, false, false},
    {"Juniper JunOS", "Modern", 78, 60, 64, 8760, 32768, 1400, 1460, 0, 6, true, true, true},
    {"Juniper ScreenOS", "Modern", 75, 60, 64, 65535, 65535, 1440, 1460, 0, 3, false, false, false},
    {"VMware ESXi", "6.x+", 80, 60, 64, 65535, 65535, 1460, 1460, 0, 7, true, true, true},
    {"FreeNAS/TrueNAS", "Modern", 75, 60, 64, 65535, 65535, 1460, 1460, 0, 7, true, false, true},
    {"Android", "Modern", 80, 60, 64, 65535, 65535, 1400, 1460, 3, 7, true, true, true},
    {"iOS/iPadOS", "Modern", 85, 60, 64, 65535, 65535, 1380, 1440, 3, 7, true, true, true},
    {"Apple TV", "Modern", 75, 60, 64, 65535, 65535, 1380, 1440, 3, 7, true, true, true},
    {"Cisco ASA", "8.x+", 75, 250, 255, 65535, 65535, 1380, 1460, 0, 3, false, false, false},
    {"Nintendo Switch", "Modern", 70, 55, 64, 65535, 65535, 1400, 1460, 0, 7, true, false, false},
    {"PlayStation", "4/5", 70, 55, 64, 65535, 65535, 1400, 1460, 0, 7, true, false, false},
    {"Xbox", "One/Series", 70, 120, 128, 65535, 65535, 1400, 1460, 0, 7, true, false, true},
    {"Contiki/RIOT", "IoT", 65, 60, 64, 1024, 4096, 500, 1000, 0, 3, false, false, false},
    {"VxWorks", "Embedded", 65, 55, 64, 32768, 65535, 1400, 1460, 0, 0, false, false, false},
    {"OpenWrt/LEDE", "Modern", 75, 60, 64, 65535, 65535, 1400, 1500, 0, 7, true, true, true},
    {"DD-WRT", "Embedded", 70, 60, 64, 65535, 65535, 1400, 1460, 0, 3, false, false, false},
    {"Z/OS (mainframe)", "Modern", 60, 55, 64, 32768, 65535, 1400, 1460, 0, 0, false, false, false},
    {NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false, false}
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

static int tcp_info_cached_mss = 0;
static int tcp_info_cached_wscale = 0;
static int tcp_info_cached_window = 0;
static bool tcp_info_cached_ts = false;
static bool tcp_info_cached_sack = false;
static bool tcp_info_valid = false;

static int connect_and_probe(uint32_t ip, int port, int timeout_ms, OSFingerprintResult* r) {
    memset(r, 0, sizeof(OSFingerprintResult));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return -1;
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int epfd = epoll_create1(0);
    if (epfd < 0) { close(sock); return -1; }
    struct epoll_event ev;
    ev.data.fd = sock;
    ev.events = EPOLLOUT | EPOLLERR;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
    long long t0 = now_ms();
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    struct epoll_event events[1];
    int rc = epoll_wait(epfd, events, 1, timeout_ms);
    long long t1 = now_ms();
    close(epfd);
    if (rc <= 0) { close(sock); return -1; }
    int so_err = 0;
    socklen_t el = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
    if (so_err != 0) { close(sock); return -1; }
    if (!tcp_info_valid) {
        struct tcp_info ti;
        socklen_t tlen = sizeof(ti);
        if (getsockopt(sock, IPPROTO_TCP, TCP_INFO, &ti, &tlen) == 0) {
            tcp_info_cached_mss = ti.tcpi_advmss;
            tcp_info_cached_wscale = ti.tcpi_snd_wscale;
            tcp_info_cached_ts = (ti.tcpi_options & TCPI_OPT_TIMESTAMPS) != 0;
            tcp_info_cached_sack = (ti.tcpi_options & TCPI_OPT_SACK) != 0;
            tcp_info_cached_window = ti.tcpi_rcv_space;
            tcp_info_valid = true;
        }
    }
    if (tcp_info_valid) {
        r->mss = tcp_info_cached_mss;
        r->wscale = tcp_info_cached_wscale;
        r->ts = tcp_info_cached_ts;
        r->sack = tcp_info_cached_sack;
        r->window = tcp_info_cached_window;
    }
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    int short_ms = timeout_ms < 500 ? timeout_ms : 500;
    struct timeval tv = {short_ms / 1000, (short_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[BANNER_SZ];
    memset(buf, 0, sizeof(buf));
    int total = 0, n;
    n = (int)read(sock, buf + total, BANNER_SZ - 1 - total);
    if (n > 0) total += n;
    if (port == 80 || port == 8080 || port == 443 || port == 8443)
        send(sock, "HEAD / HTTP/1.0\r\n\r\n", 20, 0);
    else if (port == 25 || port == 587)
        send(sock, "EHLO scan\r\n", 12, 0);
    else if (port == 110)
        send(sock, "CAPA\r\n", 6, 0);
    else if (port == 143)
        send(sock, "A001 CAPABILITY\r\n", 18, 0);
    else if (port == 21)
        send(sock, "SYST\r\n", 6, 0);
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    poll(&pfd, 1, 200);
    for (int i = 0; i < 3; ++i) {
        n = (int)read(sock, buf + total, BANNER_SZ - 1 - total);
        if (n > 0) total += n;
        else break;
    }
    close(sock);
    buf[total] = 0;
    int si = 0, di = 0;
    while (buf[si] && di < 255) {
        char c = buf[si++];
        if (c == '\r') continue;
        if (c == '\n') { r->banner[di++] = ' '; continue; }
        if (c >= 32 && c < 127) r->banner[di++] = c;
    }
    r->banner[di] = 0;
    r->ttl = 64;
    r->df = true;
    return 1;
}

static void fingerprint(OSFingerprintResult* results, int count, int* out_ttl, int* out_win, int* out_mss, int* out_wscale,
    bool* out_df, bool* out_ts, bool* out_sack) {
    int ttl_sum = 0, win_sum = 0, mss_sum = 0, wscale_sum = 0;
    int ttl_n = 0, win_n = 0, mss_n = 0, wscale_n = 0;
    bool df_all = true, ts_all = true, sack_all = true;
    for (int i = 0; i < count; ++i) {
        if (results[i].ttl > 0) { ttl_sum += results[i].ttl; ttl_n++; }
        if (results[i].window > 0) { win_sum += results[i].window; win_n++; }
        if (results[i].mss > 0) { mss_sum += results[i].mss; mss_n++; }
        if (results[i].wscale > 0) { wscale_sum += results[i].wscale; wscale_n++; }
        if (!results[i].df) df_all = false;
        if (!results[i].ts) ts_all = false;
        if (!results[i].sack) sack_all = false;
    }
    *out_ttl = ttl_n > 0 ? ttl_sum / ttl_n : 64;
    *out_win = win_n > 0 ? win_sum / win_n : 65535;
    *out_mss = mss_n > 0 ? mss_sum / mss_n : 1460;
    *out_wscale = wscale_n > 0 ? wscale_sum / wscale_n : 7;
    *out_df = df_all;
    *out_ts = ts_all;
    *out_sack = sack_all;
}

static void match_os(int ttl, int win, int mss, int wscale, bool df, bool ts, bool sack, const char* banner,
    char* os_name, int osn_sz, char* os_ver, int osv_sz, float* confidence) {
    for (int i = 0; OS_SIGS[i].name; ++i) {
        const OSSignature* s = &OS_SIGS[i];
        if (ttl < s->ttl_min || ttl > s->ttl_max) continue;
        if (win < s->win_min || win > s->win_max) continue;
        if (mss < s->mss_min || mss > s->mss_max) continue;
        if (wscale < s->wscale_min || wscale > s->wscale_max) continue;
        if (s->df_required && !df) continue;
        if (s->ts_expected && !ts) continue;
        if (s->sack_expected && !sack) continue;
        float conf = s->conf;
        if (banner && banner[0]) {
            if (strstr(banner, "SSH-2.0-OpenSSH")) conf += 5;
            if (strstr(banner, "Ubuntu")) { snprintf(os_ver, osv_sz, "Ubuntu"); conf += 5; }
            if (strstr(banner, "Debian")) { snprintf(os_ver, osv_sz, "Debian"); conf += 5; }
            if (strstr(banner, "Microsoft-IIS")) { snprintf(os_ver, osv_sz, "IIS"); conf += 5; }
            if (strstr(banner, "vsFTPd") || strstr(banner, "ProFTPD")) conf += 3;
        }
        snprintf(os_name, osn_sz, "%s", s->name);
        if (!os_ver[0]) snprintf(os_ver, osv_sz, "%s", s->version);
        *confidence = conf > 100 ? 100 : conf;
        return;
    }
    snprintf(os_name, osn_sz, "Unknown");
    snprintf(os_ver, osv_sz, "");
    *confidence = 0;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    char* target = NULL;
    char* ports_str = NULL;
    int timeout_ms = 3000;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (target == NULL) target = argv[i];
        else if (ports_str == NULL) ports_str = argv[i];
        else if (timeout_ms == 3000) timeout_ms = atoi(argv[i]);
    }
    if (!target) {
        fprintf(stderr, "Usage: %s --target <host> [--ports ports] [--timeout ms]\n", argv[0]);
        fprintf(stderr, "  %s 192.168.1.1 22,80,443\n", argv[0]);
        return 1;
    }
    uint32_t ip = resolve_ip(target);
    if (ip == 0) { fprintf(stderr, "Failed to resolve target\n"); return 1; }
    int ports[16];
    int port_count = 0;
    if (ports_str) {
        char buf[256];
        strncpy(buf, ports_str, sizeof(buf) - 1);
        char* t = strtok(buf, ",");
        while (t && port_count < 16) { ports[port_count++] = atoi(t); t = strtok(NULL, ","); }
    }
    if (port_count == 0) { ports[0] = 80; ports[1] = 22; ports[2] = 443; port_count = 3; }
    fprintf(stderr, "OS_FINGERPRINT_V2 target=%s ports=%d\n", target, port_count);
    OSFingerprintResult results[16];
    int valid = 0;
    for (int i = 0; i < port_count; ++i) {
        if (connect_and_probe(ip, ports[i], timeout_ms, &results[valid]) > 0) valid++;
    }
    if (valid == 0) {
        printf("RESULT:{\"os_name\":\"Unknown\",\"os_version\":\"\",\"confidence\":0,\"ttl\":0,\"window\":0,\"mss\":0,\"wscale\":0,\"df\":false,\"timestamps\":false,\"sack\":false}\n");
        fflush(stdout);
        fprintf(stderr, "FINAL:{\"target\":\"%s\",\"status\":\"no-response\"}\n", target);
        return 0;
    }
    int ttl, win, mss, wscale;
    bool df, ts, sack;
    fingerprint(results, valid, &ttl, &win, &mss, &wscale, &df, &ts, &sack);
    char os_name[64] = {0}, os_ver[64] = {0};
    float confidence = 0;
    match_os(ttl, win, mss, wscale, df, ts, sack, results[0].banner, os_name, sizeof(os_name), os_ver, sizeof(os_ver), &confidence);
    printf("RESULT:{\"os_name\":\"%s\",\"os_version\":\"%s\",\"confidence\":%.1f,\"ttl\":%d,\"window\":%d,\"mss\":%d,\"wscale\":%d,\"df\":%s,\"timestamps\":%s,\"sack\":%s,\"signature\":\"T=%d W=%d M=%d WS=%d DF=%d TS=%d SACK=%d\"}\n",
        os_name, os_ver, confidence, ttl, win, mss, wscale,
        df ? "true" : "false", ts ? "true" : "false", sack ? "true" : "false",
        ttl, win, mss, wscale, df, ts, sack);
    fflush(stdout);
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"os\":\"%s\",\"version\":\"%s\",\"confidence\":%.1f}\n",
        target, os_name, os_ver, confidence);
    return 0;
}
