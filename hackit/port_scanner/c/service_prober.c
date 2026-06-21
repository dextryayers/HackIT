/*
 * service_prober.c - Protocol-specific service interaction
 * Compile: gcc -O3 -o ../bin/service_prober service_prober.c -lpthread
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
#include <netinet/tcp.h>
#include <netdb.h>

#include "optimize.h"

#define MAX_PORTS    65536
#define MAX_WORKERS  64
#define BANNER_SIZE  16384

typedef struct {
    const char* command;
    const char* description;
    int wait_ms;
} ProbeStep;

typedef struct {
    int port;
    const char* service;
    ProbeStep steps[16];
} ProtocolConversation;

static const ProtocolConversation CONVS[] = {
    {21, "FTP", {
        {"SYST\r\n", "SYST", 200},
        {"FEAT\r\n", "FEAT", 200},
        {"HELP\r\n", "HELP", 200},
        {"PWD\r\n", "PWD", 200},
        {"AUTH TLS\r\n", "AUTH TLS", 300},
        {"STAT\r\n", "STAT", 200},
        {NULL, NULL, 0}
    }},
    {25, "SMTP", {
        {"EHLO hackit.local\r\n", "EHLO", 300},
        {"HELP\r\n", "HELP", 300},
        {"VRFY root\r\n", "VRFY", 300},
        {"EXPN postmaster\r\n", "EXPN", 300},
        {"STARTTLS\r\n", "STARTTLS", 500},
        {"NOOP\r\n", "NOOP", 200},
        {NULL, NULL, 0}
    }},
    {587, "SMTP-Submit", {
        {"EHLO hackit.local\r\n", "EHLO", 300},
        {"STARTTLS\r\n", "STARTTLS", 500},
        {"HELP\r\n", "HELP", 300},
        {NULL, NULL, 0}
    }},
    {110, "POP3", {
        {"CAPA\r\n", "CAPA", 200},
        {"STAT\r\n", "STAT", 200},
        {"LIST\r\n", "LIST", 300},
        {"NOOP\r\n", "NOOP", 200},
        {NULL, NULL, 0}
    }},
    {143, "IMAP", {
        {"A001 CAPABILITY\r\n", "CAPABILITY", 300},
        {"A002 NOOP\r\n", "NOOP", 200},
        {"A003 LIST \"\" \"*\"\r\n", "LIST", 500},
        {NULL, NULL, 0}
    }},
    {80, "HTTP", {
        {"HEAD / HTTP/1.0\r\nHost: hackit\r\n\r\n", "HEAD", 300},
        {"OPTIONS * HTTP/1.0\r\nHost: hackit\r\n\r\n", "OPTIONS", 300},
        {"TRACE / HTTP/1.0\r\nHost: hackit\r\n\r\n", "TRACE", 300},
        {"GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-Probe/1.0\r\nAccept: */*\r\n\r\n", "GET", 500},
        {NULL, NULL, 0}
    }},
    {8080, "HTTP-Alt", {
        {"HEAD / HTTP/1.0\r\nHost: hackit\r\n\r\n", "HEAD", 300},
        {"OPTIONS * HTTP/1.0\r\nHost: hackit\r\n\r\n", "OPTIONS", 300},
        {"TRACE / HTTP/1.0\r\nHost: hackit\r\n\r\n", "TRACE", 300},
        {"GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-Probe/1.0\r\nAccept: */*\r\n\r\n", "GET", 500},
        {NULL, NULL, 0}
    }},
    {22, "SSH", {
        {"", "Banner", 500},
        {NULL, NULL, 0}
    }},
    {23, "Telnet", {
        {"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27", "TermType", 300},
        {"\r\n", "CRLF", 200},
        {NULL, NULL, 0}
    }},
    {3306, "MySQL", {
        {"", "Greeting", 300},
        {NULL, NULL, 0}
    }},
    {5432, "PostgreSQL", {
        {"\x00\x00\x00\x08\x04\xd2\x16\x2f", "SSLRequest", 300},
        {NULL, NULL, 0}
    }},
    {6379, "Redis", {
        {"PING\r\n", "PING", 200},
        {"INFO server\r\n", "INFO", 500},
        {"CONFIG GET *\r\n", "CONFIG", 500},
        {"TIME\r\n", "TIME", 200},
        {"CLIENT LIST\r\n", "CLIENT", 500},
        {NULL, NULL, 0}
    }},
    {11211, "Memcached", {
        {"stats\r\n", "stats", 200},
        {"stats items\r\n", "stats items", 200},
        {"version\r\n", "version", 200},
        {NULL, NULL, 0}
    }},
    {27017, "MongoDB", {
        {"", "Greeting", 300},
        {NULL, NULL, 0}
    }},
    {389, "LDAP", {
        {"", "Bind", 300},
        {NULL, NULL, 0}
    }},
    {119, "NNTP", {
        {"CAPABILITIES\r\n", "CAPABILITIES", 300},
        {"HELP\r\n", "HELP", 300},
        {"LIST\r\n", "LIST", 500},
        {NULL, NULL, 0}
    }},
    {179, "BGP", {
        {"", "Open", 500},
        {NULL, NULL, 0}
    }},
    {5060, "SIP", {
        {"OPTIONS sip:hackit@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nFrom: <sip:probe@hackit>\r\nTo: <sip:hackit@127.0.0.1>\r\nCall-ID: 1@hackit\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", "OPTIONS", 500},
        {NULL, NULL, 0}
    }},
    {554, "RTSP", {
        {"OPTIONS rtsp://127.0.0.1 RTSP/1.0\r\nCSeq: 1\r\n\r\n", "OPTIONS", 300},
        {NULL, NULL, 0}
    }},
    {873, "Rsync", {
        {"", "Greeting", 500},
        {"@RSYNCD: 31.0\n", "Protocol", 300},
        {NULL, NULL, 0}
    }},
    {5985, "WinRM", {
        {"HEAD / HTTP/1.0\r\nHost: hackit\r\n\r\n", "HEAD", 300},
        {NULL, NULL, 0}
    }},
    {5900, "VNC", {
        {"", "RFB", 300},
        {NULL, NULL, 0}
    }},
    {3389, "RDP", {
        {"", "RDP", 500},
        {NULL, NULL, 0}
    }},
    {0, NULL, {{NULL, NULL, 0}}}
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

static int safe_recv(int sock, char* buf, int sz, int timeout_ms) {
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return (int)read(sock, buf, sz);
}

static void* service_worker(void* arg) {
    struct {
        char target[256];
        uint32_t target_ip;
        int* ports;
        int port_count;
        int timeout_ms;
        atomic_int next_idx;
    }* ctx = (void*)arg;
    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;
        int port = ctx->ports[idx];
        const ProtocolConversation* conv = NULL;
        for (int i = 0; CONVS[i].service; ++i) {
            if (CONVS[i].port == port) { conv = &CONVS[i]; break; }
        }
        if (!conv) {
            printf("RESULT:{\"port\":%d,\"status\":\"open\",\"service\":\"unknown\",\"conversation\":\"\"}\n", port);
            fflush(stdout);
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        addr.sin_addr.s_addr = ctx->target_ip;
        int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock < 0) continue;
        int epfd = epoll_create1(0);
        if (epfd < 0) { close(sock); continue; }
        struct epoll_event ev;
        ev.data.fd = sock;
        ev.events = EPOLLOUT | EPOLLERR;
        epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        struct epoll_event events[1];
        int rc = epoll_wait(epfd, events, 1, ctx->timeout_ms);
        close(epfd);
        if (rc <= 0) { close(sock); continue; }
        int so_err = 0;
        socklen_t el = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
        if (so_err != 0) { close(sock); continue; }
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
        char banner[BANNER_SIZE] = {0};
        char conversation[BANNER_SIZE] = {0};
        int conv_len = 0;
        char tmp[8192];
        for (int s = 0; conv->steps[s].command; s++) {
            int n;
            if (s == 0 && strlen(conv->steps[s].command) == 0) {
                n = safe_recv(sock, tmp, sizeof(tmp) - 1, conv->steps[s].wait_ms);
            } else {
                int one = 1;
                setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                write(sock, conv->steps[s].command, strlen(conv->steps[s].command));
                usleep((useconds_t)(conv->steps[s].wait_ms * 1000));
                n = safe_recv(sock, tmp, sizeof(tmp) - 1, conv->steps[s].wait_ms);
            }
            if (n > 0) {
                tmp[n] = 0;
                int o = 0;
                char line[256];
                for (int i = 0; i < n && o < 255; ++i) {
                    char c = tmp[i];
                    if (c == '\r') continue;
                    if (c == '\n') { line[o] = 0; if (o > 0) { int bl = strlen(banner); snprintf(banner + bl, BANNER_SIZE - bl, "%s|", line); } o = 0; continue; }
                    if (c >= 32 && c < 127) line[o++] = c;
                }
                if (o > 0) { line[o] = 0; int bl = strlen(banner); snprintf(banner + bl, BANNER_SIZE - bl, "%s|", line); }
                if (conv_len < BANNER_SIZE - 1) {
                    int add = snprintf(conversation + conv_len, BANNER_SIZE - conv_len, "%s:%s ", conv->steps[s].description, tmp);
                    if (add > 0) conv_len += add;
                    if (conv_len >= BANNER_SIZE) conv_len = BANNER_SIZE - 1;
                }
            }
        }
        close(sock);
        printf("RESULT:{\"port\":%d,\"status\":\"open\",\"service\":\"%s\",\"banner\":\"%s\",\"conversation\":\"%s\",\"protocol\":\"tcp\"}\n",
            port, conv->service, banner, conversation);
        fflush(stdout);
    }
    return NULL;
}

static int parse_ports(const char* spec, int* ports, int max) {
    int count = 0;
    if (!spec) return 0;
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char* t = strtok(buf, ",");
    while (t && count < max) {
        char* d = strchr(t, '-');
        if (d) {
            int s = atoi(t), e = atoi(d + 1);
            if (s < 1) s = 1; if (e > 65535) e = 65535;
            for (int p = s; p <= e && count < max; p++) ports[count++] = p;
        } else { int p = atoi(t); if (p >= 1 && p <= 65535) ports[count++] = p; }
        t = strtok(NULL, ",");
    }
    return count;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    char* target = NULL;
    char* ports_str = NULL;
    int timeout_ms = 5000;
    int workers = 8;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) workers = atoi(argv[++i]);
        else if (target == NULL) target = argv[i];
        else if (ports_str == NULL) ports_str = argv[i];
    }
    if (!target || !ports_str) {
        fprintf(stderr, "Usage: %s --target <host> --ports <ports> [--timeout ms] [--workers n]\n", argv[0]);
        return 1;
    }
    struct {
        char target[256];
        uint32_t target_ip;
        int ports[65536];
        int port_count;
        int timeout_ms;
        int workers;
        atomic_int next_idx;
        long long start_time;
    } ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
    ctx.target_ip = resolve_ip(target);
    if (ctx.target_ip == 0) { fprintf(stderr, "Failed to resolve target\n"); return 1; }
    ctx.port_count = parse_ports(ports_str, ctx.ports, 65536);
    if (ctx.port_count <= 0) { fprintf(stderr, "No valid ports\n"); return 1; }
    ctx.timeout_ms = timeout_ms;
    ctx.workers = workers;
    ctx.start_time = now_ms();
    fprintf(stderr, "SERVICE_PROBER target=%s ports=%d timeout=%dms workers=%d\n",
        target, ctx.port_count, timeout_ms, workers);
    pthread_t threads[MAX_WORKERS];
    int nt = workers;
    if (nt > MAX_WORKERS) nt = MAX_WORKERS;
    if (nt > ctx.port_count) nt = ctx.port_count;
    if (nt < 1) nt = 1;
    for (int i = 0; i < nt; ++i) pthread_create(&threads[i], NULL, service_worker, &ctx);
    for (int i = 0; i < nt; ++i) pthread_join(threads[i], NULL);
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"elapsed_ms\":%lld}\n",
        target, ctx.port_count, now_ms() - ctx.start_time);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
