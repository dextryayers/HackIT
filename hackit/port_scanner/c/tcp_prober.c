/*
 * tcp_prober.c - TCP connect prober with 60+ protocol-specific probes
 * Compile: gcc -O3 -o ../bin/tcp_prober tcp_prober.c -lpthread
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
#define MAX_WORKERS  128
#define BANNER_SIZE  16384

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

typedef struct {
    int port;
    const char* probe;
    int probe_len;
    const char* service;
    const char* expect;
} ProbeDef;

static const ProbeDef PROBES[] = {
    {80,   "GET / HTTP/1.0\r\nHost: probe\r\nUser-Agent: HackIT-TCP/1.0\r\n\r\n", 53, "HTTP", "HTTP"},
    {8080, "GET / HTTP/1.0\r\nHost: probe\r\nUser-Agent: HackIT-TCP/1.0\r\n\r\n", 53, "HTTP", "HTTP"},
    {8000, "GET / HTTP/1.0\r\nHost: probe\r\nUser-Agent: HackIT-TCP/1.0\r\n\r\n", 53, "HTTP", "HTTP"},
    {8888, "GET / HTTP/1.0\r\nHost: probe\r\nUser-Agent: HackIT-TCP/1.0\r\n\r\n", 53, "HTTP", "HTTP"},
    {8008, "GET / HTTP/1.0\r\nHost: probe\r\nUser-Agent: HackIT-TCP/1.0\r\n\r\n", 53, "HTTP", "HTTP"},
    {443,  "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", 31, "HTTPS", "HTTP"},
    {8443, "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", 31, "HTTPS", "HTTP"},
    {22,   "", 0, "SSH", "SSH"},
    {21,   "SYST\r\n", 6, "FTP", "FTP"},
    {23,   "", 0, "Telnet", "Telnet"},
    {25,   "EHLO probe.local\r\n", 19, "SMTP", "SMTP"},
    {587,  "EHLO probe.local\r\n", 19, "SMTP-Submit", "SMTP"},
    {465,  "EHLO probe.local\r\n", 19, "SMTPS", "SMTP"},
    {110,  "CAPA\r\n", 6, "POP3", "POP3"},
    {995,  "CAPA\r\n", 6, "POP3S", "POP3"},
    {143,  "A001 CAPABILITY\r\n", 18, "IMAP", "IMAP"},
    {993,  "A001 CAPABILITY\r\n", 18, "IMAPS", "IMAP"},
    {3306, "", 0, "MySQL", "mysql"},
    {5432, "\x00\x00\x00\x08\x04\xd2\x16\x2f", 8, "PostgreSQL", "PostgreSQL"},
    {6379, "PING\r\n", 6, "Redis", "Redis"},
    {11211,"stats\r\n", 7, "Memcached", "Memcached"},
    {27017,"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00", 59, "MongoDB", "MongoDB"},
    {27018,"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00", 59, "MongoDB", "MongoDB"},
    {5900, "", 0, "VNC", "RFB"},
    {5901, "", 0, "VNC-1", "RFB"},
    {3389, "", 0, "RDP", "RDP"},
    {53,   "", 0, "DNS-TCP", "DNS"},
    {389,  "", 0, "LDAP", "LDAP"},
    {636,  "", 0, "LDAPS", "LDAP"},
    {445,  "", 0, "SMB", "SMB"},
    {139,  "", 0, "NetBIOS-SSN", "NetBIOS"},
    {135,  "", 0, "MSRPC", "RPC"},
    {593,  "", 0, "HTTP-RPC", "RPC"},
    {1521, "", 0, "Oracle-DB", "Oracle"},
    {1522, "", 0, "Oracle-DB", "Oracle"},
    {1433, "", 0, "MSSQL", "MSSQL"},
    {1434, "", 0, "MSSQL-UDP", "MSSQL"},
    {119,  "CAPABILITIES\r\n", 14, "NNTP", "NNTP"},
    {563,  "CAPABILITIES\r\n", 14, "NNTPS", "NNTP"},
    {873,  "", 0, "Rsync", "Rsync"},
    {993,  "A001 CAPABILITY\r\n", 18, "IMAPS", "IMAP"},
    {995,  "CAPA\r\n", 6, "POP3S", "POP3"},
    {2082, "HEAD / HTTP/1.0\r\n\r\n", 20, "cPanel", "HTTP"},
    {2083, "HEAD / HTTP/1.0\r\n\r\n", 20, "cPanel-SSL", "HTTP"},
    {2086, "HEAD / HTTP/1.0\r\n\r\n", 20, "WHM", "HTTP"},
    {2087, "HEAD / HTTP/1.0\r\n\r\n", 20, "WHM-SSL", "HTTP"},
    {2096, "HEAD / HTTP/1.0\r\n\r\n", 20, "Webmail", "HTTP"},
    {8081, "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", 33, "HTTP-Alt", "HTTP"},
    {8443, "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", 33, "HTTPS-Alt", "HTTP"},
    {9090, "", 0, "WebSM", "HTTP"},
    {3000, "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", 33, "Golang-Default", "HTTP"},
    {5000, "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", 33, "HTTP-Alt", "HTTP"},
    {5001, "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", 33, "HTTP-Alt", "HTTP"},
    {9200, "", 0, "Elasticsearch", "Elasticsearch"},
    {9300, "", 0, "Elasticsearch-Transport", "Elasticsearch"},
    {5672, "", 0, "AMQP", "AMQP"},
    {1883, "", 0, "MQTT", "MQTT"},
    {8883, "", 0, "MQTT-TLS", "MQTT"},
    {1935, "", 0, "RTMP", "RTMP"},
    {554,  "", 0, "RTSP", "RTSP"},
    {256,  "", 0, "RAP", "RAP"},
    {179,  "", 0, "BGP", "BGP"},
    {194,  "", 0, "IRC", "IRC"},
    {6667, "", 0, "IRC", "IRC"},
    {6697, "", 0, "IRC-SSL", "IRC"},
    {3478, "", 0, "STUN", "STUN"},
    {5060, "", 0, "SIP", "SIP"},
    {5061, "", 0, "SIP-TLS", "SIP"},
    {1194, "", 0, "OpenVPN", "OpenVPN"},
    {1723, "", 0, "PPTP", "PPTP"},
    {1701, "", 0, "L2TP", "L2TP"},
    {4500, "", 0, "IPsec-NAT", "IPsec"},
    {500,  "", 0, "ISAKMP", "ISAKMP"},
    {1812, "", 0, "RADIUS", "RADIUS"},
    {1813, "", 0, "RADIUS-Acct", "RADIUS"},
    {2049, "", 0, "NFS", "NFS"},
    {111,  "", 0, "RPCBind", "RPC"},
    {631,  "", 0, "IPP", "IPP"},
    {515,  "", 0, "Printer", "Printer"},
    {9100, "", 0, "JetDirect", "JetDirect"},
    {6000, "", 0, "X11", "X11"},
    {5432, "", 0, "PostgreSQL", "PostgreSQL"},
    {3307, "", 0, "MySQL-Alt", "MySQL"},
    {3323, "", 0, "MySQL-Alt", "MySQL"},
    {5984, "", 0, "CouchDB", "CouchDB"},
    {5985, "", 0, "WinRM-HTTP", "WinRM"},
    {5986, "", 0, "WinRM-HTTPS", "WinRM"},
    {2375, "", 0, "Docker", "Docker"},
    {2376, "", 0, "Docker-TLS", "Docker"},
    {6443, "", 0, "Kubernetes-API", "Kubernetes"},
    {10250,"", 0, "Kubelet", "Kubernetes"},
    {8161, "", 0, "ActiveMQ", "ActiveMQ"},
    {61616,"", 0, "ActiveMQ-OpenWire", "ActiveMQ"},
    {4243, "", 0, "Docker-Reg", "Docker"},
    {0, NULL, 0, NULL, NULL}
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
} ProbeContext;

typedef struct {
    int   port;
    int   state; /* 0=closed, 1=open, 2=filtered */
    char  banner[BANNER_SIZE];
    char  service[64];
    long long rtt_ms;
} ProbeResult;

static int connect_probe(uint32_t ip, int port, int timeout_ms, char* banner, int bs, const char** proto_probe, int* probe_len, const char** service, long long* rtt) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return 2;
    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int epfd = epoll_create1(0);
    if (epfd < 0) { close(sock); return 2; }
    struct epoll_event ev;
    ev.data.fd = sock;
    ev.events = EPOLLOUT | EPOLLERR;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
    long long t0 = now_ms();
    int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(epfd); close(sock); return 0; }
    struct epoll_event events[1];
    rc = epoll_wait(epfd, events, 1, timeout_ms);
    long long t1 = now_ms();
    close(epfd);
    if (rc <= 0) { close(sock); return rc == 0 ? 2 : 0; }
    int so_err = 0;
    socklen_t el = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
    if (so_err != 0) { close(sock); return so_err == ECONNREFUSED ? 0 : 2; }
    if (rtt) *rtt = t1 - t0;
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char tmp[8192];
    int total = 0, n;
    memset(tmp, 0, sizeof(tmp));
    for (int a = 0; a < 3 && total < 8191; a++) {
        n = (int)read(sock, tmp + total, 8191 - total);
        if (n > 0) total += n;
        else { usleep(50000); if (a == 0) continue; break; }
    }
    if (proto_probe && *proto_probe && *probe_len > 0) {
        write(sock, *proto_probe, *probe_len);
        usleep(200000);
        for (int i = 0; i < 3; ++i) {
            n = (int)read(sock, tmp + total, 8191 - total);
            if (n > 0) total += n;
            else break;
        }
    }
    close(sock);
    if (total > 0) {
        tmp[total] = 0;
        int out = 0;
        for (int i = 0; i < total && out < bs - 1; ++i) {
            char c = tmp[i];
            if (c == '\r') continue;
            if (c == '\n') { if (out > 0 && banner[out - 1] != ' ') banner[out++] = ' '; continue; }
            if (c >= 32 && c < 127) banner[out++] = c;
        }
        banner[out] = 0;
    }
    return 1;
}

static void* prober_worker(void* arg) {
    ProbeContext* ctx = (ProbeContext*)arg;
    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;
        int port = ctx->ports[idx];
        const char* probe = NULL;
        int plen = 0;
        const char* service = "unknown";
        for (int i = 0; PROBES[i].probe != NULL || PROBES[i].port != 0; ++i) {
            if (PROBES[i].port == port) {
                service = PROBES[i].service;
                probe = PROBES[i].probe;
                plen = PROBES[i].probe_len;
                break;
            }
        }
        char banner[BANNER_SIZE] = {0};
        long long rtt = 0;
        int state = connect_probe(ctx->target_ip, port, ctx->timeout_ms, banner, BANNER_SIZE, &probe, &plen, &service, &rtt);
        printf("RESULT:{\"port\":%d,\"status\":\"%s\",\"service\":\"%s\",\"banner\":\"%s\",\"protocol\":\"tcp\",\"response_time_ms\":%lld}\n",
            port,
            state == 1 ? "open" : (state == 0 ? "closed" : "filtered"),
            service, banner, rtt);
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

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    char* target = NULL;
    char* ports_str = NULL;
    int timeout_ms = 3000;
    int workers = 16;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) workers = atoi(argv[++i]);
        else if (target == NULL) target = argv[i];
        else if (ports_str == NULL) ports_str = argv[i];
        else if (timeout_ms == 3000) timeout_ms = atoi(argv[i]);
        else if (workers == 16) workers = atoi(argv[i]);
    }
    if (!target || !ports_str) {
        fprintf(stderr, "Usage: %s --target <host> --ports <ports> [--timeout ms] [--workers n]\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s 192.168.1.1 22,80,443\n", argv[0]);
        fprintf(stderr, "  %s --target 10.0.0.1 --ports 1-1000 --workers 32\n", argv[0]);
        return 1;
    }
    ProbeContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
    ctx.target_ip = resolve_ip(target);
    if (ctx.target_ip == 0) { fprintf(stderr, "Failed to resolve target: %s\n", target); return 1; }
    ctx.port_count = parse_ports(ports_str, ctx.ports, MAX_PORTS);
    if (ctx.port_count <= 0) { fprintf(stderr, "No valid ports\n"); return 1; }
    ctx.timeout_ms = timeout_ms;
    ctx.workers = workers;
    ctx.start_time = now_ms();
    fprintf(stderr, "TCP_PROBER target=%s ports=%d timeout=%dms workers=%d\n",
        target, ctx.port_count, timeout_ms, workers);
    pthread_t threads[MAX_WORKERS];
    int nt = workers;
    if (nt > MAX_WORKERS) nt = MAX_WORKERS;
    if (nt > ctx.port_count) nt = ctx.port_count;
    if (nt < 1) nt = 1;
    for (int i = 0; i < nt; ++i) pthread_create(&threads[i], NULL, prober_worker, &ctx);
    for (int i = 0; i < nt; ++i) pthread_join(threads[i], NULL);
    long long elapsed = now_ms() - ctx.start_time;
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"elapsed_ms\":%lld}\n",
        target, ctx.port_count, elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
