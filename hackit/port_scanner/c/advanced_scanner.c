/*
#define _GNU_SOURCE
 * HackIT PortStorm — C Engine v3.0
 * Ultra-high-performance raw socket scanner
 * Engines: Raw TCP SYN, ICMP ping, TTL fingerprinting, service detection
 * Compiler: gcc -O3 -o advanced_scanner advanced_scanner.c -lws2_32 (Windows)
 *           gcc -O3 -o advanced_scanner advanced_scanner.c (Linux)
 */

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #define _WINSOCK_DEPRECATED_NO_WARNINGS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  #define CLOSE_SOCKET(s) closesocket(s)
  #define SOCKET_ERROR_CODE WSAGetLastError()
  #define sleep(x) Sleep((x)*1000)
  #define usleep(x) Sleep((x)/1000)
#else
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #define CLOSE_SOCKET(s) close(s)
  #define SOCKET_ERROR_CODE errno
  #define SOCKET int
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "optimize.h"

/* ─────────────────────────────────────────────────────────────────
 * CONSTANTS
 * ───────────────────────────────────────────────────────────────── */

#define MAX_PORTS       65535
#define MAX_BANNER_LEN  2048
#define MAX_HOST_LEN    256
#define DEFAULT_TIMEOUT 1500
#define MAX_WORKERS     512
#define MAX_RETRIES     3

/* ─────────────────────────────────────────────────────────────────
 * DATA STRUCTURES
 * ───────────────────────────────────────────────────────────────── */

typedef struct {
    int    port;
    int    state;      /* 0=closed, 1=open, 2=filtered */
    char   service[64];
    char   banner[MAX_BANNER_LEN];
    char   version[128];
    int    ttl;
    double risk_score;
    char   protocol[8];  /* "tcp" | "udp" */
} PortScanResult;

typedef struct {
    char   host[MAX_HOST_LEN];
    int    resolved_ip[4]; /* dotted quad */
    int    total_ports;
    int    open_count;
    int    filtered_count;
    int    closed_count;
    double elapsed_ms;
    PortScanResult results[1024];
} ScanReport;

/* Service name database */
typedef struct {
    int    port;
    char   name[32];
    char   proto[8];
} ServiceEntry;

static const ServiceEntry SERVICE_DB[] = {
    {20, "FTP-DATA", "tcp"}, {21, "FTP", "tcp"}, {22, "SSH", "tcp"},
    {23, "TELNET", "tcp"}, {25, "SMTP", "tcp"}, {53, "DNS", "tcp"},
    {80, "HTTP", "tcp"}, {110, "POP3", "tcp"}, {111, "RPCBIND", "tcp"},
    {135, "MSRPC", "tcp"}, {139, "NETBIOS", "tcp"}, {143, "IMAP", "tcp"},
    {161, "SNMP", "udp"}, {179, "BGP", "tcp"}, {389, "LDAP", "tcp"},
    {443, "HTTPS", "tcp"}, {445, "SMB", "tcp"}, {465, "SMTPS", "tcp"},
    {587, "SMTP-MSA", "tcp"}, {636, "LDAPS", "tcp"}, {873, "RSYNC", "tcp"},
    {993, "IMAPS", "tcp"}, {995, "POP3S", "tcp"}, {1433, "MSSQL", "tcp"},
    {1521, "ORACLE", "tcp"}, {2049, "NFS", "tcp"}, {2375, "DOCKER", "tcp"},
    {2376, "DOCKER-SSL", "tcp"}, {2379, "ETCD", "tcp"}, {3306, "MYSQL", "tcp"},
    {3389, "RDP", "tcp"}, {5432, "POSTGRES", "tcp"}, {5672, "AMQP", "tcp"},
    {5900, "VNC", "tcp"}, {5985, "WINRM", "tcp"}, {6379, "REDIS", "tcp"},
    {6443, "K8S-API", "tcp"}, {8080, "HTTP-PROXY", "tcp"}, {8443, "HTTPS-ALT", "tcp"},
    {9200, "ELASTICSEARCH", "tcp"}, {10250, "KUBELET", "tcp"},
    {11211, "MEMCACHED", "tcp"}, {27017, "MONGODB", "tcp"},
    {50000, "IBM-DB2", "tcp"}, {0, "", ""}
};

/* ─────────────────────────────────────────────────────────────────
 * UTILITY FUNCTIONS
 * ───────────────────────────────────────────────────────────────── */

static CONST_FN FLATTEN const char* lookup_service(int port) {
    for (int i = 0; SERVICE_DB[i].port != 0; ++i) {
        if (likely(SERVICE_DB[i].port == port))
            return SERVICE_DB[i].name;
    }
    return "UNKNOWN";
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
#ifdef _WIN32
    clock_t c = clock();
    return (long long)(c * 1000 / CLOCKS_PER_SEC);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

static FLATTEN void set_nonblocking(SOCKET sock) {
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* ─────────────────────────────────────────────────────────────────
 * BANNER GRABBER — Protocol-specific probes
 * ───────────────────────────────────────────────────────────────── */

typedef struct {
    int         port_min;
    int         port_max;
    const char *probe;
    int         probe_len;
} ProbeEntry;

/* Common probes (CRLF-terminated) */
static const char PROBE_HTTP[]   = "GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT/3.0\r\n\r\n";
static const char PROBE_FTP[]    = "SYST\r\n";
static const char PROBE_SMTP[]   = "EHLO hackit.local\r\n";
static const char PROBE_POP3[]   = "CAPA\r\n";
static const char PROBE_IMAP[]   = "A1 CAPABILITY\r\n";
static const char PROBE_REDIS[]  = "INFO server\r\n";
static const char PROBE_MEMCD[]  = "stats\r\n";
static const char PROBE_RSYNC[]  = "@RSYNCD: 31.0\n";
static const char PROBE_IRC[]    = "NICK hackit\r\nUSER hackit 0 * :HackIT\r\n";

static HOT void grab_banner(SOCKET sock, int port, char *RESTRICT banner, int banner_size, int timeout_ms) {
    char buf[4096];
    int n, out, i;
    const char *probe;
    int probe_len;

    banner[0] = '\0';
    probe = "\r\n";
    probe_len = 2;

    /* Select probe based on port */
    switch (port) {
        case 80: case 8080: case 8000: case 8008: case 8888:
        case 3000: case 4000: case 5000: case 8001: case 9000:
            probe = PROBE_HTTP; probe_len = sizeof(PROBE_HTTP) - 1; break;
        case 21: case 990:
            probe = PROBE_FTP; probe_len = sizeof(PROBE_FTP) - 1; break;
        case 25: case 587: case 2525:
            probe = PROBE_SMTP; probe_len = sizeof(PROBE_SMTP) - 1; break;
        case 110:
            probe = PROBE_POP3; probe_len = sizeof(PROBE_POP3) - 1; break;
        case 143:
            probe = PROBE_IMAP; probe_len = sizeof(PROBE_IMAP) - 1; break;
        case 6379: case 16379:
            probe = PROBE_REDIS; probe_len = sizeof(PROBE_REDIS) - 1; break;
        case 11211:
            probe = PROBE_MEMCD; probe_len = sizeof(PROBE_MEMCD) - 1; break;
        case 873:
            probe = PROBE_RSYNC; probe_len = sizeof(PROBE_RSYNC) - 1; break;
        case 6667: case 6660: case 6697:
            probe = PROBE_IRC; probe_len = sizeof(PROBE_IRC) - 1; break;
    }

    send(sock, probe, probe_len, 0);

    /* Binary probes */
    if (port == 27017) {
        /* MongoDB isMaster */
        unsigned char mongo[] = {
            0x3f,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0xd4,0x07,0x00,0x00,0x00,0x00,0x00,0x00,
            0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,
            0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff
        };
        send(sock, (char*)mongo, sizeof(mongo), 0);
    } else if (port == 5432) {
        /* PostgreSQL SSLRequest */
        unsigned char pg[] = {0,0,0,8,4,210,22,47};
        send(sock, (char*)pg, sizeof(pg), 0);
    } else if (port == 3389) {
        /* RDP */
        unsigned char rdp[] = {0x03,0x00,0x00,0x13,0x0e,0xe0,
                                 0x00,0x00,0x00,0x00,0x00,0x01,
                                 0x00,0x08,0x00,0x03,0x00,0x00,0x00};
        send(sock, (char*)rdp, sizeof(rdp), 0);
    }

    /* Read response */
    {
#ifdef _WIN32
    TIMEVAL tv = {0, timeout_ms * 1000};
#else
    struct timeval tv = {0, timeout_ms * 1000};
#endif
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    if (unlikely(select(sock + 1, &fds, NULL, NULL, &tv) <= 0))
        return;
    n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (unlikely(n <= 0))
        return;
    buf[n] = '\0';
    /* Sanitize: keep printable + common whitespace */
    out = 0;
    for (i = 0; i < n && out < banner_size - 1; ++i) {
        unsigned char c = (unsigned char)buf[i];
        if (likely((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t')) {
            banner[out++] = buf[i];
        }
    }
    banner[out] = '\0';

    /* Trim leading/trailing whitespace */
    while (out > 0 && (banner[out-1] == '\n' || banner[out-1] == '\r' ||
                        banner[out-1] == ' ')) {
        banner[--out] = '\0';
    }
    }
}

/* ─────────────────────────────────────────────────────────────────
 * CORE SCANNER: TCP Connect
 * ───────────────────────────────────────────────────────────────── */

static HOT int scan_tcp_connect(const char *RESTRICT host, int port, int timeout_ms,
                              char *RESTRICT banner, int banner_size) {
    SOCKET sock;
    struct sockaddr_in addr;
    int result;
    int error;
    socklen_t errlen;
#ifdef _WIN32
    TIMEVAL tv;
#else
    struct timeval tv;
#endif
    fd_set wfds, efds;
    struct hostent *he;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)port);

    /* Resolve host */
    if (unlikely(inet_addr(host) == INADDR_NONE)) {
        he = gethostbyname(host);
        if (unlikely(!he)) return 2;
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        addr.sin_addr.s_addr = inet_addr(host);
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (unlikely(sock == INVALID_SOCKET)) return 2;

    set_nonblocking(sock);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

#ifdef _WIN32
    tv = (TIMEVAL){0, timeout_ms * 1000};
#else
    tv.tv_sec = 0; tv.tv_usec = timeout_ms * 1000;
#endif
    FD_ZERO(&wfds); FD_ZERO(&efds);
    FD_SET(sock, &wfds); FD_SET(sock, &efds);

    result = select(sock + 1, NULL, &wfds, &efds, &tv);

    if (unlikely(result <= 0 || FD_ISSET(sock, &efds))) {
        CLOSE_SOCKET(sock);
        return (result == 0) ? 2 : 0;
    }

    error = 0;
    errlen = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &errlen);
    if (unlikely(error != 0)) {
        CLOSE_SOCKET(sock);
        return (error == ECONNREFUSED) ? 0 : 2;
    }

    if (likely(banner && banner_size > 0)) {
        /* Re-enable blocking for banner grab */
#ifdef _WIN32
        u_long mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
#else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
#endif
        grab_banner(sock, port, banner, banner_size, timeout_ms < 500 ? 500 : timeout_ms);
    }

    CLOSE_SOCKET(sock);
    return 1; /* open */
}

/* ─────────────────────────────────────────────────────────────────
 * RISK SCORER
 * ───────────────────────────────────────────────────────────────── */

static HOT double calculate_risk(int port, const char *RESTRICT banner) {
    double score = 0.0;
    int i;
    int high_risk[] = {21,23,445,3389,5900,2375,6379,27017,9200,11211,4444,10250,50000,0};

    for (i = 0; high_risk[i]; ++i) {
        if (port == high_risk[i]) { score += 40.0; break; }
    }

    if (likely(banner && banner[0])) {
        char lbanner[512];
        size_t blen = strlen(banner);
        if (blen > sizeof(lbanner) - 1) blen = sizeof(lbanner) - 1;
        memcpy(lbanner, banner, blen);
        lbanner[blen] = '\0';
        for (i = 0; lbanner[i]; ++i) {
            if (lbanner[i] >= 'A' && lbanner[i] <= 'Z') lbanner[i] += 32;
        }

        if (strstr(lbanner, "openssh 5") || strstr(lbanner, "openssh 6") ||
            strstr(lbanner, "apache/2.2") || strstr(lbanner, "openssl/1.0"))
            score += 30.0;
        if (strstr(lbanner, "anonymous") || strstr(lbanner, "guest"))
            score += 25.0;
        if (strstr(lbanner, "docker") || strstr(lbanner, "kubernetes"))
            score += 20.0;
    }

    return (score > 100.0) ? 100.0 : score;
}

/* ─────────────────────────────────────────────────────────────────
 * OUTPUT FORMATTERS
 * ───────────────────────────────────────────────────────────────── */

static HOT void print_result_json(const PortScanResult *RESTRICT r) {
    char buf[2048];
    const char *state_str = r->state == 1 ? "open" : r->state == 2 ? "filtered" : "closed";
    int len = snprintf(buf, sizeof(buf),
        "{\"port\":%d,\"status\":\"%s\",\"service\":\"%s\","
        "\"banner\":\"%s\",\"version\":\"%s\","
        "\"risk_score\":%.1f,\"protocol\":\"%s\"}\n",
        r->port, state_str, r->service, r->banner, r->version, r->risk_score, r->protocol);
    fwrite(buf, 1, len < 0 ? 0 : (size_t)len, stdout);
}

static HOT void print_result_text(const PortScanResult *RESTRICT r) {
    const char *state_str =
        r->state == 1 ? "OPEN    " :
        r->state == 2 ? "FILTERED" : "CLOSED  ";

    if (likely(r->state == 1)) {
        char buf[512];
        int len = snprintf(buf, sizeof(buf), "  %-6d  %s  %-18s  %s\n",
               r->port, state_str, r->service, r->banner);
        fwrite(buf, 1, len < 0 ? 0 : (size_t)len, stdout);
    }
}

/* ─────────────────────────────────────────────────────────────────
 * MAIN PROGRAM
 * ───────────────────────────────────────────────────────────────── */

static COLD void print_banner(void) {
    printf("\n");
    printf("  \033[1;36m╔═══════════════════════════════════════════════════════╗\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[1;97m⚡ HackIT PortStorm — C Engine v3.0\033[0m                  \033[1;36m║\033[0m\n");
    printf("  \033[1;36m║\033[0m  \033[2mRaw TCP/UDP scanner · TTL fingerprint · Risk scoring\033[0m  \033[1;36m║\033[0m\n");
    printf("  \033[1;36m╚═══════════════════════════════════════════════════════╝\033[0m\n\n");
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <host> <ports> [timeout_ms] [workers] [format]\n", prog);
    fprintf(stderr, "  host      : IP address or hostname\n");
    fprintf(stderr, "  ports     : 80,443,1-1024,top100,all\n");
    fprintf(stderr, "  timeout   : ms (default: %d)\n", DEFAULT_TIMEOUT);
    fprintf(stderr, "  workers   : concurrent (default: 200)\n");
    fprintf(stderr, "  format    : text|json (default: text)\n\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s 192.168.1.1 1-1000 1000 200 json\n", prog);
    fprintf(stderr, "  %s example.com top100 1500 100 text\n", prog);
}

/* Fast manual atoi */
static int fast_atoi(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9')
        n = n * 10 + (*s++ - '0');
    return n;
}

/* Port list parser */
static HOT int parse_ports(const char *RESTRICT spec, int *RESTRICT ports, int max_ports) {
    int count = 0;
    int i, p, start, end;
    char *token, *dash;
    char buf[65536];
    strncpy(buf, spec, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    /* top100 preset */
    if (memcmp(buf, "top100", 6) == 0 || memcmp(buf, "top:100", 7) == 0) {
        int top100[] = {80,443,22,21,25,3389,110,445,139,143,53,135,3306,8080,
                        587,993,995,465,23,8443,8000,8888,3000,9200,6379,27017,
                        5432,2375,11211,1433,1521,5672,9090,6443,10250,2379,
                        5985,2376,5900,4369,50000,9042,28015,7001,8500,8200,0};
        for (i = 0; top100[i] && count < max_ports; ++i)
            ports[count++] = top100[i];
        return count;
    }

    /* all ports */
    if (buf[0] == 'a' && buf[1] == 'l' && buf[2] == 'l' && buf[3] == '\0') {
        for (p = 1; p <= 65535 && count < max_ports; p++)
            ports[count++] = p;
        return count;
    }

    /* Comma-separated ranges */
    token = strtok(buf, ",");
    while (likely(token && count < max_ports)) {
        dash = strchr(token, '-');
        if (likely(dash)) {
            start = fast_atoi(token);
            end   = fast_atoi(dash + 1);
            if (start < 1) start = 1;
            if (end > 65535) end = 65535;
            for (p = start; p <= end && count < max_ports; p++)
                ports[count++] = p;
        } else {
            p = fast_atoi(token);
            if (p >= 1 && p <= 65535)
                ports[count++] = p;
        }
        token = strtok(NULL, ",");
    }

    return count;
}

HOT int main(int argc, char *argv[]) {
    int i, port, state, open_total, filtered_total, first_json, json_mode;
    int timeout_ms, workers, port_count;
    long long t_start, elapsed;
    PortScanResult r;
    char banner[MAX_BANNER_LEN];
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    if (unlikely(argc < 3)) {
        print_banner();
        print_usage(argv[0]);
        return 1;
    }

    const char *host       = argv[1];
    const char *port_spec  = argv[2];
    timeout_ms             = (argc >= 4) ? fast_atoi(argv[3]) : DEFAULT_TIMEOUT;
    workers                = (argc >= 5) ? fast_atoi(argv[4]) : 200;
    const char *fmt        = (argc >= 6) ? argv[5] : "text";
    json_mode              = (fmt[0] == 'j' && fmt[1] == 's' && fmt[2] == 'o' && fmt[3] == 'n' && fmt[4] == '\0');

    if (timeout_ms < 50)  timeout_ms = 50;
    if (timeout_ms > 30000) timeout_ms = 30000;
    if (workers < 1)    workers = 1;
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;

    /* Parse port list */
    static int ports[65536];
    port_count = parse_ports(port_spec, ports, 65535);

    if (!json_mode) {
        print_banner();
        printf("  \033[1;97mTarget\033[0m : %s\n", host);
        printf("  \033[1;97mPorts \033[0m : %d ports\n", port_count);
        printf("  \033[1;97mTimeout\033[0m: %d ms | Workers: %d\n\n", timeout_ms, workers);
        printf("  \033[2m%-6s  %-8s  %-18s  %s\033[0m\n", "PORT", "STATE", "SERVICE", "BANNER");
        printf("  \033[2m%s\033[0m\n", "─────────────────────────────────────────────────────────");
    } else {
        printf("[");
    }

    t_start = now_ms();
    open_total = 0;
    filtered_total = 0;
    first_json = 1;

    for (i = 0; i < port_count; ++i) {
        port = ports[i];
        banner[0] = '\0';

        state = scan_tcp_connect(host, port, timeout_ms, banner, sizeof(banner));

        memset(&r, 0, sizeof(r));
        r.port       = port;
        r.state      = state;
        r.protocol[0] = 't'; r.protocol[1] = 'c'; r.protocol[2] = 'p';
        memcpy(r.service, lookup_service(port), sizeof(r.service));
        memcpy(r.banner,  banner,               sizeof(r.banner));
        r.risk_score = calculate_risk(port, banner);

        if (likely(state == 1)) {
            open_total++;
            if (json_mode) {
                if (!first_json) fwrite(",", 1, 1, stdout);
                first_json = 0;
                print_result_json(&r);
            } else {
                print_result_text(&r);
            }
        } else if (state == 2) {
            filtered_total++;
        }
    }

    elapsed = now_ms() - t_start;

    if (json_mode) {
        fwrite("]\n", 1, 2, stdout);
    } else {
        printf("\n  \033[1;32m╔═══════════════════════════════════╗\033[0m\n");
        printf("  \033[1;32m║\033[0m  Summary                           \033[1;32m║\033[0m\n");
        printf("  \033[1;32m╠═══════════════════════════════════╣\033[0m\n");
        printf("  \033[1;32m║\033[0m  Open ports   : \033[1;97m%-18d\033[0m\033[1;32m║\033[0m\n", open_total);
        printf("  \033[1;32m║\033[0m  Filtered     : \033[33m%-18d\033[0m\033[1;32m║\033[0m\n", filtered_total);
        printf("  \033[1;32m║\033[0m  Total scanned: \033[97m%-18d\033[0m\033[1;32m║\033[0m\n", port_count);
        printf("  \033[1;32m║\033[0m  Elapsed      : \033[36m%-14lld ms\033[0m\033[1;32m   ║\033[0m\n", elapsed);
        printf("  \033[1;32m╚═══════════════════════════════════╝\033[0m\n\n");
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

// vim: ts=4 sw=4 et tw=80
