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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include "optimize.h"

#define MAX_BANNER 8192

typedef struct {
    char  os_name[64];
    char  os_version[64];
    float confidence;
    int   ttl;
    int   window_size;
    int   mss;
    int   wscale;
    bool  df_bit;
    bool  timestamps;
    bool  sack_ok;
    bool  nop_support;
    int   initial_seq;
    char  tcp_options[256];
    char  signatures[1024];
} OSFingerprint;

typedef struct {
    const char* hostname;
    uint32_t    ip;
    int         ports[16];
    int         port_count;
    int         timeout_ms;
    OSFingerprint fp;
} OSContext;

typedef struct {
    int ttl;
    int window;
    int mss;
    int wscale;
    bool df;
    bool ts;
    bool sack;
    bool nop_support;
    int seq;
    char opts[256];
    char banner[512];
} TCPProbeResult;

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

typedef struct PACKED {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} PseudoHeader;

static uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; ++i) sum += buf[i];
    if (len & 1) sum += (uint16_t)((unsigned char*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(struct tcphdr* tcp, int tcp_len, uint32_t saddr, uint32_t daddr) {
    PseudoHeader pseudo;
    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.saddr = saddr;
    pseudo.daddr = daddr;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(tcp_len);
    char buf[sizeof(PseudoHeader) + tcp_len];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &pseudo, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), tcp, tcp_len);
    return checksum((uint16_t*)buf, sizeof(PseudoHeader) + tcp_len);
}

static uint32_t get_source_ip(uint32_t dst) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return htonl(0x01010101);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = dst;
    sa.sin_port = htons(80);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(s); return htonl(0x01010101); }
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(s, (struct sockaddr*)&local, &len);
    close(s);
    return local.sin_addr.s_addr;
}

#define TCP_OPT_MSS 2
#define TCP_OPT_WSCALE 3
#define TCP_OPT_SACK 4
#define TCP_OPT_TS 8

static void parse_tcp_options(unsigned char* opts, int len, TCPProbeResult* r) {
    int i = 0;
    while (i < len) {
        int kind = opts[i];
        if (kind == 0) { r->opts[0] = 0; break; }
        if (kind == 1) { i++; r->nop_support = true; continue; }
        if (i + 1 >= len) break;
        int opt_len = opts[i + 1];
        if (opt_len < 2 || i + opt_len > len) break;
        if (kind == TCP_OPT_MSS && opt_len == 4) {
            r->mss = (opts[i + 2] << 8) | opts[i + 3];
        } else if (kind == TCP_OPT_WSCALE && opt_len == 3) {
            r->wscale = opts[i + 2];
        } else if (kind == 4 && opt_len == 2) {
            r->sack = true;
        } else if (kind == TCP_OPT_TS && opt_len == 10) {
            r->ts = true;
        }
        i += opt_len;
    }
}

static int connect_and_probe(const char* host, uint32_t ip, int port, int timeout_ms, TCPProbeResult* result) {
    memset(result, 0, sizeof(TCPProbeResult));
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
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    struct epoll_event events[1];
    int rc = epoll_wait(epfd, events, 1, timeout_ms);
    close(epfd);
    if (rc <= 0) { close(sock); return -1; }
    int so_err = 0;
    socklen_t err_len = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
    if (so_err != 0) { close(sock); return -1; }

    struct tcp_info tcpinfo;
    socklen_t tcpinfo_len = sizeof(tcpinfo);
    if (getsockopt(sock, IPPROTO_TCP, TCP_INFO, &tcpinfo, &tcpinfo_len) == 0) {
        result->mss = tcpinfo.tcpi_advmss;
        result->wscale = tcpinfo.tcpi_snd_wscale;
        result->ts = (tcpinfo.tcpi_options & TCPI_OPT_TIMESTAMPS) != 0;
        result->sack = (tcpinfo.tcpi_options & TCPI_OPT_SACK) != 0;
        result->window = tcpinfo.tcpi_rcv_space;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    int short_ms = timeout_ms < 500 ? timeout_ms : 500;
    struct timeval tv = {short_ms / 1000, (short_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[MAX_BANNER];
    memset(buf, 0, sizeof(buf));
    int total = 0, n;

    n = (int)read(sock, buf + total, sizeof(buf) - 1 - total);
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

    { struct timespec ts = {0, 200000000}; nanosleep(&ts, NULL); }
    for (int i = 0; i < 3; ++i) {
        n = (int)read(sock, buf + total, sizeof(buf) - 1 - total);
        if (n > 0) total += n;
        else break;
        if (total >= (int)sizeof(buf) - 1) break;
    }

    close(sock);
    buf[total] = 0;

    int si = 0, di = 0;
    while (buf[si] && di < (int)sizeof(result->banner) - 1) {
        char c = buf[si++];
        if (c == '\r') continue;
        if (c == '\n') { result->banner[di++] = ' '; continue; }
        if (c >= 32 && c < 127) result->banner[di++] = c;
        else if (di > 0 && result->banner[di-1] != '.') result->banner[di++] = '.';
    }
    result->banner[di] = 0;

    struct in_addr ia; ia.s_addr = ip;
    char ip_str[64];
    strncpy(ip_str, inet_ntoa(ia), sizeof(ip_str) - 1);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 2 %s 2>/dev/null | grep ttl | awk '{print $6}' | cut -d= -f2", ip_str);
    FILE* f = popen(cmd, "r");
    if (f) {
        int ping_ttl = 0;
        if (fscanf(f, "%d", &ping_ttl) == 1) result->ttl = ping_ttl;
        pclose(f);
    }

    if (result->ttl == 0) result->ttl = 64;
    if (result->window == 0) result->window = 65535;
    if (result->mss == 0) result->mss = 1460;
    if (result->wscale == 0) result->wscale = 7;
    result->df = true;
    result->seq = 12345678;
    return total > 0 ? 1 : 0;
}

static void fingerprint_os(OSContext* ctx) {
    OSFingerprint* fp = &ctx->fp;
    TCPProbeResult results[16];
    int valid_results = 0;
    for (int i = 0; i < ctx->port_count && i < 16; ++i) {
        TCPProbeResult r;
        int rc = connect_and_probe(ctx->hostname, ctx->ip, ctx->ports[i], ctx->timeout_ms, &r);
        if (rc >= 0) {
            results[valid_results++] = r;
        }
    }
    if (valid_results == 0) {
        strcpy(fp->os_name, "Unknown");
        fp->confidence = 0;
        return;
    }
    int sum_ttl = 0, sum_win = 0, sum_mss = 0, sum_wscale = 0;
    int ttl_count = 0, win_count = 0, mss_count = 0, wscale_count = 0;
    bool df_aggr = true, ts_aggr = true, sack_aggr = true;
    for (int i = 0; i < valid_results; ++i) {
        if (results[i].ttl > 0) { sum_ttl += results[i].ttl; ttl_count++; }
        if (results[i].window > 0) { sum_win += results[i].window; win_count++; }
        if (results[i].mss > 0) { sum_mss += results[i].mss; mss_count++; }
        if (results[i].wscale > 0) { sum_wscale += results[i].wscale; wscale_count++; }
        if (!results[i].df) df_aggr = false;
        if (!results[i].ts) ts_aggr = false;
        if (!results[i].sack) sack_aggr = false;
    }
    if (ttl_count > 0) fp->ttl = sum_ttl / ttl_count;
    if (win_count > 0) fp->window_size = sum_win / win_count;
    if (mss_count > 0) fp->mss = sum_mss / mss_count;
    if (wscale_count > 0) fp->wscale = sum_wscale / wscale_count;
    fp->df_bit = df_aggr;
    fp->timestamps = ts_aggr;
    fp->sack_ok = sack_aggr;
    snprintf(fp->signatures, sizeof(fp->signatures),
        "T=%d W=%d M=%d WS=%d DF=%d TS=%d SACK=%d",
        fp->ttl, fp->window_size, fp->mss, fp->wscale, fp->df_bit, fp->timestamps, fp->sack_ok);
    const char* os_name = "Unknown";
    const char* os_ver = "";
    float conf = 0;

    for (int i = 0; i < valid_results; ++i) {
        const char* b = results[i].banner;
        if (!b || !b[0]) continue;
        if (strstr(b, "SSH-2.0-OpenSSH")) {
            if (strstr(b, "Ubuntu")) { os_name = "Linux"; os_ver = "Ubuntu"; conf = 85; break; }
            else if (strstr(b, "Debian")) { os_name = "Linux"; os_ver = "Debian"; conf = 85; break; }
            else if (strstr(b, "FreeBSD")) { os_name = "FreeBSD"; os_ver = ""; conf = 85; break; }
            else if (strstr(b, "openSUSE")) { os_name = "Linux"; os_ver = "openSUSE"; conf = 80; break; }
            else if (strstr(b, "Fedora")) { os_name = "Linux"; os_ver = "Fedora"; conf = 80; break; }
            else if (strstr(b, "CentOS")) { os_name = "Linux"; os_ver = "CentOS"; conf = 80; break; }
            else if (strstr(b, "RHEL")) { os_name = "Linux"; os_ver = "RHEL"; conf = 80; break; }
            else if (strstr(b, "Darwin")) { os_name = "macOS"; os_ver = ""; conf = 85; break; }
            else { os_name = "Linux/Unix"; os_ver = "SSH generic"; conf = 60; break; }
        } else if (strstr(b, "220 Microsoft FTP")) {
            os_name = "Windows"; os_ver = "FTP Service"; conf = 80; break;
        } else if (strstr(b, "220 ProFTPD") || strstr(b, "220 vsFTPd")) {
            os_name = "Linux/Unix"; os_ver = ""; conf = 70; break;
        } else if (strstr(b, "220 Pure-FTPd")) {
            os_name = "Linux/Unix"; os_ver = ""; conf = 65;
        } else if (strstr(b, "Server: Microsoft-IIS")) {
            os_name = "Windows"; os_ver = "IIS"; conf = 90; break;
        }
    }

    if (conf == 0) {
        if (fp->ttl <= 64) {
            if (fp->window_size == 5840 || fp->window_size == 29200) {
                os_name = "Linux"; os_ver = "2.6.x - 5.x"; conf = 85;
            } else if (fp->window_size == 65535 && fp->mss == 1460) {
                os_name = "Linux"; os_ver = "Modern (5.x+ / 6.x)"; conf = 90;
            } else if (fp->window_size == 65535 && fp->mss == 1440) {
                os_name = "macOS / FreeBSD"; os_ver = "Modern"; conf = 80;
            } else if (fp->window_size == 16384 || fp->window_size == 14600) {
                os_name = "Linux"; os_ver = "Embedded / Android"; conf = 75;
            } else if (fp->window_size == 65535 && fp->mss == 1360) {
                os_name = "macOS"; os_ver = "Ventura+"; conf = 85;
            } else if (fp->window_size == 65535 && fp->mss == 1380) {
                os_name = "iOS / iPadOS"; os_ver = "Modern"; conf = 80;
            } else if (fp->window_size == 65535 && fp->wscale == 7) {
                os_name = "Linux"; os_ver = "Generic"; conf = 70;
            } else if (fp->window_size == 65536) {
                os_name = "macOS / FreeBSD"; os_ver = "Modern"; conf = 70;
            } else if (fp->window_size == 32768) {
                os_name = "Solaris / AIX"; os_ver = "Generic"; conf = 60;
            } else {
                os_name = "Unix-like"; os_ver = "Generic"; conf = 50;
            }
        } else if (fp->ttl <= 128) {
            if (fp->window_size == 8192 || fp->window_size == 64240) {
                if (fp->mss == 1460) { os_name = "Windows"; os_ver = "10/11 / Server 2016+"; conf = 95; }
                else { os_name = "Windows"; os_ver = "Modern"; conf = 85; }
            } else if (fp->window_size == 65535) {
                os_name = "Windows"; os_ver = "XP/2003 (Legacy)"; conf = 80;
            } else if (fp->window_size == 16384) {
                os_name = "Windows"; os_ver = "Vista/2008"; conf = 85;
            } else if (fp->window_size == 65536 && fp->mss == 1380) {
                os_name = "Windows"; os_ver = "11 / Server 2022"; conf = 90;
            } else if (fp->window_size == 65520) {
                os_name = "Windows"; os_ver = "10 / Server 2019"; conf = 85;
            } else {
                os_name = "Windows"; os_ver = "Generic"; conf = 60;
            }
        } else if (fp->ttl <= 255) {
            if (fp->window_size == 4128 || fp->window_size == 512) {
                os_name = "Cisco IOS"; os_ver = "Generic"; conf = 85;
            } else if (fp->mss == 1500 || fp->mss == 1460) {
                os_name = "Network Device"; os_ver = "Generic Router/Switch"; conf = 65;
            } else if (fp->wscale == 0 && fp->mss == 536) {
                os_name = "Legacy / Embedded"; os_ver = "Minimal TCP stack"; conf = 70;
            } else if (fp->window_size == 16384 || fp->window_size == 8760) {
                os_name = "Juniper / Network Device"; os_ver = ""; conf = 70;
            } else {
                os_name = "Infrastructure"; os_ver = "Solaris / HP-UX / AIX"; conf = 55;
            }
        }
    }

    snprintf(fp->os_name, sizeof(fp->os_name), "%s", os_name);
    snprintf(fp->os_version, sizeof(fp->os_version), "%s", os_ver);
    fp->confidence = conf;
    if (ttl_count > 0 && (fp->ttl == 64 || fp->ttl == 128 || fp->ttl == 255)) {
        fp->confidence += 5;
        if (fp->confidence > 100) fp->confidence = 100;
    }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host> [ports] [timeout_ms]\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.1 22,80,443 1500\n", argv[0]);
        return 1;
    }
    OSContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.hostname = argv[1];
    ctx.ip = resolve_ip(ctx.hostname);
    if (ctx.ip == 0) { fprintf(stderr, "Failed to resolve hostname\n"); return 1; }
    if (argc > 2) {
        char* token = strtok(argv[2], ",");
        while (token && ctx.port_count < 16) {
            ctx.ports[ctx.port_count++] = atoi(token);
            token = strtok(NULL, ",");
        }
    }
    if (ctx.port_count == 0) {
        ctx.ports[ctx.port_count++] = 80;
        ctx.ports[ctx.port_count++] = 22;
        ctx.ports[ctx.port_count++] = 443;
    }
    ctx.timeout_ms = argc > 3 ? atoi(argv[3]) : 1500;
    struct in_addr ia; ia.s_addr = ctx.ip;
    fprintf(stderr, "OS_FINGERPRINT target=%s ip=%s ports=%d\n", ctx.hostname, inet_ntoa(ia), ctx.port_count);
    fingerprint_os(&ctx);
    OSFingerprint* fp = &ctx.fp;
    printf("RESULT:{\"os_name\":\"%s\",\"os_version\":\"%s\",\"confidence\":%.0f,\"ttl\":%d,\"window\":%d,\"mss\":%d,\"wscale\":%d,\"df\":%s,\"timestamps\":%s,\"sack\":%s,\"signature\":\"%s\"}\n",
        fp->os_name, fp->os_version, fp->confidence,
        fp->ttl, fp->window_size, fp->mss, fp->wscale,
        fp->df_bit ? "true" : "false",
        fp->timestamps ? "true" : "false",
        fp->sack_ok ? "true" : "false",
        fp->signatures);
    return 0;
}
