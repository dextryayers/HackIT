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

#define TIMEOUT_MS 5000
#define BANNER_LEN 4096
#define MAX_SIGNATURES 50
#define MAX_PORTS 20
#define MAX_WORKERS 10

typedef struct {
    char device_type[64];
    char vendor[64];
    char model[64];
    const char *signature;
    int port;
    double confidence;
} IOTSignature;

typedef struct {
    int port;
    char service[32];
    char banner[BANNER_LEN];
    char title[256];
    char snmp_community[64];
    char mqtt_topic[256];
    IOTSignature matches[MAX_SIGNATURES];
    int match_count;
} IOTResult;

static const IOTSignature iot_signatures[] = {
    {"IP Camera", "Hikvision", "DS-2CD", "Hikvision", 80, 95.0},
    {"IP Camera", "Hikvision", "DS-2CD", "hikvision", 80, 90.0},
    {"IP Camera", "Dahua", "IPC-", "Dahua", 80, 95.0},
    {"IP Camera", "Dahua", "IPC-", "dahua", 80, 90.0},
    {"IP Camera", "TP-Link", "NC-", "TP-LINK", 80, 90.0},
    {"IP Camera", "Foscam", "FI-", "Foscam", 80, 95.0},
    {"IP Camera", "Axis", "M-", "Axis", 80, 90.0},
    {"Router", "Cisco", "Cisco IOS", "Cisco", 80, 85.0},
    {"Router", "Cisco", "Cisco IOS", "cisco", 23, 80.0},
    {"Router", "MikroTik", "RouterOS", "MikroTik", 80, 95.0},
    {"Router", "MikroTik", "RouterOS", "RouterOS", 80, 95.0},
    {"Router", "Ubiquiti", "EdgeRouter", "Ubiquiti", 80, 90.0},
    {"Router", "Ubiquiti", "EdgeRouter", "ubnt", 80, 85.0},
    {"Router", "TP-Link", "TL-WR", "TP-LINK", 80, 85.0},
    {"Router", "D-Link", "DIR-", "D-Link", 80, 85.0},
    {"Router", "Netgear", "N-", "Netgear", 80, 80.0},
    {"Router", "ASUS", "RT-", "ASUS", 80, 80.0},
    {"Router", "Linksys", "WRT", "Linksys", 80, 80.0},
    {"Printer", "HP", "LaserJet", "HP LaserJet", 80, 90.0},
    {"Printer", "HP", "LaserJet", "hp LaserJet", 80, 90.0},
    {"Printer", "Brother", "HL-", "Brother", 80, 85.0},
    {"Printer", "Canon", "iR-", "Canon", 80, 85.0},
    {"Printer", "Epson", "WF-", "Epson", 80, 80.0},
    {"Smart Home", "Philips", "Hue", "Philips Hue", 80, 95.0},
    {"Smart Home", "Philips", "Hue", "hue", 80, 85.0},
    {"Smart Home", "Nest", "Thermostat", "Nest", 80, 90.0},
    {"Smart Home", "Sonos", "Play", "Sonos", 80, 90.0},
    {"Smart Home", "Ring", "Doorbell", "Ring", 80, 85.0},
    {"Smart Home", "August", "Smart Lock", "August", 80, 80.0},
    {"PLC", "Siemens", "S7-", "Siemens", 102, 90.0},
    {"PLC", "Allen Bradley", "ControlLogix", "Allen-Bradley", 44818, 85.0},
    {"PLC", "Modicon", "M340", "Modicon", 502, 85.0},
    {"PLC", "Schneider", "Quantum", "Schneider", 502, 80.0},
    {"RTU", "Schweitzer", "SEL-", "SEL", 23, 85.0},
    {"RTU", "GE", "D20", "GE", 23, 75.0},
    {"NAS", "Synology", "DS-", "Synology", 80, 90.0},
    {"NAS", "QNAP", "TS-", "QNAP", 80, 90.0},
    {"VoIP", "Asterisk", "PBX", "Asterisk", 5060, 85.0},
    {"VoIP", "Cisco", "SPA", "Cisco SPA", 80, 80.0},
    {"VoIP", "Grandstream", "GXP", "Grandstream", 80, 80.0},
    {"Medical", "GE", "PACS", "GE Healthcare", 80, 65.0},
    {"Building Mgmt", "Johnson Controls", "Metasys", "Johnson", 80, 70.0},
    {"Building Mgmt", "Honeywell", "Tridium", "Honeywell", 80, 70.0},
    {"UPS", "APC", "Smart-UPS", "APC", 80, 85.0},
    {"UPS", "APC", "Smart-UPS", "apc", 80, 80.0},
    {"", "", "", "", 0, 0.0},
};

static int iot_ports[] = {80, 443, 23, 22, 161, 1883, 5683, 8080, 8443, 102, 502, 44818, 5060, 47808, 1900, 0};
static IOTResult iot_results[MAX_PORTS];
static pthread_mutex_t iot_lock = PTHREAD_MUTEX_INITIALIZER;
static char iot_target[256];

static HOT int http_fetch_title(const char *RESTRICT ip, int port, char *RESTRICT title, int title_len, char *RESTRICT full_resp, int full_len) {
    int fd, rc, epfd, nfds, err, total, one;
    struct sockaddr_in addr;
    struct epoll_event ev, events[1];
    socklen_t elen;
    char req[512];
    char *t, *end;
    int reqlen;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (unlikely(fd < 0)) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (unlikely(rc < 0 && errno != EINPROGRESS)) { close(fd); return -1; }
    epfd = epoll_create1(0);
    if (unlikely(epfd < 0)) { close(fd); return -1; }
    ev.events = EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    nfds = epoll_wait(epfd, events, 1, TIMEOUT_MS);
    if (unlikely(nfds <= 0 || !(events[0].events & EPOLLOUT))) { close(epfd); close(fd); return -1; }
    err = 0; elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (unlikely(err)) { close(epfd); close(fd); return -1; }
    reqlen = snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip);
    send(fd, req, (size_t)reqlen, 0);
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    nfds = epoll_wait(epfd, events, 1, TIMEOUT_MS);
    total = 0;
    if (nfds > 0 && (events[0].events & EPOLLIN)) {
        total = recv(fd, full_resp, full_len - 1, 0);
        if (total > 0) full_resp[total] = 0;
    }
    close(epfd);
    close(fd);
    if (likely(total > 0)) {
        t = strstr(full_resp, "<title>");
        if (t) {
            t += 7;
            end = strstr(t, "</title>");
            if (end) *end = 0;
            strncpy(title, t, (size_t)title_len - 1);
        }
    }
    return total;
}

static void match_iot_signatures(IOTResult *r) {
    for (int s = 0; iot_signatures[s].signature[0]; s++) {
        if (iot_signatures[s].port != r->port) continue;
        int matched = 0;
        if (strlen(r->title) > 0 && strcasestr(r->title, iot_signatures[s].signature)) matched = 1;
        if (strlen(r->banner) > 0 && strcasestr(r->banner, iot_signatures[s].signature)) matched = 1;
        if (matched && r->match_count < MAX_SIGNATURES)
            r->matches[r->match_count++] = iot_signatures[s];
    }
}

typedef struct { int port_idx; char target[256]; } WorkerArg;

static HOT void *scan_worker(void *arg) {
    int m, port, fd, rc, epfd, nfds, err, n, total;
    char outbuf[2048];
    struct sockaddr_in addr;
    struct epoll_event ev, events[1];
    socklen_t elen;
    struct timeval tv;
    WorkerArg *wa = (WorkerArg *)arg;
    port = iot_ports[wa->port_idx];
    if (port == 0) { free(wa); return NULL; }
    IOTResult r;
    memset(&r, 0, sizeof(r));
    r.port = port;
    char resp[BANNER_LEN] = {0};
    if (port == 80 || port == 443 || port == 8080 || port == 8443) {
        strncpy(r.service, "http", sizeof(r.service) - 1);
        http_fetch_title(wa->target, port, r.title, sizeof(r.title), resp, BANNER_LEN);
        strncpy(r.banner, resp, BANNER_LEN - 1);
        match_iot_signatures(&r);
    } else if (port == 23 || port == 22) {
        strncpy(r.service, port == 23 ? "telnet" : "ssh", sizeof(r.service) - 1);
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd >= 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, wa->target, &addr.sin_addr);
            int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
            if (!(rc < 0 && errno != EINPROGRESS)) {
                struct epoll_event ev, events[1];
                int epfd = epoll_create1(0);
                if (epfd >= 0) {
                    ev.events = EPOLLOUT | EPOLLERR;
                    ev.data.fd = fd;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
                    int nfds = epoll_wait(epfd, events, 1, 2000);
                    if (nfds > 0) {
                        ev.events = EPOLLIN;
                        epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
                        nfds = epoll_wait(epfd, events, 1, 2000);
                        if (nfds > 0 && (events[0].events & EPOLLIN)) {
                            recv(fd, resp, BANNER_LEN - 1, 0);
                            strncpy(r.banner, resp, BANNER_LEN - 1);
                            match_iot_signatures(&r);
                        }
                    }
                    close(epfd);
                }
            }
            close(fd);
        }
    } else if (port == 1883) {
        strncpy(r.service, "mqtt", sizeof(r.service) - 1);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(1883);
            inet_pton(AF_INET, wa->target, &addr.sin_addr);
            struct timeval tv = {3, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                unsigned char connect_pkt[] = {
                    0x10, 0x0e, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
                    0x04, 0x02, 0x00, 0x3c, 0x00, 0x02, 0x68, 0x69
                };
                send(fd, connect_pkt, sizeof(connect_pkt), 0);
                int n = recv(fd, resp, BANNER_LEN - 1, 0);
                if (n > 0) { resp[n] = 0; strncpy(r.banner, resp, BANNER_LEN - 1); }
            }
            close(fd);
        }
    }
    for (int m = 0; m < r.match_count; m++) {
        int olen = snprintf(outbuf, sizeof(outbuf),
            "RESULT:{\"ip\":\"%s\",\"port\":%d,\"service\":\"%s\",\"device\":\"%s\","
            "\"vendor\":\"%s\",\"model\":\"%s\",\"title\":\"%s\",\"confidence\":%.1f}\n",
            wa->target, r.port, r.service, r.matches[m].device_type, r.matches[m].vendor,
            r.matches[m].model, r.title, r.matches[m].confidence);
        fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    }
    if (r.match_count == 0 && resp[0]) {
        int olen = snprintf(outbuf, sizeof(outbuf),
            "RESULT:{\"ip\":\"%s\",\"port\":%d,\"service\":\"%s\",\"title\":\"%s\",\"matches\":0}\n",
            wa->target, r.port, r.service, r.title);
        fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    }
    pthread_mutex_lock(&iot_lock);
    iot_results[wa->port_idx] = r;
    pthread_mutex_unlock(&iot_lock);
    free(wa);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    char *target = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "t:p:")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'p': break;
        }
    }
    if (!target) { fprintf(stderr, "Usage: %s -t target\n", argv[0]); return 1; }
    strncpy(iot_target, target, sizeof(iot_target) - 1);
    memset(iot_results, 0, sizeof(iot_results));
    int total = 0;
    while (iot_ports[total]) total++;
    pthread_t threads[MAX_PORTS];
    for (int i = 0; i < total; ++i) {
        WorkerArg *wa = malloc(sizeof(WorkerArg));
        wa->port_idx = i;
        strncpy(wa->target, target, sizeof(wa->target) - 1);
        pthread_create(&threads[i], NULL, scan_worker, wa);
    }
    for (int i = 0; i < total; ++i)
        pthread_join(threads[i], NULL);
    int total_matches = 0;
    for (int i = 0; i < total; ++i) total_matches += iot_results[i].match_count;
    printf("FINAL:{\"target\":\"%s\",\"ports_scanned\":%d,\"devices_identified\":%d}\n",
           target, total, total_matches);
    return 0;
}

// vim: ts=4 sw=4 et tw=80
