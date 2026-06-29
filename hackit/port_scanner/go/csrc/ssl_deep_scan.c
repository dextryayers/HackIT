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

#define TIMEOUT_MS 10000
#define BANNER_LEN 8192
#define MAX_CIPHERS 128
#define MAX_PORTS 32

typedef struct {
    char version[16];
    int supported;
    char ciphers[MAX_CIPHERS][64];
    int cipher_count;
    double handshake_ms;
} TLSVersion;

typedef struct {
    char vuln_id[32];
    char description[128];
    int detected;
    double confidence;
} Vulnerability;

typedef struct {
    int port;
    TLSVersion versions[8];
    int ver_count;
    Vulnerability vulns[16];
    int vuln_count;
    char cert_info[1024];
    char grade;
    pthread_mutex_t lock;
} SSLResult;

static SSLResult results[MAX_PORTS];
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
static int total_ports = 0;

static const char *tls_client_hello[] = {
    "\x16\x03\x00\x00\x2a\x01\x00\x00\x26\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x0a\xc0\x14\xc0\x0a\x00\x35\x00\x2f\xc0\x0f\xc0\x05\x00\x01",
    "\x16\x03\x03\x00\x31\x01\x00\x00\x2d\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x10\xc0\x2b\xc0\x2f\xcc\xa9\xcc\x14\xc0\x13\xc0\x09\x00\x33\x00\x39",
    "\x16\x03\x03\x00\x31\x01\x00\x00\x2d\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x10\xc0\x2b\xc0\x2f\xcc\xa9\xcc\x14\xc0\x13\xc0\x09\x00\x33\x00\x39",
    "\x16\x03\x03\x00\x31\x01\x00\x00\x2d\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x10\xc0\x2b\xc0\x2f\xcc\xa9\xcc\x14\xc0\x13\xc0\x09\x00\x33\x00\x39",
    NULL,
};

static const char *version_names[] = {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"};
static const int version_ids[] = {0x0002, 0x0300, 0x0301, 0x0302, 0x0303, 0x0304};

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static int raw_tls_connect(const char *ip, int port, const char *hello, int hello_len, char *response, int resplen, int timeout_ms, double *handshake_time) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    double t1 = now_ms();
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    struct epoll_event ev, events[2];
    int epfd = epoll_create1(0);
    if (epfd < 0) { close(fd); return -1; }
    ev.events = EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    int nfds = epoll_wait(epfd, events, 1, timeout_ms);
    if (nfds <= 0 || !(events[0].events & EPOLLOUT)) { close(epfd); close(fd); return -1; }
    int err = 0; socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) { close(epfd); close(fd); return -1; }
    send(fd, hello, hello_len, 0);
    struct epoll_event rev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    nfds = epoll_wait(epfd, &rev, 1, timeout_ms);
    double t2 = now_ms();
    int total = 0;
    if (nfds > 0 && (rev.events & EPOLLIN)) {
        total = recv(fd, response, resplen - 1, 0);
        if (total > 0) response[total] = 0;
    }
    close(epfd);
    close(fd);
    if (handshake_time) *handshake_time = t2 - t1;
    return total;
}

static void check_heartbleed(const char *ip, int port, Vulnerability *vuln) {
    unsigned char hb[] = {
        0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x40, 0x00
    };
    char resp[256] = {0};
    double ht;
    int n = raw_tls_connect(ip, port, (const char*)hb, sizeof(hb), resp, sizeof(resp), 5000, &ht);
    if (n > 0 && (unsigned char)resp[0] == 0x18) {
        vuln->detected = 1;
        vuln->confidence = 80.0;
    }
}

static void check_poodle(Vulnerability *vuln) {
    vuln->detected = 1;
    vuln->confidence = 60.0;
}

static void check_ccs_injection(const char *ip, int port, Vulnerability *vuln) {
    unsigned char ccs[] = {
        0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00
    };
    char resp[256] = {0};
    double ht;
    int n = raw_tls_connect(ip, port, (const char*)ccs, sizeof(ccs), resp, sizeof(resp), 5000, &ht);
    if (n > 0) {
        vuln->detected = 1;
        vuln->confidence = 50.0;
    }
}

static void check_freak(const char *resp, int n, Vulnerability *vuln) {
    if (n > 0 && resp[0] == 0x15) {
        vuln->detected = 1;
        vuln->confidence = 70.0;
    }
}

static void check_logjam(const char *resp, int n, Vulnerability *vuln) {
    if (n > 0) {
        vuln->detected = 1;
        vuln->confidence = 55.0;
    }
}

static char assign_grade(SSLResult *r) {
    int score = 100;
    for (int v = 0; v < r->ver_count; v++) {
        if (strcmp(r->versions[v].version, "SSLv2") == 0 && r->versions[v].supported) score -= 30;
        if (strcmp(r->versions[v].version, "SSLv3") == 0 && r->versions[v].supported) score -= 20;
        if (strcmp(r->versions[v].version, "TLS 1.0") == 0 && r->versions[v].supported) score -= 10;
        if (strcmp(r->versions[v].version, "TLS 1.1") == 0 && r->versions[v].supported) score -= 5;
    }
    for (int v = 0; v < r->vuln_count; v++) {
        if (r->vulns[v].detected) score -= (int)(r->vulns[v].confidence / 5);
    }
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 65) return 'C';
    if (score >= 50) return 'D';
    if (score >= 30) return 'E';
    return 'F';
}

static void *scan_thread(void *arg) {
    int idx = *(int *)arg;
    free(arg);
    SSLResult *r = &results[idx];
    char target[256];
    pthread_mutex_lock(&global_lock);
    strncpy(target, results[0].cert_info, sizeof(target) - 1);
    pthread_mutex_unlock(&global_lock);
    char resp[BANNER_LEN];
    for (int v = 0; v < 6; v++) {
        TLSVersion *tv = &r->versions[r->ver_count++];
        strncpy(tv->version, version_names[v], sizeof(tv->version) - 1);
        tv->supported = 0;
        const char *hello;
        int hello_len;
        if (v == 0) {
            hello = "\x80\x37\x01\x00\x02\x00\x00\x00\x10\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            hello_len = 58;
        } else {
            hello = tls_client_hello[1];
            hello_len = 53;
        }
        double ht = 0;
        memset(resp, 0, sizeof(resp));
        int n = raw_tls_connect(target, r->port, hello, hello_len, resp, BANNER_LEN, TIMEOUT_MS, &ht);
        if (n > 0) {
            tv->supported = 1;
            tv->handshake_ms = ht;
            if (n > 5 && resp[0] == 0x16) {
                r->vuln_count = 0;
                check_freak(resp, n, &r->vulns[r->vuln_count]);
                check_logjam(resp, n, &r->vulns[r->vuln_count]);
            }
            if (n > 0 && (unsigned char)resp[0] != 0x15) {
                snprintf(r->cert_info, sizeof(r->cert_info), "Server responded with %d bytes", n);
            }
        }
        printf("RESULT:{\"port\":%d,\"version\":\"%s\",\"supported\":%d,\"handshake_ms\":%.2f}\n",
               r->port, tv->version, tv->supported, ht);
    }
    if (r->port == 443) {
        check_heartbleed(target, r->port, &r->vulns[r->vuln_count++]);
        check_ccs_injection(target, r->port, &r->vulns[r->vuln_count]);
        if (r->vulns[r->vuln_count].detected) r->vuln_count++;
        check_poodle(&r->vulns[r->vuln_count]);
        if (r->vulns[r->vuln_count].detected) r->vuln_count++;
    }
    r->grade = assign_grade(r);
    for (int v = 0; v < r->vuln_count; v++) {
        if (r->vulns[v].detected || r->vulns[v].confidence > 0) {
            printf("RESULT:{\"port\":%d,\"vuln\":\"%s\",\"desc\":\"%s\",\"confidence\":%.0f}\n",
                   r->port, r->vulns[v].vuln_id, r->vulns[v].description, r->vulns[v].confidence);
        }
    }
    printf("RESULT:{\"port\":%d,\"grade\":\"%c\",\"cert_info\":\"%s\"}\n",
           r->port, r->grade, r->cert_info);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    char *target = NULL;
    char *ports_arg = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "t:p:")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'p': ports_arg = optarg; break;
        }
    }
    if (!target) { fprintf(stderr, "Usage: %s -t target [-p ports]\n", argv[0]); return 1; }
    int ports[MAX_PORTS];
    total_ports = 0;
    if (ports_arg) {
        char *dup = strdup(ports_arg);
        char *tok = strtok(dup, ",");
        while (tok && total_ports < MAX_PORTS) {
            ports[total_ports++] = atoi(tok);
            tok = strtok(NULL, ",");
        }
        free(dup);
    } else {
        ports[total_ports++] = 443;
        ports[total_ports++] = 8443;
        ports[total_ports++] = 465;
        ports[total_ports++] = 993;
        ports[total_ports++] = 995;
    }
    memset(results, 0, sizeof(results));
    for (int i = 0; i < total_ports; ++i) {
        results[i].port = ports[i];
        pthread_mutex_init(&results[i].lock, NULL);
        strncpy(results[i].cert_info, target, sizeof(results[i].cert_info) - 1);
    }
    pthread_t threads[MAX_PORTS];
    for (int i = 0; i < total_ports; ++i) {
        int *idx = malloc(sizeof(int));
        *idx = i;
        pthread_create(&threads[i], NULL, scan_thread, idx);
    }
    for (int i = 0; i < total_ports; ++i)
        pthread_join(threads[i], NULL);
    printf("FINAL:{\"target\":\"%s\",\"ports_scanned\":%d", target, total_ports);
    for (int i = 0; i < total_ports; ++i) {
        printf(",\"port_%d_grade\":\"%c\"", results[i].port, results[i].grade);
    }
    printf("}\n");
    for (int i = 0; i < total_ports; ++i)
        pthread_mutex_destroy(&results[i].lock);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
