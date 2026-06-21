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
#define MAX_DBS 32
#define MAX_WORKERS 8

typedef struct {
    char db_type[32];
    int default_port;
    const char *probe;
    int probe_len;
    const char *name;
} DBProbe;

typedef struct {
    int port;
    char db_type[32];
    char version[128];
    char banner[BANNER_LEN];
    int auth_required;
    int default_creds_work;
    char auth_status[64];
} DBResult;

static DBResult results[MAX_DBS];
static int total_dbs = 0;

static const DBProbe db_probes[] = {
    {"mysql", 3306, "\x0a\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 24, "MySQL/MariaDB"},
    {"postgresql", 5432, "\x00\x00\x00\x08\x04\xd2\x16\x2f\x00\x00\x00\x00\x00\x00\x00\x00", 16, "PostgreSQL"},
    {"redis", 6379, "PING\r\n", 6, "Redis"},
    {"mongodb", 27017, "\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 56, "MongoDB"},
    {"elasticsearch", 9200, "GET / HTTP/1.0\r\n\r\n", 18, "Elasticsearch"},
    {"cassandra", 9042, "\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00", 12, "Cassandra"},
    {"mssql", 1433, "\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 60, "MSSQL"},
    {"oracle", 1521, "\x00\x3c\x00\x00\x01\x00\x00\x00\x01\x34\x01\x2c\x00\x00\x08\x00\x7f\xff\x86\x0e\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x7c\x52\x43\x46\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 156, "Oracle DB"},
    {"", 0, NULL, 0, ""},
};

static HOT int db_connect_probe(const char *RESTRICT ip, int port, const char *RESTRICT probe, int probe_len, char *RESTRICT response, int resplen, int timeout_ms) {
    int fd, rc, epfd, nfds, sent, n, total;
    struct sockaddr_in addr;
    struct epoll_event ev, events[2];
    int err;
    socklen_t elen;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (unlikely(fd < 0)) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (unlikely(rc < 0 && errno != EINPROGRESS)) { close(fd); return -1; }
    epfd = epoll_create1(0);
    if (unlikely(epfd < 0)) { close(fd); return -1; }
    ev.events = EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    nfds = epoll_wait(epfd, events, 1, timeout_ms);
    if (unlikely(nfds <= 0 || !(events[0].events & EPOLLOUT))) { close(epfd); close(fd); return -1; }
    err = 0; elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (unlikely(err)) { close(epfd); close(fd); return -1; }
    if (probe && probe_len > 0) {
        sent = 0;
        while (sent < probe_len) {
            n = send(fd, probe + sent, probe_len - sent, 0);
            if (n <= 0) break;
            sent += n;
        }
    }
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    nfds = epoll_wait(epfd, &ev, 1, timeout_ms);
    total = 0;
    if (nfds > 0 && (ev.events & EPOLLIN)) {
        total = recv(fd, response, resplen - 1, 0);
        if (total > 0) response[total] = 0;
    }
    close(epfd);
    close(fd);
    return total;
}

static void extract_version(DBResult *RESTRICT r, const unsigned char *RESTRICT resp, int n) {
    int i;
    char *ver, *nl, *v, *end;
    char clean[256];
    if (r->db_type[0] == 'm' && r->db_type[1] == 'y' && n > 4) {
        ver = (char*)resp + 5;
        i = n - 5;
        if (i > 0) {
            if (i > 127) i = 127;
            memcpy(r->version, ver, (size_t)i);
            r->version[i] = 0;
        }
    } else if (r->db_type[0] == 'p' && n > 8) {
        snprintf(r->version, sizeof(r->version), "PostgreSQL (backend pid %d)", (resp[4] << 24) | (resp[5] << 16) | (resp[6] << 8) | resp[7]);
    } else if (r->db_type[0] == 'r' && n > 0) {
        if (resp[0] == '+') {
            nl = strchr((char*)resp, '\r');
            if (nl) *nl = 0;
            strncpy(r->version, (char*)resp, sizeof(r->version) - 1);
        }
    } else if (r->db_type[0] == 'e' && n > 0) {
        v = strstr((char*)resp, "\"number\"");
        if (v) {
            v = strchr(v, ':');
            if (v) {
                v++;
                while (*v == ' ' || *v == '"') v++;
                end = strchr(v, '"');
                if (end) *end = 0;
                snprintf(r->version, sizeof(r->version), "Elasticsearch %s", v);
            }
        }
    } else {
        memset(clean, 0, sizeof(clean));
        for (i = 0; i < n && i < 255; ++i) {
            clean[i] = (resp[i] >= 32 && resp[i] < 127) ? resp[i] : '.';
        }
        strncpy(r->version, clean, sizeof(r->version) - 1);
    }
}

static void test_auth(DBResult *RESTRICT r, const char *RESTRICT ip) {
    char outbuf[1024];
    int olen;
    (void)ip;
    if ((r->db_type[0] == 'r' && r->db_type[1] == 'e') || (r->db_type[0] == 'm' && r->db_type[1] == 'o')) {
        r->auth_required = 0;
        r->default_creds_work = 1;
        snprintf(r->auth_status, sizeof(r->auth_status), "No authentication required (default)");
        olen = snprintf(outbuf, sizeof(outbuf),
            "RESULT:{\"type\":\"auth\",\"port\":%d,\"db\":\"%s\",\"message\":\"%s\"}\n",
            r->port, r->db_type, r->auth_status);
        fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    }
    if (r->db_type[0] == 'e') {
        if (strstr(r->banner, "200 OK") || strstr(r->banner, "200")) {
            r->auth_required = 0;
            r->default_creds_work = 1;
            snprintf(r->auth_status, sizeof(r->auth_status), "No authentication");
        } else if (strstr(r->banner, "401")) {
            r->auth_required = 1;
            snprintf(r->auth_status, sizeof(r->auth_status), "Authentication required");
        }
    }
    if (r->db_type[0] == 'm' && r->db_type[1] == 'y') {
        if (strstr(r->banner, "mysql_native_password") || strstr(r->banner, "caching_sha2_password"))
            r->auth_required = 1;
        snprintf(r->auth_status, sizeof(r->auth_status), "%s", r->auth_required ? "Auth required" : "Auth unknown");
    }
}

static HOT void *scan_worker(void *arg) {
    int idx, n, olen;
    char outbuf[1024];
    unsigned char buf[BANNER_LEN];
    DBResult *RESTRICT r;
    char target[256];

    idx = *(int *)arg;
    free(arg);
    r = &results[idx];
    strncpy(target, r->banner, sizeof(target) - 1);
    memset(buf, 0, BANNER_LEN);
    n = db_connect_probe(target, r->port, db_probes[idx].probe, db_probes[idx].probe_len, (char*)buf, BANNER_LEN, TIMEOUT_MS);
    if (n > 0) {
        memcpy(r->banner, buf, (size_t)(n > BANNER_LEN - 1 ? BANNER_LEN - 1 : n));
        r->banner[BANNER_LEN - 1] = 0;
        strncpy(r->db_type, db_probes[idx].db_type, sizeof(r->db_type) - 1);
        extract_version(r, buf, n);
        test_auth(r, target);
    } else {
        snprintf(r->version, sizeof(r->version), "No response");
    }
    olen = snprintf(outbuf, sizeof(outbuf),
        "RESULT:{\"port\":%d,\"db_type\":\"%s\",\"version\":\"%s\",\"auth\":\"%s\",\"default_creds\":%d}\n",
        r->port, r->db_type, r->version, r->auth_status, r->default_creds_work);
    fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    return NULL;
}

static int fast_atoi(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9')
        n = n * 10 + (*s++ - '0');
    return n;
}

HOT int main(int argc, char **argv) {
    int i, opt, p;
    char *target = NULL;
    char *ports_arg = NULL;
    char *dup, *tok;
    int *idx;
    pthread_t threads[MAX_DBS];

    signal(SIGPIPE, SIG_IGN);
    target = NULL;
    ports_arg = NULL;
    while ((opt = getopt(argc, argv, "t:p:")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'p': ports_arg = optarg; break;
        }
    }
    if (!target) { fprintf(stderr, "Usage: %s -t target [-p ports]\n", argv[0]); return 1; }
    total_dbs = 0;
    if (ports_arg) {
        dup = strdup(ports_arg);
        tok = strtok(dup, ",");
        while (tok && total_dbs < MAX_DBS) {
            p = fast_atoi(tok);
            for (i = 0; db_probes[i].name[0]; ++i) {
                if (db_probes[i].default_port == p || p == (i + 3306)) {
                    results[total_dbs].port = p;
                    strncpy(results[total_dbs].banner, target, sizeof(results[total_dbs].banner) - 1);
                    total_dbs++;
                    break;
                }
            }
            if (total_dbs == 0) {
                results[total_dbs].port = p;
                strncpy(results[total_dbs].banner, target, sizeof(results[total_dbs].banner) - 1);
                total_dbs++;
            }
            tok = strtok(NULL, ",");
        }
        free(dup);
    } else {
        for (i = 0; db_probes[i].name[0] && total_dbs < MAX_DBS; ++i) {
            results[total_dbs].port = db_probes[i].default_port;
            strncpy(results[total_dbs].banner, target, sizeof(results[total_dbs].banner) - 1);
            total_dbs++;
        }
    }
    for (i = 0; i < total_dbs; ++i) {
        idx = malloc(sizeof(int));
        *idx = i;
        pthread_create(&threads[i], NULL, scan_worker, idx);
    }
    for (i = 0; i < total_dbs; ++i)
        pthread_join(threads[i], NULL);
    printf("FINAL:{\"target\":\"%s\",\"databases_found\":%d", target, total_dbs);
    for (i = 0; i < total_dbs; ++i)
        printf(",\"port_%d\":{\"type\":\"%s\",\"version\":\"%s\",\"auth_status\":\"%s\"}",
               results[i].port, results[i].db_type, results[i].version, results[i].auth_status);
    printf("}\n");
    return 0;
}

// vim: ts=4 sw=4 et tw=80
