#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include "optimize.h"

typedef struct {
    char *target;
    int port_start;
    int port_end;
    char *scan_type;
    int timeout_ms;
} ScanJob;

typedef struct {
    int port;
    char *status;
    char *service;
    char *banner;
    char *error;
} ScanResult;

#define MAX_QUEUED_JOBS 65536
#define MAX_RESULTS 1048576

typedef struct {
    ScanJob *queue;
    volatile int queue_head;
    volatile int queue_tail;
    volatile int queue_count;
    int queue_capacity;

    ScanResult *results;
    volatile int result_count;
    int result_capacity;

    int thread_count;
    pthread_t *threads;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    volatile int shutdown;

    int active_jobs;
} ScanCoordinator;

static const char *get_svc_name(int port) {
    typedef struct { int port; const char *name; } pmap_t;
    static const pmap_t pmap[] = {
        {21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},
        {80,"http"},{110,"pop3"},{111,"rpcbind"},{135,"epmap"},{139,"netbios"},
        {143,"imap"},{389,"ldap"},{443,"https"},{445,"smb"},{465,"smtps"},
        {514,"shell"},{543,"klogin"},{544,"kshell"},{587,"submission"},
        {631,"ipp"},{636,"ldaps"},{873,"rsync"},{990,"ftps"},{992,"telnets"},
        {993,"imaps"},{995,"pop3s"},{1080,"socks"},{1194,"openvpn"},
        {1352,"lotus"},{1433,"mssql"},{1521,"oracle"},{1723,"pptp"},
        {2049,"nfs"},{2082,"cpanel"},{2083,"cpanel-ssl"},{2086,"whm"},
        {2087,"whm-ssl"},{2096,"webmail"},{2375,"docker"},{2376,"docker-tls"},
        {3128,"squid"},{3306,"mysql"},{3389,"rdp"},{3690,"svn"},
        {4899,"radmin"},{5000,"upnp"},{5060,"sip"},{5222,"xmpp"},
        {5432,"postgres"},{5555,"freeciv"},{5631,"pcany"},{5666,"nagios"},
        {5800,"vnc"},{5900,"vnc"},{5984,"couchdb"},{6000,"x11"},
        {6379,"redis"},{6667,"irc"},{6697,"irc-ssl"},{8080,"http-alt"},
        {8443,"https-alt"},{9000,"cslistener"},{9090,"websm"},{9100,"jetdirect"},
        {9200,"elastic"},{9418,"git"},{10000,"ndmp"},{11211,"memcached"},
        {27017,"mongod"},{32400,"plex"},{0,NULL}
    };
    for (int i = 0; pmap[i].name; i++)
        if (pmap[i].port == port) return pmap[i].name;
    return "unknown";
}

static int tcp_scan_port(const char *target, int port, int timeout_ms, char *banner, int banner_size) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, target, &addr.sin_addr) != 1) {
        struct hostent *he = gethostbyname(target);
        if (!he || !he->h_addr_list[0]) return 0;
        memcpy(&addr.sin_addr, he->h_addr_list[0], 4);
    }

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return 0;

    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    struct pollfd pf = {.fd = sock, .events = POLLOUT | POLLERR};
    int n = poll(&pf, 1, timeout_ms);
    int result = 0;
    if (n > 0 && (pf.revents & POLLOUT)) {
        int so_err = 0;
        socklen_t el = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
        if (so_err == 0) {
            result = 1;
            if (banner && banner_size > 0) {
                int fl = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, fl & ~O_NONBLOCK);
                struct timeval tv;
                tv.tv_sec = timeout_ms / 1000;
                tv.tv_usec = (timeout_ms % 1000) * 1000;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                char buf[4096];
                int total = 0;
                int r = (int)read(sock, buf, sizeof(buf) - 1);
                if (r > 0) total += r;
                const char *probe = NULL;
                if (port == 21) probe = "SYST\r\n";
                else if (port == 25 || port == 587) probe = "EHLO scan\r\n";
                else if (port == 110 || port == 995) probe = "CAPA\r\n";
                else if (port == 143 || port == 993) probe = "A001 CAPABILITY\r\n";
                else if (port == 80 || port == 8080 || port == 8000 || port == 8888 || port == 8443)
                    probe = "HEAD / HTTP/1.0\r\n\r\n";
                else if (port == 6379) probe = "PING\r\n";
                else if (port == 3306) { }
                if (probe) send(sock, probe, (int)strlen(probe), 0);
                r = (int)read(sock, buf + total, sizeof(buf) - 1 - total);
                if (r > 0) total += r;
                if (total > 0) {
                    buf[total] = 0;
                    int si = 0, di = 0;
                    while (buf[si] && di < banner_size - 1) {
                        char c = buf[si++];
                        if (c == '\r') continue;
                        if (c == '\n') { banner[di++] = ' '; continue; }
                        if (c >= 32 && c < 127) banner[di++] = c;
                        else if (di > 0 && banner[di - 1] != '.') banner[di++] = '.';
                    }
                    banner[di] = 0;
                }
            }
        }
    }
    close(sock);
    return result;
}

static void *coordinator_worker(void *arg) {
    ScanCoordinator *c = (ScanCoordinator *)arg;
    char banner[4096];

    for (;;) {
        pthread_mutex_lock(&c->lock);
        while (c->queue_count == 0 && !c->shutdown) {
            pthread_cond_wait(&c->cond, &c->lock);
        }
        if (c->shutdown && c->queue_count == 0) {
            pthread_mutex_unlock(&c->lock);
            break;
        }

        ScanJob job = c->queue[c->queue_head];
        c->queue_head = (c->queue_head + 1) % c->queue_capacity;
        c->queue_count--;
        pthread_mutex_unlock(&c->lock);

        for (int port = job.port_start; port <= job.port_end; port++) {
            banner[0] = 0;
            int state = 0;
            char *status = strdup("closed");
            char *err = NULL;

            if (strcmp(job.scan_type, "tcp") == 0 || strcmp(job.scan_type, "connect") == 0) {
                state = tcp_scan_port(job.target, port, job.timeout_ms, banner, sizeof(banner));
            }

            if (state) {
                free(status);
                status = strdup("open");
            } else {
                free(status);
                status = strdup("filtered");
            }

            const char *svc = get_svc_name(port);

            pthread_mutex_lock(&c->lock);
            if (c->result_count < c->result_capacity) {
                int idx = c->result_count++;
                c->results[idx].port = port;
                c->results[idx].status = status;
                c->results[idx].service = strdup(svc);
                c->results[idx].banner = banner[0] ? strdup(banner) : strdup("");
                c->results[idx].error = err ? strdup(err) : NULL;
            } else {
                free(status);
            }
            pthread_mutex_unlock(&c->lock);
        }

        free(job.target);
        free(job.scan_type);

        pthread_mutex_lock(&c->lock);
        c->active_jobs--;
        pthread_cond_broadcast(&c->cond);
        pthread_mutex_unlock(&c->lock);
    }
    return NULL;
}

ScanCoordinator *coordinator_create(int thread_count) {
    if (thread_count <= 0) thread_count = 4;
    if (thread_count > 256) thread_count = 256;

    ScanCoordinator *c = calloc(1, sizeof(ScanCoordinator));
    if (!c) return NULL;

    c->queue = calloc(MAX_QUEUED_JOBS, sizeof(ScanJob));
    c->queue_capacity = MAX_QUEUED_JOBS;
    c->queue_head = 0;
    c->queue_tail = 0;
    c->queue_count = 0;

    c->results = calloc(MAX_RESULTS, sizeof(ScanResult));
    c->result_capacity = MAX_RESULTS;
    c->result_count = 0;

    c->thread_count = thread_count;
    c->shutdown = 0;
    c->active_jobs = 0;

    pthread_mutex_init(&c->lock, NULL);
    pthread_cond_init(&c->cond, NULL);

    c->threads = calloc(thread_count, sizeof(pthread_t));
    if (!c->threads) { free(c->queue); free(c->results); free(c); return NULL; }

    for (int i = 0; i < thread_count; i++) {
        pthread_create(&c->threads[i], NULL, coordinator_worker, c);
    }

    return c;
}

void coordinator_add_job(ScanCoordinator *c, ScanJob job) {
    if (!c) return;

    pthread_mutex_lock(&c->lock);
    if (c->queue_count >= c->queue_capacity) {
        pthread_mutex_unlock(&c->lock);
        return;
    }
    c->queue[c->queue_tail] = job;
    c->queue_tail = (c->queue_tail + 1) % c->queue_capacity;
    c->queue_count++;
    c->active_jobs++;
    pthread_cond_signal(&c->cond);
    pthread_mutex_unlock(&c->lock);
}

ScanResult *coordinator_get_results(ScanCoordinator *c, int *count) {
    if (!c || !count) return NULL;

    pthread_mutex_lock(&c->lock);
    while (c->active_jobs > 0) {
        pthread_cond_wait(&c->cond, &c->lock);
    }
    *count = c->result_count;
    ScanResult *results = c->results;
    c->results = calloc(MAX_RESULTS, sizeof(ScanResult));
    c->result_count = 0;
    c->result_capacity = MAX_RESULTS;
    pthread_mutex_unlock(&c->lock);

    return results;
}

void coordinator_destroy(ScanCoordinator *c) {
    if (!c) return;

    pthread_mutex_lock(&c->lock);
    c->shutdown = 1;
    pthread_cond_broadcast(&c->cond);
    pthread_mutex_unlock(&c->lock);

    for (int i = 0; i < c->thread_count; i++) {
        pthread_join(c->threads[i], NULL);
    }

    pthread_mutex_lock(&c->lock);
    for (int i = 0; i < c->result_count; i++) {
        free(c->results[i].status);
        free(c->results[i].service);
        free(c->results[i].banner);
        free(c->results[i].error);
    }
    free(c->results);
    free(c->queue);
    free(c->threads);
    pthread_mutex_unlock(&c->lock);

    pthread_mutex_destroy(&c->lock);
    pthread_cond_destroy(&c->cond);
    memset(c, 0, sizeof(ScanCoordinator));
    free(c);
}

static void scan_result_free_batch(ScanResult *results, int count) {
    if (!results) return;
    for (int i = 0; i < count; i++) {
        free(results[i].status);
        free(results[i].service);
        free(results[i].banner);
        free(results[i].error);
    }
    free(results);
}
