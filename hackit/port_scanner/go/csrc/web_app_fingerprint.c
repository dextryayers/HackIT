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
#define BANNER_LEN 8192
#define MAX_SIGNATURES 64
#define MAX_PATHS 32
#define MAX_PORTS 16
#define MAX_WORKERS 8

typedef struct {
    char name[64];
    char category[32];
    char signature[128];
    int sig_len;
    double confidence;
} Fingerprint;

typedef struct {
    int port;
    char banner[BANNER_LEN];
    Fingerprint detected[MAX_SIGNATURES];
    int match_count;
    char server_header[256];
    char technology[512];
} WebAppResult;

static const Fingerprint signatures[] = {
    {"WordPress", "CMS", "/wp-admin/", 10, 95.0},
    {"WordPress", "CMS", "/wp-content/", 11, 90.0},
    {"WordPress", "CMS", "/wp-json/", 8, 85.0},
    {"WordPress", "CMS", "wp-content", 10, 80.0},
    {"Drupal", "CMS", "/sites/default", 15, 90.0},
    {"Drupal", "CMS", "/misc/drupal", 12, 85.0},
    {"Drupal", "CMS", "Drupal", 6, 75.0},
    {"Joomla", "CMS", "/media/system", 13, 90.0},
    {"Joomla", "CMS", "/components/com", 16, 85.0},
    {"Joomla", "CMS", "Joomla", 6, 75.0},
    {"Magento", "CMS", "/skin/frontend", 14, 85.0},
    {"Magento", "CMS", "Magento", 7, 75.0},
    {"Django", "Framework", "csrfmiddlewaretoken", 19, 85.0},
    {"Django", "Framework", "Django", 6, 75.0},
    {"Ruby on Rails", "Framework", "rails-token", 11, 85.0},
    {"Ruby on Rails", "Framework", "Rails", 5, 75.0},
    {"Laravel", "Framework", "Laravel", 7, 80.0},
    {"Laravel", "Framework", "XSRF-TOKEN", 10, 75.0},
    {"Symfony", "Framework", "symfony", 7, 75.0},
    {"Express", "Framework", "Express", 7, 70.0},
    {"Flask", "Framework", "Flask", 5, 70.0},
    {"Spring Boot", "Framework", "Spring", 6, 65.0},
    {"ASP.NET", "Framework", "ASP.NET", 6, 70.0},
    {"nginx", "Server", "nginx", 5, 95.0},
    {"Apache", "Server", "Apache", 6, 95.0},
    {"IIS", "Server", "IIS", 3, 90.0},
    {"Tomcat", "Server", "Tomcat", 6, 85.0},
    {"Caddy", "Server", "Caddy", 5, 80.0},
    {"Lighttpd", "Server", "lighttpd", 8, 85.0},
    {"Node.js", "Runtime", "Node.js", 7, 70.0},
    {"PHP", "Runtime", "PHP", 3, 75.0},
    {"Python", "Runtime", "Python", 6, 65.0},
    {"Cloudflare", "CDN", "cloudflare", 10, 90.0},
    {"Akamai", "CDN", "Akamai", 6, 80.0},
    {"Varnish", "CDN", "Varnish", 7, 75.0},
    {"", "", "", 0, 0},
};

static const char *detect_paths[] = {
    "/", "/wp-admin/", "/wp-content/", "/wp-json/", "/sites/default/",
    "/media/system/", "/components/com_", "/skin/frontend/",
    "/admin/", "/login/", "/.env", "/robots.txt", "/sitemap.xml",
    "/api/", "/graphql", "/swagger/", "/docs/", "/phpinfo.php",
    "/server-status", "/.git/config", NULL
};

static WebAppResult results[MAX_PORTS];

static int http_fetch(const char *ip, int port, const char *path, char *response, int resplen, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
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
    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
             path, ip);
    send(fd, req, strlen(req), 0);
    struct epoll_event rev;
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    nfds = epoll_wait(epfd, &rev, 1, timeout_ms);
    int total = 0;
    if (nfds > 0 && (rev.events & EPOLLIN)) {
        total = recv(fd, response, resplen - 1, 0);
        if (total > 0) response[total] = 0;
    }
    close(epfd);
    close(fd);
    return total;
}

static void match_signatures(WebAppResult *r) {
    for (int s = 0; signatures[s].name[0]; s++) {
        if (strcasestr(r->banner, signatures[s].signature)) {
            if (r->match_count < MAX_SIGNATURES) {
                r->detected[r->match_count++] = signatures[s];
            }
        }
    }
}

static void extract_server_header(WebAppResult *r) {
    char *s = strstr(r->banner, "Server:");
    if (s) {
        s += 7;
        while (*s == ' ') s++;
        char *nl = strchr(s, '\r');
        if (!nl) nl = strchr(s, '\n');
        if (nl) { *nl = 0; }
        strncpy(r->server_header, s, sizeof(r->server_header) - 1);
    }
    char *x_powered = strstr(r->banner, "X-Powered-By:");
    if (x_powered) {
        x_powered += 13;
        while (*x_powered == ' ') x_powered++;
        char *nl = strchr(x_powered, '\r');
        if (!nl) nl = strchr(x_powered, '\n');
        if (nl) *nl = 0;
        if (r->technology[0]) strncat(r->technology, "; ", sizeof(r->technology) - strlen(r->technology) - 1);
        strncat(r->technology, x_powered, sizeof(r->technology) - strlen(r->technology) - 1);
    }
}

static void *scan_worker(void *arg) {
    int port_idx = *(int *)arg;
    free(arg);
    WebAppResult *r = &results[port_idx];
    char target[256];
    strncpy(target, r->banner, sizeof(target) - 1);
    r->match_count = 0;
    memset(r->detected, 0, sizeof(r->detected));
    for (int p = 0; detect_paths[p]; p++) {
        char resp[BANNER_LEN] = {0};
        int n = http_fetch(target, r->port, detect_paths[p], resp, BANNER_LEN, TIMEOUT_MS);
        if (n > 0) {
            strncat(r->banner, resp, BANNER_LEN - strlen(r->banner) - 1);
            r->banner[BANNER_LEN - 1] = 0;
            match_signatures(r);
            if (p == 0) extract_server_header(r);
        }
    }
    char matched[MAX_SIGNATURES * 64];
    matched[0] = 0;
    for (int i = 0; i < r->match_count; ++i) {
        if (matched[0]) strncat(matched, ", ", sizeof(matched) - strlen(matched) - 1);
        strncat(matched, r->detected[i].name, sizeof(matched) - strlen(matched) - 1);
        printf("RESULT:{\"port\":%d,\"match\":\"%s\",\"category\":\"%s\",\"confidence\":%.1f}\n",
               r->port, r->detected[i].name, r->detected[i].category, r->detected[i].confidence);
    }
    printf("RESULT:{\"port\":%d,\"server\":\"%s\",\"technology\":\"%s\",\"matches\":%d}\n",
           r->port, r->server_header, r->technology, r->match_count);
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
    int ports[MAX_PORTS] = {80, 8080, 443, 8443, 8000, 3000, 5000, 9000};
    int total = 8;
    if (ports_arg) {
        total = 0;
        char *dup = strdup(ports_arg);
        char *tok = strtok(dup, ",");
        while (tok && total < MAX_PORTS) ports[total++] = atoi(tok), tok = strtok(NULL, ",");
        free(dup);
    }
    memset(results, 0, sizeof(results));
    for (int i = 0; i < total; ++i) {
        results[i].port = ports[i];
        strncpy(results[i].banner, target, sizeof(results[i].banner) - 1);
    }
    pthread_t threads[MAX_PORTS];
    for (int i = 0; i < total; ++i) {
        int *idx = malloc(sizeof(int));
        *idx = i;
        pthread_create(&threads[i], NULL, scan_worker, idx);
    }
    for (int i = 0; i < total; ++i)
        pthread_join(threads[i], NULL);
    printf("FINAL:{\"target\":\"%s\",\"ports_scanned\":%d", target, total);
    for (int i = 0; i < total; ++i)
        printf(",\"port_%d_matches\":%d", results[i].port, results[i].match_count);
    printf("}\n");
    return 0;
}
// vim: ts=4 sw=4 et tw=80
