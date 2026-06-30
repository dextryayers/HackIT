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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "optimize.h"

typedef struct {
    int status_code;
    char *server;
    char *powered_by;
    char *content_type;
    char *title;
    char *body_snippet;
    char *error;
} HttpResponse;

static pthread_mutex_t http_ssl_lock = PTHREAD_MUTEX_INITIALIZER;

static int http_connect(const char *host, int port, int timeout_ms) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        struct hostent *he = gethostbyname(host);
        if (!he || !he->h_addr_list[0]) return -1;
        memcpy(&addr.sin_addr, he->h_addr_list[0], 4);
    }

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return -1;

    int one = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    struct pollfd pf = {.fd = sock, .events = POLLOUT | POLLERR};
    int n = poll(&pf, 1, timeout_ms);
    if (n <= 0 || !(pf.revents & POLLOUT)) { close(sock); return -1; }

    int so_err = 0;
    socklen_t el = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
    if (so_err != 0) { close(sock); return -1; }

    int fl = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, fl & ~O_NONBLOCK);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return sock;
}

static int http_send_recv(int sock, const char *request, char *response, int resp_size, int timeout_ms) {
    memset(response, 0, resp_size);
    if (send(sock, request, (int)strlen(request), 0) < 0) return -1;

    int total = 0;
    long long deadline = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    deadline = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + timeout_ms;

    while (total < resp_size - 1) {
        struct pollfd pf = {.fd = sock, .events = POLLIN};
        int n = poll(&pf, 1, 100);
        if (n < 0) break;
        if (n == 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long long now_ms = (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
            if (now_ms >= deadline) break;
            continue;
        }
        int r = (int)read(sock, response + total, (size_t)(resp_size - 1 - total));
        if (r <= 0) break;
        total += r;
        if (strstr(response, "\r\n\r\n")) {
            if (total >= resp_size - 1 || r < 4096) break;
        }
    }
    response[total] = 0;
    return total;
}

static void extract_header_value(const char *headers, const char *header_name, char **out) {
    if (*out) return;
    const char *p = strstr(headers, header_name);
    if (!p) return;
    p += strlen(header_name);
    while (*p == ' ') p++;
    const char *end = strstr(p, "\r\n");
    size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len > 0 && len < 1024) {
        *out = strndup(p, len);
    }
}

static void extract_title(const char *body, char **out) {
    if (*out) return;
    const char *tstart = strstr(body, "<title");
    if (!tstart) {
        tstart = strstr(body, "<TITLE");
        if (!tstart) return;
    }
    tstart = strchr(tstart, '>');
    if (!tstart) return;
    tstart++;
    const char *tend = strstr(tstart, "</title");
    if (!tend) tend = strstr(tstart, "</TITLE");
    if (!tend) return;
    size_t len = (size_t)(tend - tstart);
    if (len > 0 && len < 512) {
        char *raw = strndup(tstart, len);
        if (raw) {
            int di = 0;
            for (size_t i = 0; raw[i]; i++) {
                if (raw[i] == '\r' || raw[i] == '\n') continue;
                raw[di++] = raw[i];
            }
            raw[di] = 0;
            *out = raw;
        }
    }
}

static HttpResponse *probe_common(const char *host, int port, int timeout_ms, int use_tls) {
    HttpResponse *resp = calloc(1, sizeof(HttpResponse));
    if (!resp) return NULL;
    resp->status_code = 0;
    resp->error = NULL;

    int sock = http_connect(host, port, timeout_ms);
    if (sock < 0) {
        resp->error = strdup("connection failed");
        return resp;
    }

    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    if (use_tls) {
        pthread_mutex_lock(&http_ssl_lock);
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
            SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        }
        pthread_mutex_unlock(&http_ssl_lock);
        if (!ctx) { close(sock); resp->error = strdup("SSL_CTX_new failed"); return resp; }

        ssl = SSL_new(ctx);
        if (!ssl) { SSL_CTX_free(ctx); close(sock); resp->error = strdup("SSL_new failed"); return resp; }

        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
            resp->error = strdup("SSL_connect failed");
            return resp;
        }
    }

    char request[2048];
    snprintf(request, sizeof(request),
        "GET / HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: HackIT-Prober/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n", host);

    char response[32768];
    int total;
    if (use_tls) {
        memset(response, 0, sizeof(response));
        SSL_write(ssl, request, (int)strlen(request));
        total = 0;
        long long deadline;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        deadline = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + timeout_ms;
        while (total < (int)sizeof(response) - 1) {
            struct pollfd pf = {.fd = sock, .events = POLLIN};
            int n = poll(&pf, 1, 100);
            if (n <= 0) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                long long now_ms = (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
                if (now_ms >= deadline) break;
                continue;
            }
            int r = SSL_read(ssl, response + total, (int)(sizeof(response) - 1 - (size_t)total));
            if (r <= 0) break;
            total += r;
        }
        response[total] = 0;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        total = http_send_recv(sock, request, response, sizeof(response), timeout_ms);
    }
    close(sock);
    if (total <= 0) { resp->error = strdup("empty response"); return resp; }

    char *headers = response;
    char *body = strstr(response, "\r\n\r\n");
    if (body) {
        *body = 0;
        body += 4;
    } else {
        body = "";
    }

    sscanf(headers, "HTTP/%*d.%*d %d", &resp->status_code);
    extract_header_value(headers, "Server: ", &resp->server);
    extract_header_value(headers, "X-Powered-By: ", &resp->powered_by);
    extract_header_value(headers, "Content-Type: ", &resp->content_type);
    extract_title(body, &resp->title);

    size_t blen = strlen(body);
    if (blen > 256) blen = 256;
    resp->body_snippet = strndup(body, blen);

    return resp;
}

HttpResponse *probe_http(const char *host, int port, int timeout_ms) {
    return probe_common(host, port, timeout_ms, 0);
}

HttpResponse *probe_https(const char *host, int port, int timeout_ms) {
    return probe_common(host, port, timeout_ms, 1);
}

void free_http_response(HttpResponse *resp) {
    if (!resp) return;
    free(resp->server);
    free(resp->powered_by);
    free(resp->content_type);
    free(resp->title);
    free(resp->body_snippet);
    free(resp->error);
    memset(resp, 0, sizeof(HttpResponse));
    free(resp);
}
