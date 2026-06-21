/* tls_prober.c — TLS/SSL Deep Probe
#define _GNU_SOURCE
 * Compile: gcc -O3 -o ../bin/tls_prober tls_prober.c -lpthread -lssl -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#include "optimize.h"

#define MAX_TARGETS 256
#define MAX_PORTS 65536

typedef struct { char host[256]; int port; int timeout; } job_t;
static job_t jobs[MAX_PORTS];
static int n_jobs = 0, idx = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static const char *tls_versions[] = {"tls1", "tls1.1", "tls1.2", "tls1.3"};

static job_t get_job() {
    pthread_mutex_lock(&mtx);
    job_t j = {.port = 0, .timeout = 3000};
    if (idx < n_jobs) j = jobs[idx++];
    pthread_mutex_unlock(&mtx);
    return j;
}

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void probe_tls(const char *host, int port, int timeout_ms) {
    long long start = now_ms();
    char result[4096] = {0};
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    struct hostent *he = gethostbyname(host);
    if (!he) { close(sock); return; }
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return; }
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(sock); return; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(sock); return; }
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);
    int ret = SSL_connect(ssl);
    if (ret == 1) {
        snprintf(result, sizeof(result), "%s", SSL_get_cipher(ssl));
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            char cn[256] = {0};
            X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn));
            char issuer[256] = {0};
            X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_commonName, issuer, sizeof(issuer));
            char tmp[1024];
            snprintf(tmp, sizeof(tmp), " | CN=%s Issuer=%s", cn, issuer);
            strncat(result, tmp, sizeof(result) - strlen(result) - 1);
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    if (strlen(result) > 0) {
        long long elapsed = now_ms() - start;
        printf("RESULT:{\"port\":%d,\"status\":\"open\",\"protocol\":\"tcp\",\"service\":\"TLS\","
               "\"version\":\"%s\",\"response_time_ms\":%lld}\n", port, result, elapsed);
        fflush(stdout);
    }
}

static void *worker(void *arg) {
    (void)arg;
    job_t j;
    while ((j = get_job()).port > 0) probe_tls(j.host, j.port, j.timeout);
    return NULL;
}

int main(int argc, char **argv) {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    char target[256] = {0}; char ports_str[4096] = {0}; int timeout = 3000, workers = 10;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) strncpy(target, argv[++i], sizeof(target) - 1);
        else if (!strcmp(argv[i], "--ports") && i + 1 < argc) strncpy(ports_str, argv[++i], sizeof(ports_str) - 1);
        else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--workers") && i + 1 < argc) workers = atoi(argv[++i]);
    }
    if (!target[0]) { fprintf(stderr, "Usage: %s --target <host> --ports <ports>\n", argv[0]); return 1; }
    int ports[MAX_PORTS], n_ports = 0;
    if (strchr(ports_str, '-')) {
        int a, b; sscanf(ports_str, "%d-%d", &a, &b);
        for (int i = a; i <= b && n_ports < MAX_PORTS; i++) ports[n_ports++] = i;
    } else {
        char *tok = strtok(ports_str, ",");
        while (tok && n_ports < MAX_PORTS) { ports[n_ports++] = atoi(tok); tok = strtok(NULL, ","); }
    }
    for (int i = 0; i < n_ports && n_jobs < MAX_PORTS; ++i) {
        snprintf(jobs[n_jobs].host, sizeof(jobs[n_jobs].host), "%s", target);
        jobs[n_jobs].port = ports[i]; jobs[n_jobs].timeout = timeout; n_jobs++;
    }
    pthread_t th[256];
    for (int i = 0; i < workers && i < 256; ++i) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < workers && i < 256; ++i) pthread_join(th[i], NULL);
    printf("FINAL:{\"target\":\"%s\",\"total\":%d,\"module\":\"tls_prober\"}\n", target, n_jobs);
    fflush(stdout);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
