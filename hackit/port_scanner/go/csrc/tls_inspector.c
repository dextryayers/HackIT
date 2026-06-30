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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include "optimize.h"

typedef struct {
    char *tls_version;
    char *cipher;
    char *subject;
    char *issuer;
    char *valid_from;
    char *valid_to;
    int san_count;
    char **san_list;
    int is_self_signed;
} TlsInfo;

static pthread_mutex_t ssl_lock = PTHREAD_MUTEX_INITIALIZER;

static int tcp_connect(const char *host, int port, int timeout_ms) {
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

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

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
    return sock;
}

static char *get_x509_time_str(const ASN1_TIME *tm) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return strdup("unknown");
    ASN1_TIME_print(bio, tm);
    long len = BIO_get_mem_data(bio, NULL);
    char *str = calloc(1, (size_t)len + 1);
    if (str) BIO_read(bio, str, (int)len);
    BIO_free(bio);
    return str;
}

TlsInfo *inspect_tls(const char *host, int port, int timeout_ms) {
    TlsInfo *info = calloc(1, sizeof(TlsInfo));
    if (!info) return NULL;

    int sock = tcp_connect(host, port, timeout_ms);
    if (sock < 0) { free(info); return NULL; }

    pthread_mutex_lock(&ssl_lock);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        pthread_mutex_unlock(&ssl_lock);
        close(sock); free(info); return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    pthread_mutex_unlock(&ssl_lock);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(sock); free(info); return NULL; }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);

    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(sock);
        free(info); return NULL;
    }

    info->tls_version = strdup(SSL_get_version(ssl));
    info->cipher = strdup(SSL_get_cipher(ssl));

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        X509_NAME *subj = X509_get_subject_name(cert);
        X509_NAME *iss = X509_get_issuer_name(cert);

        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            X509_NAME_print_ex(bio, subj, 0, XN_FLAG_RFC2253);
            long len = BIO_get_mem_data(bio, NULL);
            info->subject = calloc(1, (size_t)len + 1);
            if (info->subject) BIO_read(bio, info->subject, (int)len);
            BIO_free(bio);
        }
        if (!info->subject) info->subject = strdup("unknown");

        bio = BIO_new(BIO_s_mem());
        if (bio) {
            X509_NAME_print_ex(bio, iss, 0, XN_FLAG_RFC2253);
            long len = BIO_get_mem_data(bio, NULL);
            info->issuer = calloc(1, (size_t)len + 1);
            if (info->issuer) BIO_read(bio, info->issuer, (int)len);
            BIO_free(bio);
        }
        if (!info->issuer) info->issuer = strdup("unknown");

        const ASN1_TIME *not_before = X509_get_notBefore(cert);
        const ASN1_TIME *not_after = X509_get_notAfter(cert);
        info->valid_from = not_before ? get_x509_time_str(not_before) : strdup("unknown");
        info->valid_to = not_after ? get_x509_time_str(not_after) : strdup("unknown");

        int cmp = X509_NAME_cmp(subj, iss);
        info->is_self_signed = (cmp == 0) ? 1 : 0;

        GENERAL_NAMES *sans = (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
        if (sans) {
            int num = sk_GENERAL_NAME_num(sans);
            info->san_count = 0;
            info->san_list = calloc(num, sizeof(char *));
            for (int i = 0; i < num; i++) {
                GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
                if (gn->type == GEN_DNS) {
                    const char *dns = (const char *)ASN1_STRING_get0_data(gn->d.dNSName);
                    if (dns) info->san_list[info->san_count++] = strdup(dns);
                } else if (gn->type == GEN_IPADD) {
                    ASN1_OCTET_STRING *oct = gn->d.iPAddress;
                    if (oct && oct->length == 4) {
                        struct in_addr a;
                        memcpy(&a, oct->data, 4);
                        info->san_list[info->san_count++] = strdup(inet_ntoa(a));
                    }
                }
            }
            GENERAL_NAMES_free(sans);
        }
        X509_free(cert);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);

    if (!info->tls_version) info->tls_version = strdup("unknown");
    if (!info->cipher) info->cipher = strdup("unknown");
    return info;
}

void free_tls_info(TlsInfo *info) {
    if (!info) return;
    free(info->tls_version);
    free(info->cipher);
    free(info->subject);
    free(info->issuer);
    free(info->valid_from);
    free(info->valid_to);
    if (info->san_list) {
        for (int i = 0; i < info->san_count; i++) free(info->san_list[i]);
        free(info->san_list);
    }
    memset(info, 0, sizeof(TlsInfo));
    free(info);
}
