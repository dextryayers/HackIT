#define _GNU_SOURCE
#include "tls_deep_scan.h"
#include "optimize.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <chrono>
#include <thread>
#include <mutex>
#include <map>
#include <memory>
#include <functional>
#include <cmath>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

static std::mutex g_ssl_mutex;
static bool g_ssl_global_init = false;

static void ssl_global_init() {
    std::lock_guard<std::mutex> lock(g_ssl_mutex);
    if (!g_ssl_global_init) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        OpenSSL_add_all_algorithms();
        g_ssl_global_init = true;
    }
}

static std::string sha256_of_cert(X509* cert) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int len = 0;
    if (X509_digest(cert, EVP_sha256(), hash, &len) != 1) {
        return "";
    }
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < len; ++i) {
        out += hex[(hash[i] >> 4) & 0x0F];
        out += hex[hash[i] & 0x0F];
    }
    return out;
}

static std::string bio_to_string(BIO* bio) {
    if (!bio) return "";
    int len = BIO_pending(bio);
    if (len <= 0) return "";
    std::string out(len, '\0');
    BIO_read(bio, &out[0], len);
    return out;
}

static std::string get_x509_name(X509_NAME* name) {
    if (!name) return "";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    std::string result = bio_to_string(bio);
    BIO_free(bio);
    return result;
}

TlsDeepScanner::TlsDeepScanner() {
    ssl_global_init();
}

TlsDeepScanner::~TlsDeepScanner() {}

void TlsDeepScanner::set_sni(const std::string &sni) { sni_ = sni; }
void TlsDeepScanner::set_ca_path(const std::string &path) { ca_path_ = path; }
void TlsDeepScanner::set_verify_peer(bool verify) { verify_peer_ = verify; }
void TlsDeepScanner::set_prefer_ipv6(bool prefer) { prefer_ipv6_ = prefer; }

int TlsDeepScanner::connect_socket(const std::string &host, int port, int timeout_ms) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = prefer_ipv6_ ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        hints.ai_family = AF_UNSPEC;
        rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    }
    if (rc != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

        fcntl(fd, F_SETFL, O_NONBLOCK);

        rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }

        if (rc == 0) break;

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) {
            close(fd);
            fd = -1;
            continue;
        }

        int so_err = 0;
        socklen_t err_len = sizeof(so_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
        if (so_err != 0) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (fd >= 0) {
        fcntl(fd, F_SETFL, 0);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    return fd;
}

SSL_CTX* TlsDeepScanner::create_ctx() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return nullptr;

    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                             SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx, verify_peer_ ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);

    if (!ca_path_.empty()) {
        SSL_CTX_load_verify_locations(ctx, nullptr, ca_path_.c_str());
    }

    const char* cipher_list = "HIGH:!aNULL:!eNULL:!MD5:!RC4:!DES:!3DES:!PSK:!SRP";
    SSL_CTX_set_cipher_list(ctx, cipher_list);

    return ctx;
}

std::string TlsDeepScanner::x509_time_to_string(const ASN1_TIME* time) {
    if (!time) return "";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    ASN1_TIME_print(bio, time);
    std::string result = bio_to_string(bio);
    BIO_free(bio);
    return result;
}

std::vector<std::string> TlsDeepScanner::extract_san(X509* cert) {
    std::vector<std::string> sans;
    GENERAL_NAMES* names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (!names) return sans;

    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
        if (gn->type == GEN_DNS) {
            const char* dns = (const char*)ASN1_STRING_get0_data(gn->d.dNSName);
            if (dns) sans.emplace_back(dns);
        } else if (gn->type == GEN_IPADD) {
            const unsigned char* ip = ASN1_STRING_get0_data(gn->d.iPAddress);
            int iplen = ASN1_STRING_length(gn->d.iPAddress);
            char buf[INET6_ADDRSTRLEN] = {};
            if (iplen == 4) {
                inet_ntop(AF_INET, ip, buf, sizeof(buf));
            } else if (iplen == 16) {
                inet_ntop(AF_INET6, ip, buf, sizeof(buf));
            }
            if (buf[0]) sans.emplace_back(buf);
        }
    }
    GENERAL_NAMES_free(names);
    return sans;
}

CertInfo TlsDeepScanner::extract_cert_info(X509* cert) {
    CertInfo info;
    if (!cert) return info;

    info.subject = get_x509_name(X509_get_subject_name(cert));
    info.issuer = get_x509_name(X509_get_issuer_name(cert));

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio) {
        ASN1_INTEGER* serial = X509_get_serialNumber(cert);
        if (serial) {
            BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
            if (bn) {
                char* hex = BN_bn2hex(bn);
                if (hex) {
                    info.serial = hex;
                    OPENSSL_free(hex);
                }
                BN_free(bn);
            }
        }
        BIO_free(bio);
    }

    info.sha256_fingerprint = sha256_of_cert(cert);

    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (not_before) info.valid_from = x509_time_to_string(not_before);
    if (not_after) {
        info.valid_to = x509_time_to_string(not_after);

        int day, sec;
        if (ASN1_TIME_diff(&day, &sec, nullptr, not_after)) {
            info.days_remaining = day;
        }
    }

    info.san_list = extract_san(cert);

    if (X509_check_issued(cert, cert) == X509_V_OK) {
        info.is_self_signed = true;
    }

    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (pkey) {
        info.key_size = EVP_PKEY_bits(pkey);
        int algo = EVP_PKEY_id(pkey);
        switch (algo) {
            case EVP_PKEY_RSA: info.public_key_algo = "RSA"; break;
            case EVP_PKEY_DSA: info.public_key_algo = "DSA"; break;
            case EVP_PKEY_EC: info.public_key_algo = "EC"; break;
            case EVP_PKEY_ED25519: info.public_key_algo = "Ed25519"; break;
            default: info.public_key_algo = "Unknown"; break;
        }
    }

    int sig_nid = X509_get_signature_nid(cert);
    if (sig_nid != NID_undef) {
        const char* sn = OBJ_nid2sn(sig_nid);
        if (sn) info.signature_algo = sn;
    }

    return info;
}

bool TlsDeepScanner::test_cipher(SSL_CTX* ctx, int fd, const std::string &cipher_name, int timeout_ms) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) return false;

    SSL_set_fd(ssl, fd);
    if (!sni_.empty()) SSL_set_tlsext_host_name(ssl, sni_.c_str());

    if (SSL_set_cipher_list(ssl, cipher_name.c_str()) != 1) {
        SSL_free(ssl);
        return false;
    }

    int rc = SSL_connect(ssl);
    bool ok = (rc == 1);
    SSL_free(ssl);
    return ok;
}

void TlsDeepScanner::check_heartbleed(int fd, int timeout_ms, bool &vulnerable) {
    vulnerable = false;
    uint8_t hb[32];
    memset(hb, 0, sizeof(hb));
    hb[0] = 24;
    hb[1] = 15;
    hb[2] = 0;
    hb[3] = 8;
    memset(hb + 4, 0x01, 8);

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    if (poll(&pfd, 1, timeout_ms / 2) <= 0) return;

    send(fd, hb, 4 + 8, 0);

    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms / 2) <= 0) return;

    uint8_t buf[1024];
    int n = recv(fd, buf, sizeof(buf), 0);
    if (n > 4 + 8 + 4) {
        vulnerable = true;
    }
}

TlsReport TlsDeepScanner::scan(const std::string &host, int port, int timeout_ms) {
    TlsReport report;

    int fd = connect_socket(host, port, timeout_ms);
    if (fd < 0) return report;

    SSL_CTX* ctx = create_ctx();
    if (!ctx) { close(fd); return report; }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return report; }

    SSL_set_fd(ssl, fd);
    std::string sni = sni_.empty() ? host : sni_;
    SSL_set_tlsext_host_name(ssl, sni.c_str());

    auto start = std::chrono::steady_clock::now();
    int rc = SSL_connect(ssl);
    auto end = std::chrono::steady_clock::now();
    report.handshake_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count() / 1000.0;

    if (rc != 1) {
        ERR_clear_error();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return report;
    }

    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        report.cipher = SSL_CIPHER_get_name(cipher);
    }

    long ver = SSL_version(ssl);
    switch (ver) {
        case TLS1_VERSION: report.version = "TLSv1.0"; report.tls_version_code = 0x0301; break;
        case TLS1_1_VERSION: report.version = "TLSv1.1"; report.tls_version_code = 0x0302; break;
        case TLS1_2_VERSION: report.version = "TLSv1.2"; report.tls_version_code = 0x0303; break;
        case TLS1_3_VERSION: report.version = "TLSv1.3"; report.tls_version_code = 0x0304; break;
        default: report.version = "Unknown"; break;
    }

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        report.cert_chain.push_back(extract_cert_info(cert));
        X509_free(cert);

        STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
        if (chain) {
            for (int i = 0; i < sk_X509_num(chain); ++i) {
                X509* c = sk_X509_value(chain, i);
                if (c) {
                    report.cert_chain.push_back(extract_cert_info(c));
                }
            }
        }
    }

    const unsigned char* alpn_data = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_len);
    if (alpn_data && alpn_len > 0) {
        report.alpn_protos.emplace_back((const char*)alpn_data, alpn_len);
    }

    report.secure_renegotiation = (SSL_get_secure_renegotiation_support(ssl) == 1);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return report;
}

bool TlsDeepScanner::is_tls_supported(const std::string &host, int port) {
    TlsReport r = scan(host, port, 5000);
    return !r.cipher.empty();
}

std::vector<std::string> TlsDeepScanner::get_supported_ciphers(const std::string &host, int port) {
    std::vector<std::string> supported;

    int fd = connect_socket(host, port, 5000);
    if (fd < 0) return supported;

    SSL_CTX* ctx = create_ctx();
    if (!ctx) { close(fd); return supported; }

    const char* all_ciphers[] = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "DHE-RSA-AES256-SHA",
        "DHE-RSA-AES128-SHA",
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        nullptr
    };

    for (int i = 0; all_ciphers[i]; ++i) {
        if (test_cipher(ctx, fd, all_ciphers[i], 2000)) {
            supported.emplace_back(all_ciphers[i]);
        }
    }

    SSL_CTX_free(ctx);
    close(fd);
    return supported;
}
