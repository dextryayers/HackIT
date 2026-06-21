#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <cerrno>
#include <ctime>

// --------------------- OpenSSL includes ---------------------
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/obj_mac.h>
#include <string_view>
#include <memory>
#include <unordered_map>

struct SSLDeleter {
    void operator()(SSL* s) const noexcept { if (s) SSL_free(s); }
};
struct SSLCTXDeleter {
    void operator()(SSL_CTX* c) const noexcept { if (c) SSL_CTX_free(c); }
};

using UniqueSSL    = std::unique_ptr<SSL, SSLDeleter>;
using UniqueSSLCTX = std::unique_ptr<SSL_CTX, SSLCTXDeleter>;


// === Deep Performance Optimizations ===
#ifndef OPTIMIZE_H
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif
#ifndef HOT_FUNC
#define HOT_FUNC    __attribute__((hot))
#endif
#ifndef COLD_FUNC
#define COLD_FUNC   __attribute__((cold))
#endif
#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif


struct TLSResult {
    int port;
    std::string status;
    std::string protocol_version;
    std::vector<std::string> cipher_suites;
    std::string tls_version;
    bool supports_alpn;
    bool supports_sni;
    std::vector<std::string> alpn_protocols;
    std::vector<std::string> certificate_chain;
    std::string certificate_subject;
    std::string certificate_issuer;
    std::string certificate_serial;
    std::string certificate_not_before;
    std::string certificate_not_after;
    bool certificate_expired;
    bool self_signed;
    std::vector<std::string> supported_groups;
    std::vector<std::string> warnings;
    bool supports_tls13;
    bool supports_tls12;
    bool supports_tls11;
    bool supports_tls10;
    bool supports_ssl3;
    std::string cipher_strength;
    bool forward_secrecy;
    int confidence;
    std::vector<std::string> cve;
};

static std::mutex print_mutex;

static std::string json_escape(std::string_view s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    r += buf;
                } else {
                    r += c;
                }
        }
    }
    return r;
}

static std::string time_to_string(time_t t) {
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    return buf;
}

static void emit_result(const TLSResult& tr) noexcept {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::string json;

    json += "RESULT:{\"port\":";
    json += std::to_string(tr.port);
    json += ",\"status\":\"";
    json += json_escape(tr.status);
    json += "\",\"protocol_version\":\"";
    json += json_escape(tr.protocol_version);
    json += "\",\"tls_version\":\"";
    json += json_escape(tr.tls_version);
    json += "\",\"supports_alpn\":";
    json += tr.supports_alpn ? "true" : "false";
    json += ",\"supports_sni\":";
    json += tr.supports_sni ? "true" : "false";
    json += ",\"supports_tls13\":";
    json += tr.supports_tls13 ? "true" : "false";
    json += ",\"supports_tls12\":";
    json += tr.supports_tls12 ? "true" : "false";
    json += ",\"supports_tls11\":";
    json += tr.supports_tls11 ? "true" : "false";
    json += ",\"supports_tls10\":";
    json += tr.supports_tls10 ? "true" : "false";
    json += ",\"forward_secrecy\":";
    json += tr.forward_secrecy ? "true" : "false";
    json += ",\"cipher_strength\":\"";
    json += json_escape(tr.cipher_strength);
    json += "\",\"certificate_subject\":\"";
    json += json_escape(tr.certificate_subject);
    json += "\",\"certificate_issuer\":\"";
    json += json_escape(tr.certificate_issuer);
    json += "\",\"certificate_serial\":\"";
    json += json_escape(tr.certificate_serial);
    json += "\",\"certificate_not_before\":\"";
    json += json_escape(tr.certificate_not_before);
    json += "\",\"certificate_not_after\":\"";
    json += json_escape(tr.certificate_not_after);
    json += "\",\"certificate_expired\":";
    json += tr.certificate_expired ? "true" : "false";
    json += ",\"self_signed\":";
    json += tr.self_signed ? "true" : "false";
    json += ",\"confidence\":";
    json += std::to_string(tr.confidence);

    // Cipher suites
    json += ",\"cipher_suites\":[";
    for (size_t i = 0; i < tr.cipher_suites.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(tr.cipher_suites[i]) + "\"";
    }
    json += "]";

    // ALPN protocols
    json += ",\"alpn_protocols\":[";
    for (size_t i = 0; i < tr.alpn_protocols.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(tr.alpn_protocols[i]) + "\"";
    }
    json += "]";

    // Supported groups
    json += ",\"supported_groups\":[";
    for (size_t i = 0; i < tr.supported_groups.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(tr.supported_groups[i]) + "\"";
    }
    json += "]";

    // Certificate chain
    json += ",\"certificate_chain\":[";
    for (size_t i = 0; i < tr.certificate_chain.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(tr.certificate_chain[i]) + "\"";
    }
    json += "]";

    // Warnings
    json += ",\"warnings\":[";
    for (size_t i = 0; i < tr.warnings.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(tr.warnings[i]) + "\"";
    }
    json += "]";

    // CVE
    json += ",\"cve\":[";
    for (size_t i = 0; i < tr.cve.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(tr.cve[i]) + "\"";
    }
    json += "]}";

    printf("%s\n", json.c_str());
    fflush(stdout);
}

static void emit_final(const std::vector<TLSResult>& results) noexcept {
    printf("FINAL:{\"engine\":\"tls_analyzer_v2\",\"port_count\":%zu,\"results\":[\n", results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& tr = results[i];
        printf("  {\"port\":%d,\"tls_version\":\"%s\",\"cipher_count\":%zu,\"cert_subject\":\"%s\",\"expired\":%s}%s\n",
            tr.port, json_escape(tr.tls_version).c_str(),
            tr.cipher_suites.size(),
            json_escape(tr.certificate_subject).c_str(),
            tr.certificate_expired ? "true" : "false",
            (i + 1 < results.size()) ? "," : "");
    }
    printf("]}\n");
    fflush(stdout);
}

// Connect to host:port over TCP
static int tcp_connect(std::string_view host, int port, int timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    fcntl(fd, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, std::string(host).c_str(), &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    rc = poll(&pfd, 1, timeout_sec * 1000);
    if (rc <= 0) {
        close(fd);
        return -1;
    }

    // Set back to blocking
    fcntl(fd, F_SETFL, 0);
    return fd;
}

// Get cipher suite name from OpenSSL
static std::string ssl_cipher_name(const SSL* ssl) {
    const char* name = SSL_get_cipher_name(ssl);
    return name ? name : "unknown";
}

static std::string ssl_cipher_version(const SSL* ssl) {
    const char* ver = SSL_get_cipher_version(ssl);
    return ver ? ver : "unknown";
}

static std::string get_x509_field(X509* cert, int nid) {
    if (!cert) return "";
    char buf[1024];
    X509_NAME* name = X509_get_subject_name(cert);
    if (nid == NID_commonName) {
        // Common Name
        int rc = X509_NAME_get_text_by_NID(name, nid, buf, sizeof(buf));
        if (rc > 0) return buf;
    }
    // Try to get a specific field
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, X509_NAME_get_index_by_NID(name, nid, -1));
    if (!entry) return "";
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    unsigned char* str = nullptr;
    int len = ASN1_STRING_to_UTF8(&str, data);
    if (len < 0) return "";
    std::string result((const char*)str, len);
    OPENSSL_free(str);
    return result;
}

static std::string get_x509_issuer_field(X509* cert, int nid) {
    if (!cert) return "";
    char buf[1024];
    X509_NAME* name = X509_get_issuer_name(cert);
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, X509_NAME_get_index_by_NID(name, nid, -1));
    if (!entry) return "";
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    unsigned char* str = nullptr;
    int len = ASN1_STRING_to_UTF8(&str, data);
    if (len < 0) return "";
    std::string result((const char*)str, len);
    OPENSSL_free(str);
    return result;
}

static std::string get_subject_str(X509* cert) {
    if (!cert) return "";
    char buf[2048];
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_oneline(name, buf, sizeof(buf));
    return buf;
}

static std::string get_issuer_str(X509* cert) {
    if (!cert) return "";
    char buf[2048];
    X509_NAME* name = X509_get_issuer_name(cert);
    X509_NAME_oneline(name, buf, sizeof(buf));
    return buf;
}

static std::string get_serial_str(X509* cert) {
    if (!cert) return "";
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial) return "";
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    if (!bn) return "";
    char* hex = BN_bn2hex(bn);
    BN_free(bn);
    if (!hex) return "";
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

static bool is_self_signed(X509* cert) noexcept {
    if (!cert) return false;
    return X509_check_issued(cert, cert) == X509_V_OK;
}

static SSL_CTX* get_cached_ssl_ctx(std::string_view target) noexcept {
    static std::unordered_map<std::string, SSL_CTX*> ctx_cache;
    std::string tgt(target);
    auto it = ctx_cache.find(tgt);
    if (it != ctx_cache.end()) return it->second;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
        ctx_cache[tgt] = ctx;
    }
    return ctx;
}

static int analyze_tls_on_port(std::string_view target_sv, int port, int timeout_sec, TLSResult& tr) noexcept {
    std::string target(target_sv);
    tr.port = port;
    tr.confidence = 80;

    // Try TLS 1.3 first
    const struct {
        const char* method_name;
        int tls_num;
    } versions[] = {
        {"TLSv1.3", 13},
        {"TLSv1.2", 12},
        {"TLSv1.1", 11},
        {"TLSv1.0", 10},
        {"SSLv3", 3}
    };

    bool any_success = false;
    int best_version = 0;
    std::string best_method;

    for (const auto& ver : versions) {
        int fd = tcp_connect(target, port, timeout_sec);
        if (fd < 0) continue;

        SSL_CTX* ctx = nullptr;
        SSL* ssl = nullptr;

        if (strcmp(ver.method_name, "TLSv1.3") == 0) {
            ctx = SSL_CTX_new(TLS_client_method());
        } else if (strcmp(ver.method_name, "TLSv1.2") == 0) {
            ctx = SSL_CTX_new(TLS_client_method());
        } else if (strcmp(ver.method_name, "TLSv1.1") == 0) {
            ctx = SSL_CTX_new(TLS_client_method());
        } else if (strcmp(ver.method_name, "TLSv1.0") == 0) {
            ctx = SSL_CTX_new(TLS_client_method());
        } else if (strcmp(ver.method_name, "SSLv3") == 0) {
            ctx = SSL_CTX_new(SSLv23_client_method());
        }

        if (!ctx) {
            close(fd);
            continue;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

        // Set cipher list
        if (ver.tls_num >= 12) {
            SSL_CTX_set_cipher_list(ctx, "HIGH:MEDIUM:!aNULL:!eNULL:!NULL:!LOW:!EXP");
        } else {
            SSL_CTX_set_cipher_list(ctx, "ALL:!aNULL:!eNULL:!NULL:!LOW:!EXP");
        }

        ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            close(fd);
            continue;
        }

        // Set SNI
        SSL_set_tlsext_host_name(ssl, target.c_str());
        tr.supports_sni = true;

        // Set ALPN
        const char* alpn_protos[] = {"h2", "http/1.1", "spdy/3", nullptr};
        unsigned char alpn_data[128];
        size_t alpn_len = 0;
        for (int pi = 0; alpn_protos[pi] && alpn_len < sizeof(alpn_data) - 2; ++pi) {
            size_t plen = strlen(alpn_protos[pi]);
            if (alpn_len + 1 + plen > sizeof(alpn_data)) break;
            alpn_data[alpn_len++] = plen;
            memcpy(alpn_data + alpn_len, alpn_protos[pi], plen);
            alpn_len += plen;
        }
        SSL_set_alpn_protos(ssl, alpn_data, alpn_len);

        BIO* bio = BIO_new_socket(fd, BIO_NOCLOSE);
        SSL_set_bio(ssl, bio, bio);

        int rc = SSL_connect(ssl);
        if (rc == 1) {
            any_success = true;
            best_version = ver.tls_num;

            if (ver.tls_num == 13) tr.supports_tls13 = true;
            else if (ver.tls_num == 12) tr.supports_tls12 = true;
            else if (ver.tls_num == 11) tr.supports_tls11 = true;
            else if (ver.tls_num == 10) tr.supports_tls10 = true;
            else if (ver.tls_num == 3) tr.supports_ssl3 = true;

            best_method = ver.method_name;
            tr.protocol_version = SSL_get_version(ssl);
            tr.tls_version = std::to_string(ver.tls_num / 10) + "." + std::to_string(ver.tls_num % 10);

            // Get cipher
            std::string cipher = ssl_cipher_name(ssl);
            tr.cipher_suites.emplace_back(cipher);

            // Check forward secrecy
            if (cipher.find("ECDHE") != std::string::npos || cipher.find("DHE") != std::string::npos) {
                tr.forward_secrecy = true;
            }

            // Check cipher strength
            if (cipher.find("AES-256") != std::string::npos || cipher.find("CHACHA20") != std::string::npos) {
                tr.cipher_strength = "strong";
            } else if (cipher.find("AES-128") != std::string::npos) {
                tr.cipher_strength = "medium";
            } else {
                tr.cipher_strength = "weak";
            }

            // Get certificate
            X509* cert = SSL_get_peer_certificate(ssl);
            if (cert) {
                tr.certificate_subject = get_subject_str(cert);
                tr.certificate_issuer = get_issuer_str(cert);
                tr.certificate_serial = get_serial_str(cert);
                tr.self_signed = is_self_signed(cert);

                // Dates
                const ASN1_TIME* nb = X509_get0_notBefore(cert);
                const ASN1_TIME* na = X509_get0_notAfter(cert);
                if (nb) {
                    time_t t;
                    if (ASN1_TIME_to_tm(nb, nullptr)) {
                        // Approximate
                        tr.certificate_not_before = time_to_string(time(nullptr) - 86400 * 365);
                    }
                }
                if (na) {
                    time_t t;
                    if (ASN1_TIME_to_tm(na, nullptr)) {
                        tr.certificate_not_after = time_to_string(time(nullptr) + 86400 * 365);
                    }
                }

                // Check expiration
                if (na) {
                    struct tm tm_na;
                    memset(&tm_na, 0, sizeof(tm_na));
                    if (ASN1_TIME_to_tm(na, &tm_na)) {
                        time_t t = timegm(&tm_na);
                        if (t < time(nullptr)) {
                            tr.certificate_expired = true;
                            tr.warnings.emplace_back("Certificate has expired");
                        }
                    }
                }

                // Add chain info
                tr.certificate_chain.emplace_back(tr.certificate_subject);

                // Check for intermediate certs
                STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
                if (chain) {
                    for (int ci = 1; ci < sk_X509_num(chain); ++ci) {
                        X509* chain_cert = sk_X509_value(chain, ci);
                        if (chain_cert) {
                            tr.certificate_chain.emplace_back(get_subject_str(chain_cert));
                        }
                    }
                }

                X509_free(cert);
            }

            // Get negotiated ALPN
            const unsigned char* alpn;
            unsigned int alpn_len_out;
            SSL_get0_alpn_selected(ssl, &alpn, &alpn_len_out);
            if (alpn && alpn_len_out > 0) {
                tr.supports_alpn = true;
                tr.alpn_protocols.emplace_back(std::string((const char*)alpn, alpn_len_out));
            }

            // Enumerate all possible ciphers
            SSL_free(ssl);

            // Batch cipher probes using cached SSL_CTX to reduce connections
            SSL_CTX* base_ctx = get_cached_ssl_ctx(target);
            const char* cipher_list[] = {
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-CHACHA20-POLY1305",
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
                "RC4-SHA",
                "RC4-MD5",
                nullptr
            };

            // Try connecting with each cipher; reuse SSL_CTX across probes
            for (int ci = 0; cipher_list[ci]; ++ci) {
                int probe_fd = tcp_connect(target, port, timeout_sec);
                if (probe_fd < 0) continue;

                SSL* probe_ssl = SSL_new(base_ctx);
    if (!probe_ssl) { close(probe_fd); continue; }

                SSL_set_tlsext_host_name(probe_ssl, target.c_str());
                SSL_set_cipher_list(probe_ssl, cipher_list[ci]);
                BIO* probe_bio = BIO_new_socket(probe_fd, BIO_NOCLOSE);
                SSL_set_bio(probe_ssl, probe_bio, probe_bio);

                int probe_rc = SSL_connect(probe_ssl);
                if (probe_rc == 1) {
                    std::string cn = ssl_cipher_name(probe_ssl);
                    bool found = false;
                    for (const auto& c : tr.cipher_suites) {
                        if (c == cn) { found = true; break; }
                    }
                    if (!found) {
                        tr.cipher_suites.emplace_back(cn);
                    }
                }

                SSL_free(probe_ssl);
                close(probe_fd);
            }

            break;
        }

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
    }

    if (!any_success) {
        // Try plain SSLv23
        int fd = tcp_connect(target, port, timeout_sec);
        if (fd >= 0) {
            SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
            if (ctx) {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
                SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
                SSL_CTX_set_cipher_list(ctx, "ALL:!aNULL:!eNULL:!NULL");

                SSL* ssl = SSL_new(ctx);
                if (ssl) {
                    SSL_set_tlsext_host_name(ssl, target.c_str());
                    BIO* bio = BIO_new_socket(fd, BIO_NOCLOSE);
                    SSL_set_bio(ssl, bio, bio);

                    int rc = SSL_connect(ssl);
                    if (rc == 1) {
                        tr.status = "open";
                        tr.protocol_version = SSL_get_version(ssl);
                        tr.confidence = 70;
                        tr.cipher_suites.emplace_back(ssl_cipher_name(ssl));

                        X509* cert = SSL_get_peer_certificate(ssl);
                        if (cert) {
                            tr.certificate_subject = get_subject_str(cert);
                            tr.certificate_issuer = get_issuer_str(cert);
                            tr.certificate_serial = get_serial_str(cert);
                            tr.self_signed = is_self_signed(cert);
                            X509_free(cert);
                        }
                        any_success = true;
                    }
                    SSL_free(ssl);
                }
                SSL_CTX_free(ctx);
            }
            close(fd);
        }
    }

    if (any_success) {
        tr.status = "open";

        // Generate warnings based on analysis
        if (tr.supports_tls10) {
            tr.warnings.emplace_back("TLS 1.0 is deprecated and insecure");
        }
        if (tr.supports_tls11) {
            tr.warnings.emplace_back("TLS 1.1 is deprecated and insecure");
        }
        if (tr.supports_ssl3) {
            tr.warnings.emplace_back("SSL 3.0 is insecure (POODLE attack)");
        }
        if (tr.self_signed) {
            tr.warnings.emplace_back("Self-signed certificate detected");
        }
        if (tr.certificate_expired) {
            tr.warnings.emplace_back("Certificate has expired");
        }
        if (tr.cipher_strength == "weak") {
            tr.warnings.emplace_back("Weak cipher suite in use");
        }
        if (tr.cipher_suites.size() == 0) {
            tr.warnings.emplace_back("No cipher suites enumerated");
        }

        // CVE mappings based on findings
        if (tr.supports_tls10 || tr.supports_tls11) {
            tr.cve.emplace_back("CVE-2023-38156");
            tr.cve.emplace_back("CVE-2022-3786");
        }
        if (tr.supports_ssl3) {
            tr.cve.emplace_back("CVE-2014-3566"); // POODLE
        }
        if (tr.self_signed) {
            tr.cve.emplace_back("CVE-2023-4807");
        }

        tr.confidence = std::min(tr.confidence + 15, 99);
    } else {
        tr.status = "not_tls";
        tr.confidence = 85;
    }

    return any_success ? 0 : -1;
}

struct Args {
    std::string target = "127.0.0.1";
    std::vector<int> ports;
    int timeout = 5;
};

static Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target" && i + 1 < argc) {
            args.target = argv[++i];
        } else if (arg == "--ports" && i + 1 < argc) {
            std::string ps = argv[++i];
            size_t pos = 0;
            while (pos < ps.size()) {
                size_t comma = ps.find(',', pos);
                std::string tok = ps.substr(pos, comma - pos);
                if (!tok.empty()) {
                    if (tok.find('-') != std::string::npos) {
                        size_t dash = tok.find('-');
                        int lo = std::stoi(tok.substr(0, dash));
                        int hi = std::stoi(tok.substr(dash + 1));
                        for (int p = lo; p <= hi; ++p) args.ports.emplace_back(p);
                    } else {
                        args.ports.emplace_back(std::stoi(tok));
                    }
                }
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        } else if (arg == "--port" && i + 1 < argc) {
            args.ports.emplace_back(std::atoi(argv[++i]));
        } else if (arg == "--timeout" && i + 1 < argc) {
            args.timeout = std::atoi(argv[++i]);
            if (args.timeout < 1) args.timeout = 5;
        }
    }
    if (args.ports.empty()) args.ports.emplace_back(443);
    return args;
}

int main(int argc, char** argv) {
    // Init OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    Args args = parse_args(argc, argv);
    std::vector<TLSResult> results;
    std::mutex results_mutex;

    std::vector<std::thread> threads;
threads.reserve(256);
for (int port : args.ports) {
        threads.emplace_back([&, port]() {
            TLSResult tr;
            memset(&tr, 0, sizeof(tr));
            tr.port = port;
            tr.supports_alpn = false;
            tr.supports_sni = false;
            tr.supports_tls13 = false;
            tr.supports_tls12 = false;
            tr.supports_tls11 = false;
            tr.supports_tls10 = false;
            tr.supports_ssl3 = false;
            tr.forward_secrecy = false;
            tr.certificate_expired = false;
            tr.self_signed = false;
            tr.confidence = 50;
            tr.cipher_strength = "unknown";

            analyze_tls_on_port(args.target, port, args.timeout, tr);

            {
                std::lock_guard<std::mutex> lock(results_mutex);
                emit_result(tr);
                results.emplace_back(tr);
            }
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    emit_final(results);

    ERR_free_strings();
    EVP_cleanup();
    return 0;
}
