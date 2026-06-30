#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>

struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string sha256_fingerprint;
    std::string valid_from;
    std::string valid_to;
    std::vector<std::string> san_list;
    bool is_self_signed{false};
    int key_size{0};
    std::string signature_algo;
    std::string public_key_algo;
    int days_remaining{0};
};

struct TlsReport {
    std::string version;
    std::string cipher;
    std::vector<CertInfo> cert_chain;
    bool ocsp_stapling{false};
    std::vector<std::string> alpn_protos;
    std::vector<std::string> supported_groups;
    bool session_ticket{false};
    bool secure_renegotiation{false};
    bool heartbleed_vulnerable{false};
    bool cert_expired{false};
    bool cert_not_yet_valid{false};
    double handshake_ms{0.0};
    int tls_version_code{0};
};

class TlsDeepScanner {
public:
    TlsDeepScanner();
    ~TlsDeepScanner();

    TlsReport scan(const std::string &host, int port, int timeout_ms);
    bool is_tls_supported(const std::string &host, int port);
    std::vector<std::string> get_supported_ciphers(const std::string &host, int port);

    void set_sni(const std::string &sni);
    void set_ca_path(const std::string &path);
    void set_verify_peer(bool verify);
    void set_prefer_ipv6(bool prefer);

private:
    std::string sni_;
    std::string ca_path_;
    bool verify_peer_{false};
    bool prefer_ipv6_{false};

    int connect_socket(const std::string &host, int port, int timeout_ms);
    SSL_CTX* create_ctx();
    CertInfo extract_cert_info(X509* cert);
    std::vector<std::string> extract_san(X509* cert);
    std::string x509_time_to_string(const ASN1_TIME* time);
    bool test_cipher(SSL_CTX* ctx, int fd, const std::string &cipher_name, int timeout_ms);
    void check_heartbleed(int fd, int timeout_ms, bool &vulnerable);
};
