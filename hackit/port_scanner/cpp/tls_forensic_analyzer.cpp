#include "optimize.h"

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <cerrno>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <mutex>
#include <map>
#include <set>
#include <array>
#include <chrono>
#include <atomic>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#ifdef __linux__
#include <netinet/tcp.h>
#include <string_view>
#include <random>
#include <memory>
#include <unordered_map>
#endif

static std::mutex g_print_mutex;

static constexpr int CONNECT_TIMEOUT_MS = 5000;

HOT_FUNC static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(len * 2);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out += hex[(data[i] >> 4) & 0x0f];
        out += hex[data[i] & 0x0f];
    }
    return out;
}

struct Ja3sData {
    std::string version_str;
    std::string cipher_str;
    std::string ext_str;
    std::string curve_str;
    std::string fmt_str;
    std::string fingerprint;

    std::string compute() {
        std::string raw = version_str + "," + cipher_str + "," + ext_str + "," + curve_str + "," + fmt_str;
        unsigned char md5[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), md5);
        fingerprint = bytes_to_hex(md5, MD5_DIGEST_LENGTH);
        return fingerprint;
    }
};

struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string not_before;
    std::string not_after;
    int days_remaining{0};
    bool expired{false};
    bool self_signed{false};
    std::vector<std::string> san_dns;
    std::vector<std::string> san_ip;
    std::string sig_algo;
    std::string key_type;
    int key_bits{0};
    std::string sha256_fingerprint;
    std::string pem;
};

struct TlsForensicResult {
    std::string target;
    int port{0};
    bool connected{false};
    std::string tls_version;
    std::string cipher_suite;
    uint16_t cipher_id{0};
    Ja3sData ja3s;
    std::vector<CertInfo> chain;
    std::string alpn;
    std::string sni;
    std::string error;
};

static std::string x509_name_to_string(X509_NAME* name) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE);
    char buf[1024];
    int len = BIO_read(bio, buf, static_cast<int>(sizeof(buf) - 1));
    buf[std::max(0, len)] = 0;
    std::string r(buf);
    BIO_free(bio);
    return r;
}

static std::string time_to_string(const ASN1_TIME* t) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    ASN1_TIME_print(bio, t);
    char buf[128];
    int len = BIO_read(bio, buf, static_cast<int>(sizeof(buf) - 1));
    buf[std::max(0, len)] = 0;
    std::string r(buf);
    BIO_free(bio);
    return r;
}

static std::string compute_sha256(X509* cert) {
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (LIKELY(X509_digest(cert, EVP_sha256(), buf, &len))) {
        return bytes_to_hex(buf, len);
    }
    return "";
}

static CertInfo extract_cert_info(X509* cert) {
    CertInfo info;

    info.subject = x509_name_to_string(X509_get_subject_name(cert));
    info.issuer = x509_name_to_string(X509_get_issuer_name(cert));

    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
        if (bn) {
            char* hex = BN_bn2hex(bn);
            info.serial = hex ? hex : "";
            OPENSSL_free(hex);
            BN_free(bn);
        }
    }

    const ASN1_TIME* nb = X509_get0_notBefore(cert);
    const ASN1_TIME* na = X509_get0_notAfter(cert);
    if (nb) info.not_before = time_to_string(nb);
    if (na) info.not_after = time_to_string(na);

    if (na) {
        struct tm tm = {};
        const char* fmt = nullptr;
        if (na->type == V_ASN1_UTCTIME) fmt = "%y%m%d%H%M%S";
        else if (na->type == V_ASN1_GENERALIZEDTIME) fmt = "%Y%m%d%H%M%S";
        if (fmt) {
            strptime(reinterpret_cast<const char*>(na->data), fmt, &tm);
            time_t expiry = timegm(&tm);
            time_t now_t = time(nullptr);
            double diff = difftime(expiry, now_t);
            info.days_remaining = static_cast<int>(diff / 86400.0);
            info.expired = diff < 0;
        }
    }

    info.self_signed = (X509_name_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0);

    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names) {
        int n = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < n; ++i) {
            GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
            if (gn->type == GEN_DNS) {
                info.san_dns.emplace_back(
                    reinterpret_cast<const char*>(ASN1_STRING_get0_data(gn->d.dNSName)),
                    static_cast<size_t>(ASN1_STRING_length(gn->d.dNSName)));
            } else if (gn->type == GEN_IPADD) {
                const unsigned char* d = ASN1_STRING_get0_data(gn->d.iPAddress);
                int l = ASN1_STRING_length(gn->d.iPAddress);
                if (l == 4) {
                    char ip[INET6_ADDRSTRLEN];
                    std::snprintf(ip, sizeof(ip), "%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
                    info.san_ip.emplace_back(ip);
                } else if (l == 16) {
                    char ip[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, d, ip, sizeof(ip));
                    info.san_ip.emplace_back(ip);
                }
            }
        }
        GENERAL_NAMES_free(names);
    }

    int sig_nid = X509_get_signature_nid(cert);
    info.sig_algo = OBJ_nid2ln(sig_nid);
    if (info.sig_algo.empty()) info.sig_algo = "unknown";

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey) {
        info.key_bits = EVP_PKEY_bits(pkey);
        int tid = EVP_PKEY_id(pkey);
        switch (tid) {
            case EVP_PKEY_RSA: info.key_type = "RSA"; break;
            case EVP_PKEY_EC:  info.key_type = "ECDSA"; break;
            case EVP_PKEY_DSA: info.key_type = "DSA"; break;
            case EVP_PKEY_DH:  info.key_type = "DH"; break;
            default:           info.key_type = "Unknown"; break;
        }
        EVP_PKEY_free(pkey);
    }

    info.sha256_fingerprint = compute_sha256(cert);

    BIO* bp = BIO_new(BIO_s_mem());
    if (bp) {
        PEM_write_bio_X509(bp, cert);
        char* pem_data = nullptr;
        long pem_len = BIO_get_mem_data(bp, &pem_data);
        if (pem_data && pem_len > 0)
            info.pem.assign(pem_data, static_cast<size_t>(pem_len));
        BIO_free(bp);
    }

    return info;
}

struct __attribute__((packed)) TlsRecordHeader {
    uint8_t type;
    uint16_t version;
    uint16_t length;
};

static_assert(sizeof(TlsRecordHeader) == 5, "TLS record header must be 5 bytes");

struct TlsServerHello {
    uint16_t version;
    std::vector<uint8_t> random;
    std::vector<uint8_t> session_id;
    uint16_t cipher_suite;
    uint8_t compression;
    std::vector<uint8_t> extensions_data;
};

static int tcp_raw_connect(std::string_view host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (UNLIKELY(fd < 0)) return -1;

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    std::string host_str(host);
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host_str.c_str(), &addr.sin_addr) != 1) {
        struct hostent* he = gethostbyname(host_str.c_str());
        if (UNLIKELY(!he)) { close(fd); return -1; }
        std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    fcntl(fd, F_SETFL, O_NONBLOCK);
    connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    struct pollfd pfd{fd, POLLOUT, 0};
    int rc = poll(&pfd, 1, CONNECT_TIMEOUT_MS);
    if (rc <= 0) { close(fd); return -1; }

    int so_err = 0;
    socklen_t err_len = sizeof(so_err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
    if (so_err != 0) { close(fd); return -1; }

    fcntl(fd, F_SETFL, 0);
    return fd;
}

static int send_all(int fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = static_cast<int>(write(fd, data + sent, len - sent));
        if (n <= 0) return -1;
        sent += static_cast<size_t>(n);
    }
    return 0;
}

static int recv_all(int fd, uint8_t* buf, size_t len, int timeout_ms) {
    size_t total = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (total < len) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;
        int remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (remaining < 1) remaining = 1;
        struct pollfd pfd{fd, POLLIN, 0};
        int rc = poll(&pfd, 1, remaining);
        if (rc <= 0) break;
        int n = static_cast<int>(read(fd, buf + total, len - total));
        if (n <= 0) break;
        total += static_cast<size_t>(n);
    }
    return static_cast<int>(total);
}

HOT_FUNC static std::vector<uint8_t> build_client_hello(std::string_view hostname, uint16_t tls_version) {
    std::vector<uint8_t> ch;

    uint8_t random[32];
    // std::mt19937 rng(std::random_device{}());
    for (auto& b : random) b = static_cast<uint8_t>(std::rand() & 0xff);

    const std::vector<uint16_t> ciphers = {
        0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
        0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9,
        0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
        0xC007, 0xC008, 0xC009, 0xC00A, 0xC011, 0xC012,
        0xC023, 0xC024, 0xC027, 0xC028,
        0x000A, 0x0033, 0x0039, 0x0067, 0x006B,
        0x0016, 0x0038, 0x0041, 0x008D, 0x00FF,
    };

    std::vector<uint16_t> curves = {
        0x001D, 0x0017, 0x001E, 0x0019, 0x0018,
    };

    std::vector<uint8_t> curves_bytes;
curves_bytes.reserve(256);
for (auto c : curves) {
        curves_bytes.emplace_back(static_cast<uint8_t>(c >> 8));
        curves_bytes.emplace_back(static_cast<uint8_t>(c & 0xff));
    }

    std::vector<uint8_t> formats = {0x00};

    auto push_u16 = [&](uint16_t v) {
        ch.emplace_back(static_cast<uint8_t>(v >> 8));
        ch.emplace_back(static_cast<uint8_t>(v & 0xff));
    };
    auto push_u8 = [&](uint8_t v) { ch.emplace_back(v); };
    auto push_data = [&](const uint8_t* d, size_t len) {
        ch.insert(ch.end(), d, d + len);
    };
    auto push_vec = [&](const std::vector<uint8_t>& v) { ch.insert(ch.end(), v.begin(), v.end()); };

    ch.emplace_back(0x01);
    push_u16(tls_version);
    push_data(random, 32);
    push_u8(0);
    push_u16(static_cast<uint16_t>(ciphers.size() * 2));
    for (auto c : ciphers) push_u16(c);

    push_u8(1);
    push_u8(0x00);

    std::vector<uint8_t> exts;

    auto ext_push_u16 = [&](uint16_t v) {
        exts.emplace_back(static_cast<uint8_t>(v >> 8));
        exts.emplace_back(static_cast<uint8_t>(v & 0xff));
    };
    auto ext_push_u8 = [&](uint8_t v) { exts.emplace_back(v); };
    auto ext_push_data = [&](const uint8_t* d, size_t len) {
        exts.insert(exts.end(), d, d + len);
    };
    auto ext_push_vec = [&](const std::vector<uint8_t>& v) {
        exts.insert(exts.end(), v.begin(), v.end());
    };
    auto ext_push_u16_vec = [&](uint16_t type, const std::vector<uint8_t>& data) {
        ext_push_u16(type);
        ext_push_u16(static_cast<uint16_t>(data.size()));
        ext_push_vec(data);
    };

    if (!hostname.empty()) {
        std::vector<uint8_t> sni_data;
        std::string hn = std::string(hostname);
        sni_data.emplace_back(0x00);
        sni_data.emplace_back(static_cast<uint8_t>(hn.size()));
        sni_data.insert(sni_data.end(), hn.begin(), hn.end());
        uint16_t sni_len = static_cast<uint16_t>(sni_data.size());
        std::vector<uint8_t> sni_ext;
        sni_ext.emplace_back(static_cast<uint8_t>(sni_len >> 8));
        sni_ext.emplace_back(static_cast<uint8_t>(sni_len & 0xff));
        sni_ext.insert(sni_ext.end(), sni_data.begin(), sni_data.end());
        ext_push_u16_vec(0x0000, sni_ext);
    }

    {
        std::vector<uint8_t> sg_data;
        sg_data.emplace_back(static_cast<uint8_t>(curves.size() * 2 >> 8));
        sg_data.emplace_back(static_cast<uint8_t>(curves.size() * 2 & 0xff));
        ext_push_vec(curves_bytes);
        ext_push_u16_vec(0x000A, sg_data);
    }

    {
        std::vector<uint8_t> ecpf;
        ecpf.emplace_back(static_cast<uint8_t>(formats.size()));
        ext_push_vec(formats);
        ext_push_u16_vec(0x000B, ecpf);
    }

    {
        std::vector<uint8_t> sig_algo;
        uint16_t sigs[] = {0x0804, 0x0403, 0x0805, 0x0503, 0x0806, 0x0603, 0x0201, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502};
        sig_algo.emplace_back(0);
        sig_algo.emplace_back(static_cast<uint8_t>(sizeof(sigs)));
        for (auto s : sigs) { sig_algo.emplace_back(static_cast<uint8_t>(s >> 8)); sig_algo.emplace_back(static_cast<uint8_t>(s & 0xff)); }
        ext_push_u16_vec(0x000D, sig_algo);
    }

    {
        std::vector<uint8_t> alpn_data;
        std::string alpn_protos = "\x02h2\x08http/1.1";
        alpn_data.emplace_back(static_cast<uint8_t>(alpn_protos.size()));
        alpn_data.insert(alpn_data.end(), alpn_protos.begin(), alpn_protos.end());
        ext_push_u16_vec(0x0010, alpn_data);
    }

    {
        std::vector<uint8_t> reneg;
        reneg.emplace_back(0x00);
        ext_push_u16_vec(0xFF01, reneg);
    }

    std::vector<uint8_t> supported_versions;
    if (tls_version >= 0x0304) {
        supported_versions.emplace_back(static_cast<uint8_t>(3 * 2 + 1));
        supported_versions.emplace_back(0x03); supported_versions.emplace_back(0x04);
        supported_versions.emplace_back(0x03); supported_versions.emplace_back(0x03);
        supported_versions.emplace_back(0x03); supported_versions.emplace_back(0x02);
        supported_versions.emplace_back(0x03); supported_versions.emplace_back(0x01);
        ext_push_u16_vec(0x002B, supported_versions);
    }

    push_u16(static_cast<uint16_t>(exts.size()));
    ext_push_vec(exts);

    return ch;
}

HOT_FUNC static bool parse_server_hello(const std::vector<uint8_t>& raw, TlsForensicResult& res) noexcept {
    if (raw.size() < 5) return false;
    if (raw[0] != 0x16) return false;

    size_t pos = 5;
    if (pos + 38 > raw.size()) return false;

    if (raw[pos] != 0x02) return false;
    pos++;
    uint32_t sh_len = (static_cast<uint32_t>(raw[pos]) << 16) | (static_cast<uint32_t>(raw[pos + 1]) << 8) | raw[pos + 2];
    pos += 3;
    if (pos + sh_len > raw.size()) sh_len = static_cast<uint32_t>(raw.size() - pos);

    uint16_t srv_version = (static_cast<uint16_t>(raw[pos]) << 8) | raw[pos + 1];
    pos += 2;

    const char* ver_str = "unknown";
    switch (srv_version) {
        case 0x0304: ver_str = "TLS 1.3"; break;
        case 0x0303: ver_str = "TLS 1.2"; break;
        case 0x0302: ver_str = "TLS 1.1"; break;
        case 0x0301: ver_str = "TLS 1.0"; break;
        case 0x0300: ver_str = "SSL 3.0"; break;
    }
    res.tls_version = ver_str;

    pos += 32;
    if (pos + 1 > raw.size()) return false;
    uint8_t sid_len = raw[pos]; pos++;
    pos += sid_len;
    if (pos + 2 > raw.size()) return false;
    res.cipher_id = (static_cast<uint16_t>(raw[pos]) << 8) | raw[pos + 1];
    pos += 2;

    if (pos + 1 > raw.size()) return false;
    uint8_t comp = raw[pos]; pos++;

    if (pos + 2 > raw.size()) return false;
    uint16_t ext_len = (static_cast<uint16_t>(raw[pos]) << 8) | raw[pos + 1];
    pos += 2;

    res.ja3s.version_str = std::to_string(srv_version);
    res.ja3s.cipher_str = std::to_string(res.cipher_id);

    std::vector<uint16_t> ext_types;
    std::vector<uint16_t> curves_seen;
    std::vector<uint8_t> formats_seen;

    size_t ext_end = pos + ext_len;
    while (pos + 4 <= ext_end && pos + 4 <= raw.size()) {
        uint16_t ext_type = (static_cast<uint16_t>(raw[pos]) << 8) | raw[pos + 1];
        uint16_t ext_data_len = (static_cast<uint16_t>(raw[pos + 2]) << 8) | raw[pos + 3];
        pos += 4;
        ext_types.emplace_back(ext_type);

        if (ext_type == 0x000A && ext_data_len >= 2 && pos + 2 <= raw.size()) {
            uint16_t groups_len = (static_cast<uint16_t>(raw[pos]) << 8) | raw[pos + 1];
            size_t groups_end = pos + 2 + groups_len;
            size_t gp = pos + 2;
            while (gp + 2 <= groups_end && gp + 2 <= raw.size()) {
                curves_seen.emplace_back((static_cast<uint16_t>(raw[gp]) << 8) | raw[gp + 1]);
                gp += 2;
            }
        }

        if (ext_type == 0x000B && ext_data_len >= 1 && pos + 1 <= raw.size()) {
            uint8_t fmts_len = raw[pos];
            for (uint8_t fi = 0; fi < fmts_len && static_cast<size_t>(pos + 1 + fi) < raw.size(); ++fi)
                formats_seen.emplace_back(raw[pos + 1 + fi]);
        }

        if (ext_type == 0x0010 && ext_data_len >= 2 && pos + 2 <= raw.size()) {
            uint16_t alpn_len = (static_cast<uint16_t>(raw[pos]) << 8) | raw[pos + 1];
            if (pos + 2 + 1 <= raw.size() && alpn_len >= 1) {
                uint8_t proto_len = raw[pos + 2];
                if (pos + 2 + 1 + proto_len <= raw.size()) {
                    res.alpn.assign(reinterpret_cast<const char*>(raw.data() + pos + 3), proto_len);
                }
            }
        }

        pos += ext_data_len;
    }

    for (size_t i = 0; i < ext_types.size(); ++i) {
        if (i) res.ja3s.ext_str += "-";
        res.ja3s.ext_str += std::to_string(ext_types[i]);
    }

    for (size_t i = 0; i < curves_seen.size(); ++i) {
        if (i) res.ja3s.curve_str += "-";
        res.ja3s.curve_str += std::to_string(curves_seen[i]);
    }

    for (size_t i = 0; i < formats_seen.size(); ++i) {
        if (i) res.ja3s.fmt_str += "-";
        res.ja3s.fmt_str += std::to_string(formats_seen[i]);
    }

    res.ja3s.compute();
    return true;
}

COLD_FUNC static void init_openssl_once() noexcept {
    static std::once_flag flag;
    std::call_once(flag, [] {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    });
}

COLD_FUNC static bool openssl_connect_and_extract(std::string_view host, int port, TlsForensicResult& res) {
    int fd = tcp_raw_connect(host, port);
    if (UNLIKELY(fd < 0)) {
        res.error = "TCP connection failed";
        return false;
    }

    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if (UNLIKELY(!ctx)) {
        res.error = "SSL_CTX_new failed";
        close(fd);
        return false;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_timeout(ctx, CONNECT_TIMEOUT_MS / 1000);

    SSL* ssl = SSL_new(ctx);
    if (UNLIKELY(!ssl)) {
        res.error = "SSL_new failed";
        SSL_CTX_free(ctx);
        close(fd);
        return false;
    }

    std::string host_str2(host);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host_str2.c_str());
    res.sni = host_str2;

    int ret = SSL_connect(ssl);
    if (LIKELY(ret == 1)) {
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
        if (cipher) {
            res.cipher_suite = SSL_CIPHER_get_name(cipher);
            res.cipher_id = static_cast<uint16_t>(SSL_CIPHER_get_id(cipher) & 0xffff);
        }

        if (res.tls_version == "unknown") {
            int ver = SSL_version(ssl);
            switch (ver) {
                case TLS1_3_VERSION: res.tls_version = "TLS 1.3"; break;
                case TLS1_2_VERSION: res.tls_version = "TLS 1.2"; break;
                case TLS1_1_VERSION: res.tls_version = "TLS 1.1"; break;
                case TLS1_VERSION:   res.tls_version = "TLS 1.0"; break;
                case SSL3_VERSION:  res.tls_version = "SSL 3.0"; break;
            }
        }

        const unsigned char* alpn_data = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_len);
        if (alpn_data && alpn_len > 0)
            res.alpn.assign(reinterpret_cast<const char*>(alpn_data), static_cast<size_t>(alpn_len));

        STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
        if (chain) {
            int n = sk_X509_num(chain);
            for (int i = 0; i < n; ++i) {
                X509* cert = sk_X509_value(chain, i);
                if (cert) {
                    X509_up_ref(cert);
                    res.chain.emplace_back(extract_cert_info(cert));
                    X509_free(cert);
                }
            }
        } else {
            X509* cert = SSL_get1_peer_certificate(ssl);
            if (cert) {
                res.chain.emplace_back(extract_cert_info(cert));
                X509_free(cert);
            }
        }
    } else {
        res.error = "SSL handshake failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr));
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return ret == 1;
}

HOT_FUNC static std::string json_escape(std::string_view s) {
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
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    r += buf;
                } else {
                    r += c;
                }
        }
    }
    return r;
}

HOT_FUNC static void emit_json(const TlsForensicResult& res) noexcept {
    std::lock_guard<std::mutex> lock(g_print_mutex);
    std::cout << "RESULT:{\"target\":\"" << json_escape(res.target)
              << "\",\"port\":" << res.port
              << ",\"connected\":" << (res.connected ? "true" : "false")
              << ",\"tls_version\":\"" << json_escape(res.tls_version)
              << "\",\"cipher_suite\":\"" << json_escape(res.cipher_suite)
              << "\",\"cipher_id\":" << res.cipher_id
              << ",\"ja3s\":{"
              << "\"version\":\"" << json_escape(res.ja3s.version_str)
              << "\",\"ciphers\":\"" << json_escape(res.ja3s.cipher_str)
              << "\",\"extensions\":\"" << json_escape(res.ja3s.ext_str)
              << "\",\"curves\":\"" << json_escape(res.ja3s.curve_str)
              << "\",\"formats\":\"" << json_escape(res.ja3s.fmt_str)
              << "\",\"fingerprint\":\"" << res.ja3s.fingerprint
              << "\"}"
              << ",\"alpn\":\"" << json_escape(res.alpn)
              << "\",\"sni\":\"" << json_escape(res.sni)
              << "\",\"chain\":[";
    for (size_t i = 0; i < res.chain.size(); ++i) {
        const auto& c = res.chain[i];
        if (i) std::cout << ",";
        std::cout << "{\"subject\":\"" << json_escape(c.subject)
                  << "\",\"issuer\":\"" << json_escape(c.issuer)
                  << "\",\"serial\":\"" << json_escape(c.serial)
                  << "\",\"not_before\":\"" << json_escape(c.not_before)
                  << "\",\"not_after\":\"" << json_escape(c.not_after)
                  << "\",\"days_remaining\":" << c.days_remaining
                  << ",\"expired\":" << (c.expired ? "true" : "false")
                  << ",\"self_signed\":" << (c.self_signed ? "true" : "false")
                  << ",\"sig_algo\":\"" << json_escape(c.sig_algo)
                  << "\",\"key_type\":\"" << json_escape(c.key_type)
                  << "\",\"key_bits\":" << c.key_bits
                  << ",\"sha256\":\"" << c.sha256_fingerprint
                  << "\",\"san_dns\":[";
        for (size_t d = 0; d < c.san_dns.size(); ++d) {
            if (d) std::cout << ",";
            std::cout << "\"" << json_escape(c.san_dns[d]) << "\"";
        }
        std::cout << "],\"san_ip\":[";
        for (size_t a = 0; a < c.san_ip.size(); ++a) {
            if (a) std::cout << ",";
            std::cout << "\"" << json_escape(c.san_ip[a]) << "\"";
        }
        std::cout << "]}";
    }
    std::cout << "],\"error\":\"" << json_escape(res.error) << "\"}\n" << std::flush;
}

struct CliArgs {
    std::string target = "127.0.0.1";
    std::vector<int> ports;
    int timeout = CONNECT_TIMEOUT_MS;
};

static CliArgs parse_cli(int argc, char** argv) {
    CliArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if ((arg == "--target" || arg == "-t") && i + 1 < argc) {
            args.target = argv[++i];
        } else if ((arg == "--ports" || arg == "-p") && i + 1 < argc) {
            std::string ps(argv[++i]);
            size_t pos = 0;
            while (pos < ps.size()) {
                size_t comma = ps.find(',', pos);
                std::string tok = ps.substr(pos, comma - pos);
                if (!tok.empty()) {
                    auto dash = tok.find('-');
                    if (dash != std::string::npos) {
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
        } else if (arg == "--timeout" && i + 1 < argc) {
            args.timeout = std::atoi(argv[++i]) * 1000;
            if (args.timeout < 1000) args.timeout = 1000;
        } else if (arg == "--help" || arg == "-h") {
            std::cerr << "Usage: " << argv[0]
                      << " --target <IP> --ports <port,list> [--timeout <sec>]\n";
            std::exit(0);
        }
    }
    if (args.ports.empty()) args.ports = {443, 8443, 465, 993, 995, 636, 990, 992, 853, 587, 2083};
    return args;
}

int main(int argc, char** argv) {
    auto args = parse_cli(argc, argv);
    init_openssl_once();

    std::cerr << "[*] TLS Forensic Analyzer scanning " << args.target
              << " on " << args.ports.size() << " ports\n";

    for (int port : args.ports) {
        TlsForensicResult res;
        res.target = args.target;
        res.port = port;

        int fd = tcp_raw_connect(args.target, port);
        if (LIKELY(fd >= 0)) {
            auto ch = build_client_hello(args.target, 0x0303);
            std::vector<uint8_t> record_header(5);
            record_header[0] = 0x16;
            record_header[1] = 0x03; record_header[2] = 0x01;
            record_header[3] = static_cast<uint8_t>((ch.size() >> 8) & 0xff);
            record_header[4] = static_cast<uint8_t>(ch.size() & 0xff);

            if (send_all(fd, record_header.data(), 5) == 0 && send_all(fd, ch.data(), ch.size()) == 0) {
                uint8_t resp_hdr[5];
                if (recv_all(fd, resp_hdr, 5, args.timeout) == 5 && resp_hdr[0] == 0x16) {
                    uint16_t resp_len = (static_cast<uint16_t>(resp_hdr[3]) << 8) | resp_hdr[4];
                    if (resp_len > 0 && resp_len < 65536) {
                        std::vector<uint8_t> resp_body(resp_len);
                        if (recv_all(fd, resp_body.data(), resp_len, args.timeout) == static_cast<int>(resp_len)) {
                            std::vector<uint8_t> full_resp;
                            full_resp.insert(full_resp.end(), resp_hdr, resp_hdr + 5);
                            full_resp.insert(full_resp.end(), resp_body.begin(), resp_body.end());
                            res.connected = true;
                            parse_server_hello(full_resp, res);
                        }
                    }
                }
            }
            close(fd);
        }

        if (res.connected) {
            openssl_connect_and_extract(args.target, port, res);
        }

        emit_json(res);
    }

    return 0;
}
