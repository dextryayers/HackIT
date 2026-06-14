#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "crypt32.lib")
  #include <windows.h>
  typedef int socklen_t;
  #define CLOSE_SOCKET(s) closesocket(s)
  #define IS_INVALID(s) ((s) == INVALID_SOCKET)
  #define SOCK_ERRNO WSAGetLastError()
  #define SOCK_EWOULDBLOCK WSAEWOULDBLOCK
#else
  #include <sys/socket.h>
  #include <sys/poll.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <sys/time.h>
  #include <netinet/tcp.h>
  #include <netinet/in.h>
  #define CLOSE_SOCKET(s) close(s)
  #define SOCKET int
  #define INVALID_SOCKET -1
  #define IS_INVALID(s) ((s) < 0)
  #define SOCK_ERRNO errno
  #define SOCK_EWOULDBLOCK EWOULDBLOCK
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/x509v3.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <queue>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <iomanip>

using namespace std;
using namespace chrono;

const int DEFAULT_TIMEOUT_MS = 1500;
const int MAX_BANNER = 16384;
const int MAX_WORKERS = 32;

struct CipherSuite {
    string iana_name;
    string openssl_name;
    uint16_t id;
    string kx, au, enc, mac;
    int key_size;
    string protocol;
    string severity;
};

struct TLSResult {
    int port;
    bool tls_supported;
    string version;
    vector<CipherSuite> ciphers;
    string cert_subject;
    string cert_issuer;
    string cert_serial;
    string cert_not_before;
    string cert_not_after;
    int cert_days_remaining;
    bool cert_self_signed;
    bool cert_expired;
    vector<string> san_dns;
    vector<string> san_ip;
    string signature_algorithm;
    int key_bits;
    string public_key_type;
    vector<string> supported_groups;
    bool heartbleed_vuln;
    bool poodle_vuln;
    bool beast_vuln;
    bool freak_vuln;
    bool logjam_vuln;
    bool sweet32_vuln;
    bool rc4_used;
    bool null_cipher;
    bool anon_cipher;
    bool des_used;
    bool tls13_supported;
    double grade;
    string grade_label;
    string risk_level;
};

static const uint16_t CIPHER_IDS[] = {
    0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
    0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9,
    0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
    0xC007, 0xC008, 0xC009, 0xC00A, 0xC011, 0xC012,
    0xC023, 0xC024, 0xC027, 0xC028,
    0x000A, 0x0033, 0x0039, 0x0067, 0x006B,
    0x0016, 0x0038, 0x0041, 0x008D,
    0xC010, 0xC018,
    0x009E, 0x009F,
    0x0005, 0x0004, 0x0001,
    0
};

static const char* CIPHER_NAMES[] = {
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA", "AES128-GCM-SHA256", "AES256-GCM-SHA384", "AES128-SHA", "AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA", "ECDHE-ECDSA-AES128-SHA256", "ECDHE-ECDSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-SHA", "DHE-RSA-AES256-SHA", "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-CHACHA20-POLY1305",
    "EDH-RSA-DES-CBC3-SHA", "DHE-RSA-AES256-SHA256", "DHE-RSA-AES128-SHA256", "DHE-RSA-CAMELLIA256-SHA", "DHE-RSA-CAMELLIA128-SHA",
    "ECDHE-RSA-DES-CBC3-SHA", "DHE-RSA-DES-CBC3-SHA",
    "AES128-SHA256", "AES256-SHA256",
    "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5",
    NULL
};

static const char* CIPHER_SEVERITY[] = {
    "GOOD", "GOOD", "GOOD", "GOOD", "GOOD",
    "GOOD", "GOOD", "GOOD", "GOOD", "GOOD", "GOOD",
    "OK", "OK", "GOOD", "GOOD", "OK", "OK",
    "OK", "OK", "OK", "OK", "OK", "OK",
    "GOOD", "GOOD", "GOOD", "GOOD",
    "OK", "OK", "GOOD", "GOOD", "GOOD",
    "WEAK", "OK", "OK", "OK", "OK",
    "WEAK", "WEAK",
    "OK", "OK",
    "WEAK", "INSECURE", "INSECURE",
    NULL
};

static long long now_ms() {
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static void set_nonblocking(SOCKET s, bool nb) {
#ifdef _WIN32
    u_long mode = nb ? 1 : 0;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, nb ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
#endif
}

static SOCKET tcp_connect(const string& host, int port, int timeout_ms) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        struct hostent* he = gethostbyname(host.c_str());
        if (!he) return INVALID_SOCKET;
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (IS_INVALID(s)) return INVALID_SOCKET;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));
    set_nonblocking(s, true);
    connect(s, (struct sockaddr*)&addr, sizeof(addr));
    struct pollfd pfd = {s, POLLOUT, 0};
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) { CLOSE_SOCKET(s); return INVALID_SOCKET; }
    int so_err = 0;
    socklen_t err_len = sizeof(so_err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &err_len);
    if (so_err != 0) { CLOSE_SOCKET(s); return INVALID_SOCKET; }
    set_nonblocking(s, false);
    return s;
}

static bool probe_tls_version(const string& host, int port, int timeout_ms, const string& tls_version,
    uint8_t major, uint8_t minor, string& server_hello, int& max_recv) {
    SOCKET s = tcp_connect(host, port, timeout_ms);
    if (IS_INVALID(s)) return false;
    uint8_t ch[] = {
        0x16, major, minor,
        0x00, 0x00,
        0x01, 0x00, 0x00,
        major, minor,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02,
        0x00, 0x2F, 0x00, 0x35,
        0x01, 0x00
    };
    uint16_t len = htons((uint16_t)(sizeof(ch) - 5));
    memcpy(ch + 3, &len, 2);
    send(s, (char*)ch, sizeof(ch), 0);
    char buf[16384];
    int total = 0;
    long long deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline && total < (int)sizeof(buf)) {
        int n = recv(s, buf + total, sizeof(buf) - total, 0);
        if (n > 0) total += n;
        else break;
        if (total >= 5 && (buf[0] == 0x15 || buf[0] == 0x16)) break;
    }
    CLOSE_SOCKET(s);
    max_recv = total;
    server_hello = string(buf, total);
    return total >= 5 && (unsigned char)buf[0] == 0x16 && (unsigned char)buf[5] == 0x02;
}

static double grade_tls(TLSResult& r) {
    double score = 100;
    if (r.rc4_used || r.null_cipher || r.anon_cipher) score -= 40;
    if (r.des_used) score -= 20;
    if (r.poodle_vuln) score -= 30;
    if (r.heartbleed_vuln) score -= 35;
    if (r.beast_vuln) score -= 15;
    if (r.freak_vuln) score -= 20;
    if (r.logjam_vuln) score -= 10;
    if (r.sweet32_vuln) score -= 15;
    if (!r.tls13_supported) score -= 10;
    if (r.cert_expired) score -= 25;
    if (r.cert_self_signed) score -= 15;
    if (r.cert_days_remaining < 30) score -= 10;
    if (score > 100) score = 100;
    if (score < 0) score = 0;
    if (score >= 90) { r.grade_label = "A+"; r.risk_level = "LOW"; }
    else if (score >= 80) { r.grade_label = "A"; r.risk_level = "LOW"; }
    else if (score >= 70) { r.grade_label = "B"; r.risk_level = "MEDIUM"; }
    else if (score >= 60) { r.grade_label = "C"; r.risk_level = "MEDIUM"; }
    else if (score >= 50) { r.grade_label = "D"; r.risk_level = "HIGH"; }
    else if (score >= 30) { r.grade_label = "E"; r.risk_level = "HIGH"; }
    else { r.grade_label = "F"; r.risk_level = "CRITICAL"; }
    return score;
}

static TLSResult scan_tls(const string& host, int port, int timeout_ms) {
    TLSResult r;
    memset(&r, 0, sizeof(r));
    r.port = port;
    string sh;
    int n;
    r.tls13_supported = probe_tls_version(host, port, timeout_ms, "TLS 1.3", 0x03, 0x04, sh, n);
    r.tls_supported = probe_tls_version(host, port, timeout_ms, "TLS 1.2", 0x03, 0x03, sh, n) ||
                      probe_tls_version(host, port, timeout_ms, "TLS 1.1", 0x03, 0x02, sh, n) ||
                      probe_tls_version(host, port, timeout_ms, "TLS 1.0", 0x03, 0x01, sh, n) ||
                      probe_tls_version(host, port, timeout_ms, "SSL 3.0", 0x03, 0x00, sh, n);
    if (probe_tls_version(host, port, timeout_ms, "TLS 1.3", 0x03, 0x04, sh, n)) r.version = "TLS 1.3";
    else if (probe_tls_version(host, port, timeout_ms, "TLS 1.2", 0x03, 0x03, sh, n)) r.version = "TLS 1.2";
    else if (probe_tls_version(host, port, timeout_ms, "TLS 1.1", 0x03, 0x02, sh, n)) r.version = "TLS 1.1";
    else if (probe_tls_version(host, port, timeout_ms, "TLS 1.0", 0x03, 0x01, sh, n)) r.version = "TLS 1.0";
    else if (probe_tls_version(host, port, timeout_ms, "SSL 3.0", 0x03, 0x00, sh, n)) r.version = "SSL 3.0";
    else r.version = "none";
    if (r.tls_supported) {
        for (int i = 0; CIPHER_IDS[i]; i++) {
            CipherSuite cs;
            cs.id = CIPHER_IDS[i];
            cs.iana_name = CIPHER_NAMES[i] ? CIPHER_NAMES[i] : "unknown";
            cs.severity = CIPHER_SEVERITY[i] ? CIPHER_SEVERITY[i] : "UNKNOWN";
            r.ciphers.push_back(cs);
        }
        r.tls13_supported = probe_tls_version(host, port, timeout_ms, "TLS 1.3", 0x03, 0x04, sh, n);
    }
    r.grade = grade_tls(r);
    return r;
}

static void print_json(const TLSResult& r) {
    printf("RESULT:{\"port\":%d,\"tls\":%s,\"version\":\"%s\",\"grade\":\"%s\",\"risk\":\"%s\",\"ciphers\":%zu,\"tls13\":%s}\n",
        r.port, r.tls_supported ? "true" : "false", r.version.c_str(),
        r.grade_label.c_str(), r.risk_level.c_str(),
        r.ciphers.size(), r.tls13_supported ? "true" : "false");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host> [ports] [timeout_ms]\n", argv[0]);
        fprintf(stderr, "  ports: comma-separated (default: 443,8443,465,993,995,636,990,992,853,587)\n");
        return 1;
    }
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    vector<int> ports;
    if (argc > 2) {
        char* p = strtok(argv[2], ",");
        while (p) { ports.push_back(atoi(p)); p = strtok(NULL, ","); }
    }
    if (ports.empty()) {
        ports = {443, 8443, 465, 993, 995, 636, 990, 992, 853, 587};
    }
    int timeout = argc > 3 ? atoi(argv[3]) : DEFAULT_TIMEOUT_MS;
    fprintf(stderr, "TLS_SCANNER target=%s ports=%zu timeout=%dms\n", argv[1], ports.size(), timeout);
    for (int port : ports) {
        TLSResult r = scan_tls(argv[1], port, timeout);
        print_json(r);
        fflush(stdout);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
