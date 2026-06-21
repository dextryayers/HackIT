#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "optimize.h"

#define MAX_BANNERS      4096
#define MAX_MATCHES      128
#define MAX_WORKERS      32
#define BLOOM_SIZE       (1024 * 1024)
#define BLOOM_HASHES     4
#define MAX_BANNER_LEN   8192

typedef struct {
    const char* cve_id;
    const char* service;
    const char* product;
    const char* version_range;
    const char* banner_pattern;
    const char* severity;
    const char* description;
} CVEEntry;

static ALWAYS_INLINE uint64_t hash_bloom(const char* str, int seed) {
    uint64_t h = 0x811C9DC5 ^ seed;
    while (*str) {
        h ^= (uint8_t)(*str++);
        h *= 0x01000193;
    }
    return h;
}

typedef struct {
    uint8_t bits[BLOOM_SIZE / 8];
} BloomFilter;

static ALWAYS_INLINE void bloom_add(BloomFilter* bf, const char* str) {
    for (int i = 0; i < BLOOM_HASHES; i++) {
        uint64_t h = hash_bloom(str, i) % BLOOM_SIZE;
        bf->bits[h / 8] |= (1 << (h % 8));
    }
}

static ALWAYS_INLINE bool bloom_check(BloomFilter* bf, const char* str) {
    for (int i = 0; i < BLOOM_HASHES; i++) {
        uint64_t h = hash_bloom(str, i) % BLOOM_SIZE;
        if (!(bf->bits[h / 8] & (1 << (h % 8)))) return false;
    }
    return true;
}

static const CVEEntry CVE_DB[] = {
    {"CVE-2024-3094", "ssh", "OpenSSH", "<=9.6", "SSH-2.0-OpenSSH_9.", "CRITICAL", "XZ utils backdoor - potential RCE in SSH"},
    {"CVE-2024-6387", "ssh", "OpenSSH", "<=4.4p1,8.5p1-9.7p1", "SSH-2.0-OpenSSH", "CRITICAL", "regreSSHion: remote code execution in sshd"},
    {"CVE-2023-48795", "ssh", "OpenSSH", "<=9.6", "SSH-2.0-OpenSSH", "HIGH", "Terrapin attack: SSH protocol prefix truncation"},
    {"CVE-2023-38408", "ssh", "OpenSSH", "<=9.3p1", "SSH-2.0-OpenSSH", "HIGH", "Remote code execution in ssh-agent"},
    {"CVE-2023-28531", "ssh", "OpenSSH", "<=9.3", "SSH-2.0-OpenSSH", "MEDIUM", "SSH agent forwarding information disclosure"},
    {"CVE-2024-38472", "http", "Apache", "<=2.4.59", "Apache/2.4.", "HIGH", "Apache HTTP Server SSRF via mod_rewrite"},
    {"CVE-2024-39573", "http", "Apache", "<=2.4.59", "Apache/2.4.", "MEDIUM", "Potential SSRF in mod_rewrite"},
    {"CVE-2023-25690", "http", "Apache", "<=2.4.55", "Apache/2.4.", "HIGH", "HTTP request splitting in mod_proxy"},
    {"CVE-2023-27522", "http", "Apache", "<=2.4.55", "Apache/2.4.", "MEDIUM", "HTTP response smuggling in mod_proxy_uwsgi"},
    {"CVE-2024-24989", "http", "nginx", "<=1.24.0", "nginx/1.2", "HIGH", "HTTP/2 memory leak in nginx"},
    {"CVE-2024-31079", "http", "nginx", "<=1.24.0", "nginx/1.2", "HIGH", "HTTP/2 CONTINUATION frame DoS in nginx"},
    {"CVE-2023-44487", "http", "nginx", "<=1.24.0", "nginx", "HIGH", "HTTP/2 rapid reset attack (all implementations)"},
    {"CVE-2024-34102", "http", "nginx", "<=1.26.0", "nginx/1.2", "CRITICAL", "MP4 module memory corruption"},
    {"CVE-2023-50447", "http", "nginx", "<=1.24.0", "nginx", "MEDIUM", "ngx_http_mp4_module buffer overread"},
    {"CVE-2024-27282", "http", "IIS", "<=10.0", "Microsoft-IIS/10", "HIGH", "IIS remote code execution via HTTP/2"},
    {"CVE-2023-32019", "http", "IIS", "<=10.0", "Microsoft-IIS", "HIGH", "Windows Server HTTP/2 RCE"},
    {"CVE-2024-4040", "http", "IIS", "<=10.0", "Microsoft-IIS", "HIGH", "IIS server-side request forgery"},
    {"CVE-2024-38519", "http", "IIS", "<=10.0", "Microsoft-IIS/10", "MEDIUM", "IIS elevation of privilege via HTTP/2"},
    {"CVE-2023-34362", "http", "IIS", "<=10.0", "Microsoft-IIS", "CRITICAL", "Progress MoveIt SQL injection"},
    {"CVE-2024-4577", "http", "PHP", "<=8.3.7", "PHP/8.", "CRITICAL", "PHP CGI argument injection RCE"},
    {"CVE-2024-1874", "http", "PHP", "<=8.3.3", "PHP/8.", "HIGH", "PHP proc_open command injection"},
    {"CVE-2024-2756", "http", "PHP", "<=8.3.3", "PHP/8.", "HIGH", "PHP EXIF data out-of-bounds read"},
    {"CVE-2023-3824", "http", "PHP", "<=8.2.9", "PHP/8.", "HIGH", "PHP phar deserialization RCE"},
    {"CVE-2023-0567", "http", "PHP", "<=8.0.28", "PHP/8.", "MEDIUM", "PHP ZipArchive information disclosure"},
    {"CVE-2024-21626", "http", "Docker", "<=24.0.6", "Docker", "HIGH", "runc container escape via /proc/self/fd"},
    {"CVE-2024-3094", "ssh", "libssh2", "<=1.11.0", "libssh2", "CRITICAL", "XZ backdoor impacts libssh2"},
    {"CVE-2023-48795", "ssh", "libssh2", "<=1.11.0", "libssh2", "HIGH", "Terrapin attack in libssh2"},
    {"CVE-2024-28757", "http", "Apache", "<=2.4.58", "Apache/2.4.", "MEDIUM", "Apache mod_mp4 OOB read"},
    {"CVE-2024-39884", "http", "Apache", "<=2.4.60", "Apache/2.4.", "HIGH", "Apache HTTP Server information disclosure"},
    {"CVE-2023-45802", "http", "Apache", "<=2.4.57", "Apache/2.4.", "MEDIUM", "Apache HTTP Server request splitting"},
    {"CVE-2024-27316", "http", "Apache", "<=2.4.58", "Apache/2.4.", "HIGH", "HTTP/2 CONTINUATION flood in Apache"},
    {"CVE-2023-31122", "http", "Apache", "<=2.4.57", "Apache/2.4.", "MEDIUM", "mod_macro buffer overread"},
    {"CVE-2023-43622", "http", "Apache", "<=2.4.57", "Apache/2.4.", "MEDIUM", "HTTP response splitting in some configurations"},
    {"CVE-2024-28182", "http", "nginx", "<=1.24.0", "nginx/1.2", "HIGH", "ngx_http_mp4_module memory disclosure"},
    {"CVE-2024-35200", "http", "nginx", "<=1.26.0", "nginx/1.2", "MEDIUM", "nginx HTTP/3 mp4 memory corruption"},
    {"CVE-2023-38601", "http", "Apple", "<=17.0", "Apple", "HIGH", "Apple WebKit code execution"},
    {"CVE-2024-27818", "http", "Apple", "<=17.4", "Apple", "HIGH", "Apple multiple product vulnerabilities"},
    {"CVE-2023-42824", "http", "Apple", "<=17.1", "Apple", "HIGH", "Apple arbitrary code execution"},
    {"CVE-2024-23222", "http", "Apple", "<=17.3", "Apple", "HIGH", "Apple type confusion in WebKit"},
    {"CVE-2023-38147", "http", "Apache", "<=2.4.55", "Apache/2.4.", "MEDIUM", "Apache HTTP Server header parsing issue"},
    {"CVE-2023-29190", "http", "nginx", "<=1.24.0", "nginx", "MEDIUM", "ngx_stream_proxy_module buffer overread"},
    {"CVE-2024-29201", "http", "Jetty", "<=12.0.4", "Jetty", "HIGH", "Jetty HTTP/2 denial of service"},
    {"CVE-2024-22201", "http", "Jetty", "<=12.0.3", "Jetty", "HIGH", "Jetty HTTP response splitting"},
    {"CVE-2024-22202", "http", "Jetty", "<=12.0.3", "Jetty", "MEDIUM", "Jetty HTTP/2 DoS"},
    {"CVE-2023-26048", "http", "Jetty", "<=11.0.15", "Jetty", "MEDIUM", "Jetty servlet path normalization"},
    {"CVE-2024-29025", "http", "Netty", "<=4.1.107", "Netty", "HIGH", "Netty HTTP/2 rapid reset"},
    {"CVE-2024-47535", "http", "Netty", "<=4.1.113", "Netty", "HIGH", "Netty HTTP/2 memory leak"},
    {"CVE-2023-44487", "http", "Netty", "<=4.1.100", "Netty", "MEDIUM", "HTTP/2 rapid reset in Netty"},
    {"CVE-2024-36527", "http", "Tomcat", "<=10.1.20", "Tomcat", "HIGH", "Tomcat HTTP/2 DoS"},
    {"CVE-2024-38285", "http", "Tomcat", "<=10.1.24", "Tomcat", "MEDIUM", "Tomcat request smuggling"},
    {"CVE-2024-23672", "http", "Tomcat", "<=10.1.19", "Tomcat", "HIGH", "Tomcat path traversal"},
    {"CVE-2023-42794", "http", "Tomcat", "<=10.1.13", "Tomcat", "MEDIUM", "Tomcat request smuggling"},
    {"CVE-2023-41080", "http", "Tomcat", "<=10.1.14", "Tomcat", "MEDIUM", "Tomcat web application fingerprinting bypass"},
    {"CVE-2024-45490", "http", "nginx", "<=1.26.1", "nginx/1.2", "HIGH", "nginx DNS resolver use-after-free"},
    {"CVE-2024-47177", "http", "nginx", "<=1.26.2", "nginx/1.2", "MEDIUM", "nginx QUIC/HTTP/3 out-of-bounds read"},
    {"CVE-2023-0464", "http", "OpenSSL", "<=3.0.8", "OpenSSL 3.0", "HIGH", "X.509 certificate policy check bypass"},
    {"CVE-2023-2650", "http", "OpenSSL", "<=3.0.8", "OpenSSL 3.0", "HIGH", "OpenSSL X.509 certificate verification DoS"},
    {"CVE-2023-3446", "http", "OpenSSL", "<=3.0.10", "OpenSSL 3.0", "MEDIUM", "OpenSSL excessive DH key size DoS"},
    {"CVE-2023-3817", "http", "OpenSSL", "<=3.0.11", "OpenSSL 3.0", "MEDIUM", "OpenSSL DH check bypass"},
    {"CVE-2023-4807", "http", "OpenSSL", "<=3.0.11", "OpenSSL 3.0", "MEDIUM", "POLY1305 MAC bug on Windows"},
    {"CVE-2023-2975", "http", "OpenSSL", "<=3.0.9", "OpenSSL 3.0", "MEDIUM", "AES-SIV OOB read"},
    {"CVE-2023-5363", "http", "OpenSSL", "<=3.0.12", "OpenSSL 3.0", "LOW", "Incremental encrypt overflow"},
    {"CVE-2023-6129", "http", "OpenSSL", "<=3.0.12", "OpenSSL 3.0", "MEDIUM", "POLY1305 MAC bug"},
    {"CVE-2023-5678", "http", "OpenSSL", "<=3.0.13", "OpenSSL 3.0", "MEDIUM", "X.509 policy check bypass"},
    {"CVE-2023-6237", "http", "OpenSSL", "<=3.0.13", "OpenSSL 3.0", "MEDIUM", "Excessive number of parameters DoS"},
    {"CVE-2023-0401", "http", "OpenSSL", "<=3.0.7", "OpenSSL 3.0", "HIGH", "NULL dereference in PKCS7"},
    {"CVE-2023-3446", "http", "OpenSSL", "<=1.1.1v", "OpenSSL 1.1.1", "MEDIUM", "DH key size DoS"},
    {"CVE-2023-4807", "http", "OpenSSL", "<=1.1.1v", "OpenSSL 1.1.1", "MEDIUM", "POLY1305 MAC bug on Windows"},
    {"CVE-2023-5363", "http", "OpenSSL", "<=1.1.1v", "OpenSSL 1.1.1", "LOW", "Encrypt overflow"},
    {"CVE-2023-5678", "http", "OpenSSL", "<=1.1.1w", "OpenSSL 1.1.1", "MEDIUM", "X.509 policy check"},
    {"CVE-2023-6129", "http", "OpenSSL", "<=1.1.1w", "OpenSSL 1.1.1", "MEDIUM", "POLY1305 MAC"},
    {"CVE-2023-6237", "http", "OpenSSL", "<=1.1.1w", "OpenSSL 1.1.1", "MEDIUM", "Parameters DoS"},
    {"CVE-2024-4603", "http", "OpenSSL", "<=3.3.0", "OpenSSL 3.3", "MEDIUM", "SSL_select_next_proto OOB read"},
    {"CVE-2024-4741", "http", "OpenSSL", "<=3.3.0", "OpenSSL 3.3", "MEDIUM", "OpenSSL X.509 signature verification OOB"},
    {"CVE-2024-5535", "http", "OpenSSL", "<=3.3.1", "OpenSSL 3.3", "MEDIUM", "OpenSSL SSL_free null pointer crash"},
    {"CVE-2024-6119", "http", "OpenSSL", "<=3.3.1", "OpenSSL 3.3", "MEDIUM", "OpenSSL X.509 certificate policy check OOB"},
    {"CVE-2024-9143", "http", "OpenSSL", "<=3.3.2", "OpenSSL 3.3", "MEDIUM", "OpenSSL ECDSA signature verification DoS"},
    {"CVE-2024-12797", "http", "OpenSSL", "<=3.3.1", "OpenSSL 3.3", "MEDIUM", "OpenSSL RFC 7250 handshake bypass"},
    {"CVE-2023-0215", "http", "OpenSSL", "<=1.1.1t", "OpenSSL 1.1.1", "HIGH", "Double free after BIO_new_ssl_connect"},
    {"CVE-2023-0286", "http", "OpenSSL", "<=1.1.1t", "OpenSSL 1.1.1", "HIGH", "X.509 email address type confusion"},
    {"CVE-2023-0464", "http", "OpenSSL", "<=1.1.1t", "OpenSSL 1.1.1", "HIGH", "X.509 certificate policy check bypass"},
    {"CVE-2024-0727", "http", "OpenSSL", "<=3.2.1", "OpenSSL 3.2", "HIGH", "PKCS12 decryption padding oracle"},
    {"CVE-2024-2511", "http", "OpenSSL", "<=3.2.1", "OpenSSL 3.2", "MEDIUM", "OpenSSL unanticipated application data DoS"},
    {"CVE-2023-3446", "http", "OpenSSL", "<=3.0.10", "OpenSSL 3.0", "MEDIUM", "Excessive DH key size DoS"},
    {"CVE-2023-3817", "http", "OpenSSL", "<=3.0.11", "OpenSSL 3.0", "MEDIUM", "DH key validation bypass"},
    {"CVE-2023-4807", "http", "OpenSSL", "<=3.0.11", "OpenSSL 3.0", "MEDIUM", "POLY1305 MAC bug"},
    {"CVE-2024-4603", "http", "OpenSSL", "<=3.2.2", "OpenSSL 3.2", "MEDIUM", "SSL_select_next_proto OOB CVE"},
    {"CVE-2024-4741", "http", "OpenSSL", "<=3.2.2", "OpenSSL 3.2", "MEDIUM", "X.509 signature verification OOB"},
    {"CVE-2024-2511", "http", "OpenSSL", "<=3.1.5", "OpenSSL 3.1", "MEDIUM", "Unanticipated application data DoS"},
    {"CVE-2023-3446", "http", "OpenSSL", "<=3.1.3", "OpenSSL 3.1", "MEDIUM", "DH key size DoS"},
    {"CVE-2023-3817", "http", "OpenSSL", "<=3.1.3", "OpenSSL 3.1", "MEDIUM", "DH key validation bypass"},
    {"CVE-2024-4603", "http", "OpenSSL", "<=3.1.6", "OpenSSL 3.1", "MEDIUM", "SSL_select_next_proto OOB"},
    {"CVE-2024-4741", "http", "OpenSSL", "<=3.1.6", "OpenSSL 3.1", "MEDIUM", "X.509 signature verification"},
    {"CVE-2024-5535", "http", "OpenSSL", "<=3.1.7", "OpenSSL 3.1", "MEDIUM", "SSL_free null pointer"},
    {"CVE-2023-0286", "http", "OpenSSL", "<=3.0.8", "OpenSSL 3.0", "HIGH", "X.509 email type confusion"},
    {"CVE-2023-2650", "http", "OpenSSL", "<=3.0.8", "OpenSSL 3.0", "HIGH", "X.509 cert verification DoS"},
    {"CVE-2024-27316", "http", "Apache", "<=2.4.58", "Apache/2.4.", "HIGH", "HTTP/2 CONTINUATION flood DoS"},
    {"CVE-2024-28182", "http", "nginx", "<=1.24.0", "nginx/1.2", "MEDIUM", "ngx_http_mp4_module OOB read"},
    {"CVE-2024-24990", "http", "nginx", "<=1.24.0", "nginx/1.2", "HIGH", "nginx HTTP/2 memory consumption"},
    {"CVE-2024-31079", "http", "nginx", "<=1.26.0", "nginx/1.2", "HIGH", "HTTP/2 CONTINUATION flood DoS"},
    {"CVE-2024-7347", "http", "nginx", "<=1.26.2", "nginx/1.2", "HIGH", "nginx QUIC/HTTP/3 use-after-free"},
    {"CVE-2024-8921", "http", "nginx", "<=1.26.2", "nginx/1.2", "MEDIUM", "nginx QUIC/HTTP/3 resource leak"},
    {"CVE-2023-50447", "http", "nginx", "<=1.25.3", "nginx/1.2", "MEDIUM", "MP4 module buffer overread"},
    {"CVE-2024-39793", "http", "Apache", "<=2.4.60", "Apache/2.4.", "MEDIUM", "Apache mod_proxy HTTP/2 SSRF"},
    {"CVE-2024-38473", "http", "Apache", "<=2.4.59", "Apache/2.4.", "HIGH", "Apache HTTP Server DoS via HTTP/2"},
    {"CVE-2024-38475", "http", "Apache", "<=2.4.59", "Apache/2.4.", "MEDIUM", "Apache HTTP Server weakness in mod_proxy"},
    {"CVE-2024-38477", "http", "Apache", "<=2.4.59", "Apache/2.4.", "CRITICAL", "Apache HTTP Server CRLF injection via mod_rewrite"},
    {"CVE-2024-39573", "http", "Apache", "<=2.4.59", "Apache/2.4.", "MEDIUM", "Apache mod_rewrite SSRF"},
    {"CVE-2024-40898", "http", "Apache", "<=2.4.60", "Apache/2.4.", "HIGH", "Apache HTTP Server HTTP/2 request splitting"},
    {"CVE-2024-40725", "http", "Apache", "<=2.4.60", "Apache/2.4.", "HIGH", "Apache HTTP Server HTTP/2 response splitting"},
    {"CVE-2024-41795", "http", "Apache", "<=2.4.61", "Apache/2.4.", "MEDIUM", "Apache HTTP Server file disclosure via mod_rewrite"},
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};

typedef struct {
    char        banner[MAX_BANNER_LEN];
    char        service[64];
    char        product[128];
    int         port;
} BannerEntry;

typedef struct {
    char        cve_id[32];
    char        service[64];
    char        product[128];
    char        severity[16];
    char        description[256];
} CVEMatch;

typedef struct {
    BannerEntry* banners;
    int         banner_count;
    CVEMatch    matches[MAX_BANNERS][MAX_MATCHES];
    int         match_counts[MAX_BANNERS];
    BloomFilter bloom;
    atomic_int  next_idx;
    int         total_matches;
    int         thread_count;
    long long   start_time;
} CVEMatchContext;

static void init_bloom_with_cves(BloomFilter* bf) {
    memset(bf, 0, sizeof(BloomFilter));
    for (int i = 0; CVE_DB[i].cve_id; i++) {
        bloom_add(bf, CVE_DB[i].banner_pattern);
        bloom_add(bf, CVE_DB[i].product);
        bloom_add(bf, CVE_DB[i].service);
        char combined[256];
        snprintf(combined, sizeof(combined), "%s %s", CVE_DB[i].service, CVE_DB[i].product);
        bloom_add(bf, combined);
    }
}

static bool wildcard_match(const char* str, const char* pattern) {
    if (!pattern || !pattern[0]) return true;
    while (*pattern) {
        if (*pattern == '*') {
            while (*(pattern + 1) == '*') pattern++;
            if (!*(pattern + 1)) return true;
            while (*str) {
                if (wildcard_match(str, pattern + 1)) return true;
                str++;
            }
            return false;
        } else if (*pattern == '?' || *str == *pattern) {
            if (!*str) return false;
            str++; pattern++;
        } else {
            return false;
        }
    }
    return !*str;
}

static BloomFilter bloom_global;

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

HOT static void match_banner_cves(BannerEntry* banner, CVEMatch* matches, int* match_count) {
    *match_count = 0;
    if (!banner->banner[0]) return;

    char combined[512];
    snprintf(combined, sizeof(combined), "%s %s %s", banner->service, banner->product, banner->banner);

    if (!bloom_check(&bloom_global, combined) &&
        !bloom_check(&bloom_global, banner->banner) &&
        !bloom_check(&bloom_global, banner->product)) {
        return;
    }

    for (int i = 0; CVE_DB[i].cve_id && *match_count < MAX_MATCHES; i++) {
        bool service_match = banner->service[0] && strstr(CVE_DB[i].service, banner->service);
        bool product_match = banner->product[0] && strstr(banner->product, CVE_DB[i].product);
        if (!service_match && !product_match) continue;

        if (CVE_DB[i].banner_pattern && CVE_DB[i].banner_pattern[0]) {
            if (!strstr(banner->banner, CVE_DB[i].banner_pattern) &&
                !wildcard_match(banner->banner, CVE_DB[i].banner_pattern)) {
                if (CVE_DB[i].version_range && CVE_DB[i].version_range[0]) {
                    bool range_match = false;
                    char* range_copy = strdup(CVE_DB[i].version_range);
                    char* part = strtok(range_copy, ",");
                    while (part) {
                        while (*part == ' ') part++;
                        if (strstr(banner->banner, part)) { range_match = true; break; }
                        part = strtok(NULL, ",");
                    }
                    free(range_copy);
                    if (!range_match) continue;
                } else {
                    continue;
                }
            }
        }

        CVEMatch* m = &matches[*match_count];
        strncpy(m->cve_id, CVE_DB[i].cve_id, sizeof(m->cve_id) - 1);
        strncpy(m->service, CVE_DB[i].service, sizeof(m->service) - 1);
        strncpy(m->product, CVE_DB[i].product, sizeof(m->product) - 1);
        strncpy(m->severity, CVE_DB[i].severity, sizeof(m->severity) - 1);
        strncpy(m->description, CVE_DB[i].description, sizeof(m->description) - 1);
        (*match_count)++;
    }
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <banner_file> [threads]\n", prog);
    fprintf(stderr, "  banner_file - file with JSON banner lines, or '-' for stdin\n");
    fprintf(stderr, "  threads     - worker threads (default: 4)\n");
    fprintf(stderr, "Input format per line: {\"port\":80,\"service\":\"http\",\"product\":\"Apache\",\"banner\":\"Apache/2.4.41 (Ubuntu)\"}\n");
}

static int parse_banner_line(const char* line, BannerEntry* be) {
    memset(be, 0, sizeof(BannerEntry));
    const char* p;

    p = strstr(line, "\"port\":");
    if (p) be->port = atoi(p + 7);

    p = strstr(line, "\"service\":\"");
    if (p) {
        p += 11;
        int i = 0;
        while (*p && *p != '"' && i < (int)sizeof(be->service) - 1) be->service[i++] = *p++;
    }

    p = strstr(line, "\"product\":\"");
    if (p) {
        p += 11;
        int i = 0;
        while (*p && *p != '"' && i < (int)sizeof(be->product) - 1) be->product[i++] = *p++;
    }

    p = strstr(line, "\"banner\":\"");
    if (p) {
        p += 10;
        int i = 0;
        while (*p && *p != '"' && i < (int)sizeof(be->banner) - 1) {
            if (*p == '\\' && *(p + 1)) p++;
            be->banner[i++] = *p++;
        }
    }
    return be->banner[0] ? 1 : 0;
}

HOT static void* cve_match_worker(void* arg) {
    CVEMatchContext* ctx = (CVEMatchContext*)arg;

    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->banner_count) break;

        match_banner_cves(&ctx->banners[idx], ctx->matches[idx], &ctx->match_counts[idx]);

        int mc = ctx->match_counts[idx];
        if (mc > 0) {
            atomic_fetch_add(&ctx->total_matches, mc);
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    int threads = argc > 2 ? atoi(argv[2]) : 4;
    if (threads < 1) threads = 1;
    if (threads > MAX_WORKERS) threads = MAX_WORKERS;

    init_bloom_with_cves(&bloom_global);

    static BannerEntry all_banners[MAX_BANNERS];
    int banner_count = 0;

    FILE* f = strcmp(argv[1], "-") == 0 ? stdin : fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "Failed to open: %s\n", argv[1]);
        return 1;
    }

    char line[16384];
    while (fgets(line, sizeof(line), f) && banner_count < MAX_BANNERS) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (line[0]) {
            if (parse_banner_line(line, &all_banners[banner_count])) {
                banner_count++;
            }
        }
    }
    if (f != stdin) fclose(f);

    if (banner_count == 0) {
        fprintf(stderr, "No valid banners found\n");
        return 1;
    }

    fprintf(stderr, "CVE_MATCHER banners=%d threads=%d cve_db_entries=%zu\n",
        banner_count, threads, sizeof(CVE_DB) / sizeof(CVE_DB[0]));

    CVEMatchContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.banners = all_banners;
    ctx.banner_count = banner_count;
    ctx.thread_count = threads;
    ctx.start_time = now_ms();

    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < threads; i++)
        pthread_create(&workers[i], NULL, cve_match_worker, &ctx);
    for (int i = 0; i < threads; i++)
        pthread_join(workers[i], NULL);

    long long elapsed = now_ms() - ctx.start_time;
    int total_unique = 0;

    for (int i = 0; i < banner_count; i++) {
        for (int j = 0; j < ctx.match_counts[i]; j++) {
            CVEMatch* m = &ctx.matches[i][j];
            printf("{\"cve_id\":\"%s\",\"service\":\"%s\",\"product\":\"%s\",\"severity\":\"%s\",\"description\":\"%s\",\"port\":%d,\"banner\":\"%s\"}\n",
                m->cve_id, m->service, m->product, m->severity, m->description,
                ctx.banners[i].port, ctx.banners[i].banner);
            total_unique++;
        }
    }

    fprintf(stderr, "FINAL:{\"banners\":%d,\"matches\":%d,\"unique_cves\":%d,\"elapsed_ms\":%lld}\n",
        banner_count, ctx.total_matches, total_unique, elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
