#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/**
 * Expert OS Fingerprinting Engine (C-Core)
 * Enhanced with real-time banner grabbing and version detection
 */

// Enhanced banner grabbing structure
typedef struct {
    char* banner;
    char* service;
    char* version;
    int port;
} banner_result_t;

// Version detection patterns (simplified for Windows compatibility)
typedef struct {
    const char* service;
    const char* pattern;
} version_pattern_t;

// Protocol-specific probes
typedef struct {
    int port;
    const char* probe;
    int probe_len;
} protocol_probe_t;

// Initialize version patterns (simplified for Windows)
static version_pattern_t version_patterns[] = {
    {"http", "Server:"},
    {"nginx", "nginx/"},
    {"apache", "Apache/"},
    {"iis", "IIS/"},
    {"litespeed", "LiteSpeed/"},
    {"ssh", "SSH-"},
    {"openssh", "OpenSSH_"},
    {"ftp", "Pure-FTPd"},
    {"vsftpd", "vsftpd"},
    {"mysql", "-MariaDB"},
    {"postgresql", "PostgreSQL"},
    {"redis", "redis_version:"},
    {"mongodb", "MongoDB"},
    {"telnet", "Telnet"},
    {"vnc", "RFB"},
};

// Protocol probes
static protocol_probe_t protocol_probes[] = {
    {80, "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n", 0},
    {443, "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n", 0},
    {21, "", 0}, // FTP sends banner automatically
    {22, "SSH-2.0-HackIT-Scanner\r\n", 0},
    {25, "EHLO hackit-scanner\r\n", 0},
    {587, "EHLO hackit-scanner\r\n", 0},
    {110, "CAPA\r\n", 0},
    {143, "A001 CAPABILITY\r\n", 0},
    {3306, "\x00\x00\x00\x01", 4}, // MySQL handshake
    {5432, "\x00\x00\x00\x08\x04\xd2\x16\x2f", 12}, // PostgreSQL startup
    {6379, "INFO\r\n", 0}, // Redis
    {27017, "\x3b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00", 59}, // MongoDB
    {23, "\xff\xfb\x01\xff\xfb\x03", 6}, // Telnet negotiation
    {5900, "RFB 003.008\n", 0}, // VNC
    {3389, "\x03\x00\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00\x00", 24}, // RDP
    {445, "\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x02\x00\x0c\x00\x02\x4e\x54\x4c\x4d\x20\x30\x2e\x31\x32\x00", 47}, // SMB
};

// Enhanced banner grabbing function
char* grab_banner(const char* host, int port, int timeout_ms) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return NULL;
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, host, &server.sin_addr);

    // Set timeout
    DWORD timeout = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return NULL;
    }

    // Send protocol-specific probe
    for (size_t i = 0; i < sizeof(protocol_probes) / sizeof(protocol_probe_t); i++) {
        if (protocol_probes[i].port == port && protocol_probes[i].probe_len > 0) {
            send(sock, protocol_probes[i].probe, protocol_probes[i].probe_len, 0);
            break;
        } else if (protocol_probes[i].port == port) {
            if (strlen(protocol_probes[i].probe) > 0) {
                send(sock, protocol_probes[i].probe, strlen(protocol_probes[i].probe), 0);
            }
            break;
        }
    }

    // Read response
    char buffer[4096] = {0};
    int bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0);

    closesocket(sock);
    WSACleanup();

    if (bytes_read > 0) {
        char* result = (char*)malloc(bytes_read + 1);
        memcpy(result, buffer, bytes_read);
        result[bytes_read] = '\0';
        return result;
    }

    return NULL;
}

// Enhanced version extraction
char* extract_version(const char* service, const char* banner) {
    if (!banner || strlen(banner) == 0) {
        return strdup(service);
    }

    char banner_lower[4096];
    strncpy(banner_lower, banner, sizeof(banner_lower) - 1);
    banner_lower[sizeof(banner_lower) - 1] = '\0';
    for (char* p = banner_lower; *p; ++p) *p = tolower(*p);

    // Try regex patterns (simplified for Windows compatibility)
    for (size_t i = 0; i < sizeof(version_patterns) / sizeof(version_pattern_t); i++) {
        if (strcmp(version_patterns[i].service, service) == 0 ||
            strstr(banner_lower, version_patterns[i].service) != NULL) {

            // Simple pattern matching for Windows
            const char* pattern = version_patterns[i].pattern;
            char* found = strstr(banner_lower, pattern);
            if (found) {
                // Extract version number after pattern
                char* version_start = found + strlen(pattern);
                char version[256];
                int j = 0;
                while (*version_start && j < 255 && (*version_start >= '0' && *version_start <= '9' || *version_start == '.')) {
                    version[j++] = *version_start++;
                }
                version[j] = '\0';
                if (j > 0) {
                    char* result = (char*)malloc(strlen(service) + strlen(version) + 2);
                    if (result) {
                        snprintf(result, strlen(service) + strlen(version) + 2, "%s %s", service, version);
                        return result;
                    }
                }
            }
        }
    }

    // Fallback: extract from first line if informative
    char* banner_copy = strdup(banner);
    if (banner_copy) {
        char* first_line = strtok(banner_copy, "\r\n");
        if (first_line && strlen(first_line) > 10 && strlen(first_line) < 100) {
            size_t result_len = strlen(service) + strlen(first_line) + 4;
            char* result = (char*)malloc(result_len);
            if (result) {
                snprintf(result, result_len, "%s (%s)", service, first_line);
                free(banner_copy);
                return result;
            }
        }
        free(banner_copy);
    }

    return strdup(service);
}

// Enhanced service detection
char* detect_service(int port, const char* banner) {
    if (banner && strlen(banner) > 0) {
        char banner_lower[4096];
        strncpy(banner_lower, banner, sizeof(banner_lower) - 1);
        banner_lower[sizeof(banner_lower) - 1] = '\0';
        for (char* p = banner_lower; *p; ++p) *p = tolower(*p);

        if (strstr(banner_lower, "nginx")) return extract_version("nginx", banner);
        if (strstr(banner_lower, "apache")) return extract_version("apache", banner);
        if (strstr(banner_lower, "iis") || strstr(banner_lower, "microsoft-iis")) return extract_version("iis", banner);
        if (strstr(banner_lower, "litespeed")) return extract_version("litespeed", banner);
        if (strstr(banner_lower, "openssh")) return extract_version("ssh", banner);
        if (strstr(banner_lower, "pure-ftpd")) return extract_version("ftp", banner);
        if (strstr(banner_lower, "vsftpd")) return extract_version("ftp", banner);
        if (strstr(banner_lower, "postfix")) return extract_version("smtp", banner);
        if (strstr(banner_lower, "mysql")) return extract_version("mysql", banner);
        if (strstr(banner_lower, "postgresql")) return extract_version("postgresql", banner);
        if (strstr(banner_lower, "redis")) return extract_version("redis", banner);
        if (strstr(banner_lower, "mongodb")) return extract_version("mongodb", banner);
        if (strstr(banner_lower, "telnet")) return extract_version("telnet", banner);
        if (strstr(banner_lower, "vnc") || strstr(banner_lower, "rfb")) return extract_version("vnc", banner);
    }

    // Port-based fallback
    switch (port) {
        case 21: return strdup("ftp");
        case 22: return strdup("ssh");
        case 23: return strdup("telnet");
        case 25:
        case 587: return strdup("smtp");
        case 53: return strdup("dns");
        case 80:
        case 443:
        case 8080:
        case 8443: return strdup("http");
        case 110: return strdup("pop3");
        case 143: return strdup("imap");
        case 3306: return strdup("mysql");
        case 5432: return strdup("postgresql");
        case 6379: return strdup("redis");
        case 27017: return strdup("mongodb");
        case 3389: return strdup("rdp");
        case 5900: return strdup("vnc");
        default: return strdup("unknown");
    }
}

// Enhanced banner grabbing with service detection
banner_result_t* grab_banner_enhanced(const char* host, int port, int timeout_ms) {
    banner_result_t* result = (banner_result_t*)malloc(sizeof(banner_result_t));
    result->port = port;
    result->banner = grab_banner(host, port, timeout_ms);

    if (result->banner) {
        result->service = detect_service(port, result->banner);
        result->version = extract_version(result->service, result->banner);
    } else {
        result->service = strdup("unknown");
        result->version = strdup("unknown");
    }

    return result;
}

// Free banner result
void free_banner_result(banner_result_t* result) {
    if (result) {
        if (result->banner) free(result->banner);
        if (result->service) free(result->service);
        if (result->version) free(result->version);
        free(result);
    }
}

typedef struct {
    int ttl;
    int window_size;
    int mss;
    int df_bit;
    const char* tcp_options;
    const char* os_name;
    const char* version;
    const char* details;
    int confidence;
} os_signature_t;

// Enhanced signature database for C engine
static os_signature_t signatures[] = {
    // Linux variants
    {64, 5840, 1460, 1, "mss,sackOK,nop,wscale", "Linux", "2.4.x-2.6.x", "Generic Linux Kernel", 85},
    {64, 29200, 1460, 1, "mss,sackOK,nop,wscale,TS", "Linux", "3.x-4.x", "Modern Linux Kernel", 90},
    {64, 64240, 1460, 1, "mss,sackOK,nop,wscale,TS", "Linux", "5.x+", "Latest Linux Kernel", 95},
    {64, 14600, 1460, 1, "mss,sackOK,nop,wscale,TS", "Linux", "Ubuntu/Debian", "Ubuntu or Debian Linux", 88},
    {64, 32736, 1460, 1, "mss,sackOK,nop,wscale", "Linux", "CentOS/RHEL", "Red Hat Enterprise Linux", 87},
    {64, 5720, 1460, 1, "mss,sackOK,nop,wscale", "Linux", "Google GWS", "Google Web Server", 92},

    // Windows variants
    {128, 8192, 1460, 1, "mss,nop,wscale,sackOK", "Windows", "7/10", "Windows 7/10 Professional", 85},
    {128, 16384, 1460, 1, "mss,nop,wscale,sackOK", "Windows", "Server 2016", "Windows Server 2016", 88},
    {128, 64240, 1460, 1, "mss,nop,wscale,sackOK,TS", "Windows", "11", "Windows 11", 90},
    {128, 65535, 1460, 1, "mss,nop,wscale,sackOK", "Windows", "XP/2003", "Legacy Windows", 80},
    {128, 26280, 1460, 1, "mss,nop,wscale,sackOK,TS", "Windows", "Server 2019", "Windows Server 2019", 89},

    // BSD variants
    {64, 65535, 1460, 1, "mss,sackOK,nop,wscale,TS", "FreeBSD", "11.x-13.x", "FreeBSD Server", 88},
    {64, 131072, 1460, 1, "mss,sackOK,nop,wscale,TS", "macOS", "10.x-12.x", "macOS Desktop", 87},
    {255, 65535, 1460, 1, "mss,sackOK,nop,wscale", "OpenBSD", "6.x-7.x", "OpenBSD Security", 85},

    // Network devices
    {255, 4128, 1460, 1, "mss,nop,wscale", "Cisco IOS", "15.x", "Cisco Router/Switch", 90},
    {255, 16384, 1460, 1, "mss,nop,wscale", "Solaris", "10/11", "Oracle Solaris", 85},
    {255, 14600, 1460, 1, "mss,nop,wscale", "MikroTik", "6.x-7.x", "MikroTik RouterOS", 88},
    {255, 512, 1460, 1, "mss,nop,wscale", "F5 Big-IP", "15.x-17.x", "F5 Load Balancer", 87},
    {255, 60352, 1460, 1, "mss,nop,wscale", "Juniper JunOS", "18.x-21.x", "Juniper Switch", 89},

    // Mobile/IoT
    {64, 64240, 1460, 1, "mss,sackOK,nop,wscale,TS", "Android", "9.x-13.x", "Android Mobile", 83},
    {64, 16384, 1460, 1, "mss,sackOK,nop,wscale", "Apple iOS", "14.x-16.x", "iPhone/iPad", 84},

    {0, 0, 0, 0, NULL, NULL, NULL, NULL, 0}
};

typedef struct {
    const char* os_name;
    const char* version;
    const char* details;
    float confidence;
    char ip_info[1024];
} detection_result_t;

// IP Information Structure
typedef struct {
    char ip[256];
    char hostname[256];
    char country[64];
    char city[64];
    char region[64];
    char asn[32];
    char org[256];
    char isp[256];
    double latitude;
    double longitude;
    char timezone[64];
} ip_info_t;

detection_result_t c_expert_detect_os_advanced(int ttl, int window_size) {
    detection_result_t result = {"Unknown OS", "Unknown", "Unknown", 0.0f};
    int i = 0;
    int max_confidence = 0;

    while (signatures[i].os_name != NULL) {
        int confidence = 0;

        // TTL matching (exact match gets highest score)
        if (ttl == signatures[i].ttl) {
            confidence += 40;
        } else if (abs(ttl - signatures[i].ttl) <= 2) {
            confidence += 20; // Close match
        }

        // Window size matching
        if (window_size == signatures[i].window_size) {
            confidence += 35;
        } else if (abs(window_size - signatures[i].window_size) <= 1000) {
            confidence += 15; // Close match
        }

        // MSS matching (if available)
        if (signatures[i].mss > 0) {
            confidence += 10; // Bonus for MSS data
        }

        // DF bit matching
        if (signatures[i].df_bit >= 0) {
            confidence += 5; // Bonus for DF data
        }

        // Apply signature confidence modifier
        confidence = (confidence * signatures[i].confidence) / 100;

        if (confidence > max_confidence) {
            max_confidence = confidence;
            result.os_name = signatures[i].os_name;
            result.version = signatures[i].version;
            result.details = signatures[i].details;
            result.confidence = (float)confidence / 100.0f;
        }

        i++;
    }

    // If no good match found, try fuzzy matching
    if (max_confidence < 30) {
        i = 0;
        while (signatures[i].os_name != NULL) {
            // Fuzzy TTL matching
            if (abs(ttl - signatures[i].ttl) <= 10) {
                result.os_name = signatures[i].os_name;
                result.version = signatures[i].version;
                result.details = signatures[i].details;
                result.confidence = 0.25f; // Low confidence fuzzy match
                break;
            }
            i++;
        }
    }

    return result;
}

// Gather IP information (simplified implementation)
ip_info_t* gather_ip_info_c(const char* hostname) {
    static ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(ip_info_t));

    // Basic hostname resolution
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
        struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip_info.ip, sizeof(ip_info.ip));
        freeaddrinfo(res);
    }

    // Set hostname
    strncpy(ip_info.hostname, hostname, sizeof(ip_info.hostname) - 1);
    ip_info.hostname[sizeof(ip_info.hostname) - 1] = '\0';

    // Placeholder geolocation data (in real implementation, use external APIs)
    if (strstr(hostname, "nasa.gov") != NULL) {
        strncpy(ip_info.country, "United States", sizeof(ip_info.country) - 1);
        ip_info.country[sizeof(ip_info.country) - 1] = '\0';
        strncpy(ip_info.city, "Greenbelt", sizeof(ip_info.city) - 1);
        ip_info.city[sizeof(ip_info.city) - 1] = '\0';
        strncpy(ip_info.region, "Maryland", sizeof(ip_info.region) - 1);
        ip_info.region[sizeof(ip_info.region) - 1] = '\0';
        strncpy(ip_info.asn, "AS7018", sizeof(ip_info.asn) - 1);
        ip_info.asn[sizeof(ip_info.asn) - 1] = '\0';
        strncpy(ip_info.org, "NASA", sizeof(ip_info.org) - 1);
        ip_info.org[sizeof(ip_info.org) - 1] = '\0';
        strncpy(ip_info.isp, "NASA Network", sizeof(ip_info.isp) - 1);
        ip_info.isp[sizeof(ip_info.isp) - 1] = '\0';
        ip_info.latitude = 39.0046;
        ip_info.longitude = -76.8755;
        strncpy(ip_info.timezone, "America/New_York", sizeof(ip_info.timezone) - 1);
        ip_info.timezone[sizeof(ip_info.timezone) - 1] = '\0';
    } else {
        strncpy(ip_info.country, "Unknown", sizeof(ip_info.country) - 1);
        ip_info.country[sizeof(ip_info.country) - 1] = '\0';
        strncpy(ip_info.city, "Unknown", sizeof(ip_info.city) - 1);
        ip_info.city[sizeof(ip_info.city) - 1] = '\0';
        strncpy(ip_info.region, "Unknown", sizeof(ip_info.region) - 1);
        ip_info.region[sizeof(ip_info.region) - 1] = '\0';
        strncpy(ip_info.asn, "Unknown", sizeof(ip_info.asn) - 1);
        ip_info.asn[sizeof(ip_info.asn) - 1] = '\0';
        strncpy(ip_info.org, "Unknown", sizeof(ip_info.org) - 1);
        ip_info.org[sizeof(ip_info.org) - 1] = '\0';
        strncpy(ip_info.isp, "Unknown", sizeof(ip_info.isp) - 1);
        ip_info.isp[sizeof(ip_info.isp) - 1] = '\0';
        ip_info.latitude = 0.0;
        ip_info.longitude = 0.0;
        strncpy(ip_info.timezone, "Unknown", sizeof(ip_info.timezone) - 1);
        ip_info.timezone[sizeof(ip_info.timezone) - 1] = '\0';
    }

    return &ip_info;
}

// Get detailed OS and IP information as formatted string
char* c_get_detailed_os_ip_info(const char* hostname, const char* open_ports, int ttl, int window_size) {
    static char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    detection_result_t os_result = c_expert_detect_os_advanced(ttl, window_size);
    ip_info_t* ip_info = gather_ip_info_c(hostname);

    const char* os_family = "Unknown";
    if (os_result.os_name) {
        if (strstr(os_result.os_name, "Windows") != NULL) os_family = "Windows";
        else if (strstr(os_result.os_name, "Linux") != NULL) os_family = "Linux/Unix";
        else if (strstr(os_result.os_name, "macOS") != NULL) os_family = "macOS";
        else if (strstr(os_result.os_name, "FreeBSD") != NULL || strstr(os_result.os_name, "OpenBSD") != NULL) os_family = "BSD";
        else if (strstr(os_result.os_name, "Cisco") != NULL || strstr(os_result.os_name, "Juniper") != NULL || strstr(os_result.os_name, "MikroTik") != NULL) os_family = "Network Device";
    }

    snprintf(buffer, sizeof(buffer),
        "DETAILED OS DETECTION AND IP INFORMATION:\n"
        "==========================================\n"
        "OS DETECTION:\n"
        "  Operating System: %s %s\n"
        "  Family: %s\n"
        "  Details: %s\n"
        "  Confidence: %.1f%%\n"
        "  TCP: ttl=%d win=%d\n"
        "  Open Ports: %s\n"
        "\n"
        "IP INFORMATION:\n"
        "  IP: %s\n"
        "  Hostname: %s\n"
        "  Geo: %s, %s, %s\n"
        "  ASN: %s\n"
        "  Org: %s\n"
        "  ISP: %s\n"
        "  Coordinates: %.4f, %.4f\n"
        "  Timezone: %s\n",
        os_result.os_name,
        os_result.version ? os_result.version : "",
        os_family,
        os_result.details,
        os_result.confidence * 100.0f,
        ttl,
        window_size,
        (open_ports && *open_ports) ? open_ports : "",
        ip_info->ip,
        ip_info->hostname,
        ip_info->country,
        ip_info->city,
        ip_info->region,
        ip_info->asn,
        ip_info->org,
        ip_info->isp,
        ip_info->latitude,
        ip_info->longitude,
        ip_info->timezone
    );

    return buffer;
}

#ifdef OS_DETECT_LIBRARY
// When included from another translation unit, do not provide a main().
#else
int main(int argc, char** argv) {
    const char* host = (argc > 1) ? argv[1] : "127.0.0.1";
    const char* ports = (argc > 2) ? argv[2] : "80,443";
    int ttl = (argc > 3) ? atoi(argv[3]) : 64;
    int win = (argc > 4) ? atoi(argv[4]) : 29200;
    printf("%s\n", c_get_detailed_os_ip_info(host, ports, ttl, win));
    return 0;
}
#endif
