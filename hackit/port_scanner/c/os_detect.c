#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Expert OS Fingerprinting Engine (C-Core)
 * Based on TCP/IP Stack behavior (TTL, Window Size, DF flag)
 */

typedef struct {
    int ttl;
    int window_size;
    const char* os_name;
    const char* details;
} os_signature_t;

// Signature database for C engine
static os_signature_t signatures[] = {
    {64, 5840, "Linux", "Kernel 2.4/2.6"},
    {64, 29200, "Linux", "Kernel 3.x/4.x/5.x"},
    {64, 5720, "Google Custom", "Google Web Server (GWS)"},
    {64, 65535, "FreeBSD/macOS", "BSD-based Stack"},
    {64, 14600, "Linux", "Ubuntu/Debian"},
    {64, 64240, "Linux", "Android/Mobile"},
    {64, 32768, "Linux", "CentOS/RHEL"},
    {64, 16384, "Apple iOS", "iPhone/iPad"},
    {128, 8192, "Windows", "Windows 7/10/Server 2016"},
    {128, 65535, "Windows", "Windows XP/2003"},
    {128, 16384, "Windows", "Windows Server 2022"},
    {128, 64240, "Windows", "Windows 11"},
    {128, 26280, "Windows", "Windows Server 2019"},
    {255, 4128, "Cisco IOS", "Cisco Router/Switch"},
    {255, 16384, "Solaris", "Solaris 10/11"},
    {255, 14600, "MikroTik", "RouterOS"},
    {255, 65535, "OpenBSD", "Expert Security OS"},
    {255, 512, "F5 Big-IP", "Load Balancer"},
    {255, 60352, "Juniper JunOS", "Enterprise Switch"},
    {0, 0, NULL, NULL}
};

typedef struct {
    const char* os_name;
    const char* details;
    float confidence;
} detection_result_t;

detection_result_t c_expert_detect_os_advanced(int ttl, int window_size) {
    detection_result_t result = {"Unknown OS", "Unknown", 0.0f};
    int i = 0;
    int closest_ttl_diff = 1000;
    
    while (signatures[i].os_name != NULL) {
        // Exact Match
        if (ttl == signatures[i].ttl && (window_size == 0 || window_size == signatures[i].window_size)) {
            result.os_name = signatures[i].os_name;
            result.details = signatures[i].details;
            result.confidence = (window_size > 0) ? 0.95f : 0.80f;
            return result;
        }

        // Closest TTL match
        int diff = abs(ttl - signatures[i].ttl);
        if (diff < closest_ttl_diff) {
            closest_ttl_diff = diff;
            result.os_name = signatures[i].os_name;
            result.details = signatures[i].details;
            result.confidence = 0.60f - (diff * 0.05f);
            if (result.confidence < 0.1f) result.confidence = 0.1f;
        }
        i++;
    }

    // Default heuristics if confidence is low
    if (result.confidence < 0.5f) {
        if (ttl <= 64) {
            result.os_name = "Linux/Unix (Generic)";
            result.confidence = 0.5f;
        } else if (ttl <= 128) {
            result.os_name = "Windows (Generic)";
            result.confidence = 0.5f;
        } else if (ttl <= 255) {
            result.os_name = "Network Device (Generic)";
            result.confidence = 0.5f;
        }
    }
    
    return result;
}

#ifndef OS_DETECT_LIBRARY
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Unknown OS|Unknown|0.0\n");
        return 0;
    }

    int ttl = atoi(argv[2]);
    int window_size = (argc > 3) ? atoi(argv[3]) : 0;

    detection_result_t res = c_expert_detect_os_advanced(ttl, window_size);
    printf("%s|%s|%.2f\n", res.os_name, res.details, res.confidence);
    return 0;
}
#endif
