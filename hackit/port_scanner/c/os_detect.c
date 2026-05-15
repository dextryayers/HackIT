#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Export for Windows DLL
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

typedef struct {
    char name[64];
    char version[64];
    int confidence;
    int ttl;
    int window_size;
} OSInfoResult;

// Heuristic OS Fingerprinting based on TCP/IP stack behavior
EXPORT char* c_get_detailed_os_ip_info(const char* host, const char* open_ports, int ttl_obs, int window_obs) {
    char* report = (char*)malloc(2048);
    memset(report, 0, 2048);

    const char* os_name = "Unknown";
    const char* os_ver = "N/A";
    int confidence = 0;

    // TTL Analysis (Industrial Grade Heuristics)
    if (ttl_obs > 0) {
        if (ttl_obs <= 64) {
            os_name = "Linux/Unix";
            confidence = 60;
            if (window_obs == 5840 || window_obs == 29200) {
                os_ver = "Linux 2.6.x - 5.x";
                confidence = 85;
            } else if (window_obs == 64240 || window_obs == 65535) {
                os_ver = "Modern Linux (5.x+) / FreeBSD";
                confidence = 90;
            } else if (window_obs == 16384 || window_obs == 14600) {
                os_ver = "Embedded Linux / Android";
                confidence = 75;
            }
        } else if (ttl_obs <= 128) {
            os_name = "Windows";
            confidence = 60;
            if (window_obs == 8192 || window_obs == 64240) {
                os_ver = "Windows 7/10/11 / Server 2016+";
                confidence = 95;
            } else if (window_obs == 65535) {
                os_ver = "Legacy Windows (XP/2003)";
                confidence = 80;
            } else if (window_obs == 16384) {
                os_ver = "Windows Vista/2008";
                confidence = 85;
            }
        } else if (ttl_obs <= 255) {
            os_name = "Infrastructure";
            if (window_obs == 4128 || window_obs == 512) {
                os_ver = "Cisco IOS / RouterOS";
                confidence = 85;
            } else {
                os_ver = "Generic Network Node";
                confidence = 65;
            }
        }
    }

    // Adjust based on open ports
    if (strstr(open_ports, "445") || strstr(open_ports, "3389")) {
        if (strcmp(os_name, "Windows") == 0) confidence += 10;
        else {
            os_name = "Windows (Heuristic)";
            confidence = 50;
        }
    } else if (strstr(open_ports, "22")) {
        if (strcmp(os_name, "Linux/Unix") == 0) confidence += 10;
    }

    if (confidence > 100) confidence = 100;

    sprintf(report, 
        "[C-CORE] DETECTED OS: %s\n"
        "[C-CORE] VERSION     : %s\n"
        "[C-CORE] CONFIDENCE  : %d%%\n"
        "[C-CORE] TTL METRIC  : %d\n"
        "[C-CORE] WIN METRIC  : %d\n"
        "[C-CORE] TARGET NODE : %s",
        os_name, os_ver, confidence, ttl_obs, window_obs, host
    );

    return report;
}

EXPORT void c_free_string(char* s) {
    free(s);
}
