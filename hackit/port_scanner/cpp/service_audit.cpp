#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string_view>
#include <memory>
#include <unordered_map>

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


#endif

// Export for Windows DLL
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    struct ServiceResult {
        char* banner;
        char* service;
        char* version;
        int port;
    };

    EXPORT ServiceResult* cpp_scan_service(const char* host, int port, int timeout_ms) {
        ServiceResult* res = (ServiceResult*)malloc(sizeof(ServiceResult));
        res->banner = (char*)malloc(1024);
        res->service = (char*)malloc(64);
        res->version = (char*)malloc(64);
        res->port = port;

        memset(res->banner, 0, 1024);
        strcpy(res->service, "UNKNOWN");
        strcpy(res->version, "N/A");

        // Industrial Protocol Audit (Surgical Implementation)
        int sock = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != (-1)) {
            struct sockaddr_in server;
            server.sin_family = AF_INET;
            server.sin_port = htons(port);
            server.sin_addr.s_addr = inet_addr(host);

            // Fast connect with timeout
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
            connect(sock, (struct sockaddr*)&server, sizeof(server));
            
            struct pollfd pfd;
            pfd.fd = sock;
            pfd.events = POLLOUT;
            int prc = poll(&pfd, 1, timeout_ms);
            fcntl(sock, F_SETFL, flags);

            if (prc > 0) {
                // Connected - Send Industrial Probe
                constexpr char* probe = "\r\n\r\n";
                if (port == 80 || port == 8080) probe = "HEAD / HTTP/1.0\r\n\r\n";
                else if (port == 21) probe = "HELP\r\n";
                
                send(sock, probe, strlen(probe), 0);
                
                char buffer[1024];
                memset(buffer, 0, sizeof(buffer));
                int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (bytes > 0) {
                    strncpy(res->banner, buffer, 1023);
                    
                    // Surgical Service Mapping
                    if (strstr(buffer, "HTTP/")) strcpy(res->service, "http");
                    else if (strstr(buffer, "SSH-")) strcpy(res->service, "ssh");
                    else if (strstr(buffer, "MySQL")) strcpy(res->service, "mysql");
                    else if (strstr(buffer, "220 ")) strcpy(res->service, "ftp/smtp");
                }
            }
            close(sock);
        }

        if (strcmp(res->service, "UNKNOWN") == 0) {
            sprintf(res->banner, "[CPP-OFFLINE]: Node %s:%d closed or non-responsive", host, port);
        }

        return res;
    }

    EXPORT void cpp_free_service_result(ServiceResult* res) noexcept {
        if (res) {
            free(res->banner);
            free(res->service);
            free(res->version);
            free(res);
        }
    }
}
