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
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET) {
            struct sockaddr_in server;
            server.sin_family = AF_INET;
            server.sin_port = htons(port);
            server.sin_addr.s_addr = inet_addr(host);

            // Fast connect with timeout
            unsigned long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
            connect(sock, (struct sockaddr*)&server, sizeof(server));
            
            fd_set set;
            FD_ZERO(&set);
            FD_SET(sock, &set);
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            if (select(sock + 1, NULL, &set, NULL, &tv) > 0) {
                // Connected - Send Industrial Probe
                const char* probe = "\r\n\r\n";
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
            closesocket(sock);
        }

        if (strcmp(res->service, "UNKNOWN") == 0) {
            sprintf(res->banner, "[CPP-OFFLINE]: Node %s:%d closed or non-responsive", host, port);
        }

        return res;
    }

    EXPORT void cpp_free_service_result(ServiceResult* res) {
        if (res) {
            free(res->banner);
            free(res->service);
            free(res->version);
            free(res);
        }
    }
}
