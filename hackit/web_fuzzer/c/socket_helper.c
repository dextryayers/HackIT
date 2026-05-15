#include "socket_helper.h"
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

void init_ws() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

void cleanup_ws() {
    WSACleanup();
}

SOCKET create_connection(const char* ip, int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return INVALID_SOCKET;
    }
    return s;
}
