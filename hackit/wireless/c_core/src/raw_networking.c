#include "raw_networking.h"
#include <stdlib.h>
#include <stdio.h>

raw_socket_t* hackit_net_open_raw(const char* interface_name) {
    printf("[C-RAW-NET] Opening raw socket on %s (Mock)\n", interface_name);
    raw_socket_t* sock = (raw_socket_t*)malloc(sizeof(raw_socket_t));
    if (sock) {
        sock->socket_fd = 999;
        sock->is_raw = true;
    }
    return sock;
}

bool hackit_net_inject_packet(raw_socket_t* sock, const uint8_t* payload, size_t len) {
    if (!sock) return false;
    printf("[C-RAW-NET] Injecting %zu bytes of raw payload into FD %d\n", len, sock->socket_fd);
    return true;
}

void hackit_net_close(raw_socket_t* sock) {
    if (sock) {
        printf("[C-RAW-NET] Closing raw socket FD %d\n", sock->socket_fd);
        free(sock);
    }
}
