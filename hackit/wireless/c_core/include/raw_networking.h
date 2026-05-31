#ifndef HACKIT_RAW_NETWORKING_H
#define HACKIT_RAW_NETWORKING_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Mock structures for raw sockets (libc/libnet)
typedef struct {
    int socket_fd;
    bool is_raw;
} raw_socket_t;

raw_socket_t* hackit_net_open_raw(const char* interface_name);
bool hackit_net_inject_packet(raw_socket_t* sock, const uint8_t* payload, size_t len);
void hackit_net_close(raw_socket_t* sock);

#endif
