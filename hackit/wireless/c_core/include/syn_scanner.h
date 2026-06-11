#ifndef HACKIT_SYN_SCANNER_H
#define HACKIT_SYN_SCANNER_H

#include <stdint.h>
#include <stdbool.h>

int hackit_syn_scan_port(const char* host, int port, int timeout_ms, bool* filtered_out);

int hackit_syn_scan_ports(const char* host, const int* ports, int port_count,
                          int timeout_ms, int threads, int rate_limit,
                          bool* open_results, int max_results);

bool hackit_raw_socket_available(void);

#endif
