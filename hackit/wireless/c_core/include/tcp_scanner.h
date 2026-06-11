#ifndef HACKIT_TCP_SCANNER_H
#define HACKIT_TCP_SCANNER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#define MAX_SCANNER_BANNER 2048
#define MAX_SCANNER_PORTS 65536

typedef enum { SCAN_STATE_OPEN, SCAN_STATE_CLOSED, SCAN_STATE_FILTERED } ScannerPortState;

typedef struct {
    int port;
    ScannerPortState state;
    char service[64];
    char product[128];
    char version[64];
    char banner[MAX_SCANNER_BANNER];
    char os_hint[64];
    double rtt_ms;
} ScannerPortResult;

int hackit_parse_ports(const char* range, int* out, int max);

int hackit_scan_tcp_port(const char* host, int port, int timeout_ms, ScannerPortResult* result);

typedef void (*ScanProgressFn)(int current, int total, const ScannerPortResult* result);
int hackit_scan_tcp_ports(const char* host, const int* ports, int port_count,
                          int timeout_ms, int threads, bool grab_banners,
                          ScannerPortResult* results, int max_results,
                          ScanProgressFn callback);

const char* hackit_port_service_name(int port);

#endif
