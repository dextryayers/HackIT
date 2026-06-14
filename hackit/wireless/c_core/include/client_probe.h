#include <stddef.h>
#ifndef HACKIT_CLIENT_PROBE_H
#define HACKIT_CLIENT_PROBE_H

#include <stdbool.h>
#include <stdint.h>

int hackit_capture_probe_requests(const char* iface, int duration_ms, void (*callback)(const uint8_t*, size_t));
int hackit_parse_probe_request(const uint8_t* frame, size_t len, char* ssid_out, size_t ssid_out_len, uint8_t* sta_mac);
int hackit_get_connected_clients(const char* iface, const char* bssid, char** clients_out, int max_clients);

#endif // HACKIT_CLIENT_PROBE_H
