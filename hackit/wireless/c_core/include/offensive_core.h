#ifndef HACKIT_OFFENSIVE_CORE_H
#define HACKIT_OFFENSIVE_CORE_H

#include <stdint.h>
#include <stddef.h>

#define MAX_SSID_LEN 32
#define MAX_BSSID_LEN 6
#define MAX_IE_LEN 256
#define MAX_CLIENTS 1024

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    int8_t signal;
    uint16_t capabilities;
    uint8_t ie_data[MAX_IE_LEN];
    int ie_len;
} hackit_ap_info;

typedef struct {
    uint8_t client_mac[6];
    uint8_t bssid[6];
    int8_t signal;
    uint16_t seq;
    int probe_count;
} hackit_client_info;

typedef struct {
    uint8_t target_bssid[6];
    uint8_t target_sta[6];
    int reason_code;
    int count;
    int interval_ms;
} hackit_deauth_params;

typedef struct {
    char ssids[64][33];
    int ssid_count;
    uint8_t bssid[6];
    uint8_t channel;
    int count;
    int interval_ms;
    uint16_t capabilities;
} hackit_beacon_flood_params;

typedef struct {
    char ssids[64][33];
    int ssid_count;
    uint8_t src_mac[6];
    int count;
    int interval_ms;
} hackit_probe_flood_params;

typedef struct {
    uint8_t target_bssid[6];
    int timeout_sec;
    char output_file[256];
    int deauth;
} hackit_handshake_params;

typedef struct {
    uint8_t target_bssid[6];
    int timeout_sec;
    char output_file[256];
} hackit_pmkid_params;

int hackit_harvest_pmkid(const char* iface, hackit_pmkid_params* params);
int hackit_send_deauth(const char* iface, hackit_deauth_params* params);
int hackit_flood_beacon(const char* iface, hackit_beacon_flood_params* params);
int hackit_flood_probe(const char* iface, hackit_probe_flood_params* params);
int hackit_find_hidden_ssid(const char* iface, int timeout_sec, hackit_ap_info* results, int* count);
int hackit_hunt_clients(const char* iface, int timeout_sec, hackit_client_info* results, int* count);
int hackit_capture_handshake(const char* iface, hackit_handshake_params* params);

#endif
