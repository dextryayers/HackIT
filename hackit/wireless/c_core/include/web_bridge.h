#ifndef HACKIT_WEB_BRIDGE_H
#define HACKIT_WEB_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_APS 256
#define MAX_SSID_LEN 33
#define MAC_STR_LEN 18

typedef struct {
    char bssid[MAC_STR_LEN];
    char ssid[MAX_SSID_LEN];
    int channel;
    int8_t signal_dbm;
    int8_t noise_dbm;
    char encryption[16];
    int clients;
    int is_hidden;
    char vendor[32];
    int wps_supported;
} ScanResult;

typedef struct {
    char attack_type[32];
    char target_bssid[MAC_STR_LEN];
    char target_sta[MAC_STR_LEN];
    int packets_sent;
    int packets_received;
    int handshake_captured;
    char status[64];
    char output_file[256];
    double progress;
} AttackResult;

typedef struct {
    ScanResult results[MAX_APS];
    int count;
    double scan_duration_ms;
    int channels_scanned;
} ScanResults;

int web_scan(const char* interface, int scan_sec, int band_2ghz, int band_5ghz, int band_6ghz);
int web_attack(const char* interface, const char* attack, const char* bssid, const char* station, int count, int timeout_sec);
int web_get_scan_results(ScanResults* out);
int web_get_attack_result(AttackResult* out);
int web_scan_all_channels(const char* interface, int* channels, int num_channels, int dwell_ms);
int web_set_channel(const char* interface, int channel);
int web_send_deauth(const char* interface, const char* bssid, const char* station, int count);
int web_flood_beacon(const char* interface, const char* ssid, int count);
int web_capture_handshake(const char* interface, const char* bssid, int timeout, const char* output);
int web_get_interface_list(char ifaces[][IFNAMSIZ], int* count);
int web_set_monitor_mode(const char* interface, int enable);
int web_get_channel(const char* interface, int* channel);

#ifdef __cplusplus
}
#endif

#endif
