#ifndef HACKIT_ADAPTER_DETECTION_H
#define HACKIT_ADAPTER_DETECTION_H

#include <stdbool.h>

typedef struct {
    char name[32];
    char mac[18];
    char driver[32];
    int channel;
    int signal_dbm;
    bool is_monitor;
    bool supports_2ghz;
    bool supports_5ghz;
    int max_tx_power;
} c_wifi_adapter_t;

typedef struct {
    int channel;
    int frequency_mhz;
    int band; // 0=2.4GHz, 1=5GHz
    int max_power_dbm;
} c_channel_info_t;

int hackit_c_detect_adapters(c_wifi_adapter_t* out_adapters, int max_adapters);
int hackit_c_get_supported_channels(const char* iface_name, c_channel_info_t* out_channels, int max_channels);
bool hackit_c_set_channel(const char* iface_name, int channel);
bool hackit_c_set_monitor_mode(const char* iface_name);
bool hackit_c_set_managed_mode(const char* iface_name);
int hackit_c_get_current_channel(const char* iface_name);

#endif // HACKIT_ADAPTER_DETECTION_H
