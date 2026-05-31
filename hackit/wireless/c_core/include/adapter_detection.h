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
} c_wifi_adapter_t;

int hackit_c_detect_adapters(c_wifi_adapter_t* out_adapters, int max_adapters);

#endif // HACKIT_ADAPTER_DETECTION_H
