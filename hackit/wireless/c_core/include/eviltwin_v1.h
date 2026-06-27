#ifndef HACKIT_EVILTWIN_V1_H
#define HACKIT_EVILTWIN_V1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int eviltwin_v1_start(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel);

void eviltwin_v1_stop(void);

long long eviltwin_v1_sent(void);

#ifdef __cplusplus
}
#endif

#endif
