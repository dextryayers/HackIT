#ifndef HACKIT_EVILTWIN_V3_H
#define HACKIT_EVILTWIN_V3_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int eviltwin_v3_start(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel, int captive_port);

void eviltwin_v3_stop(void);

long long eviltwin_v3_sent(void);

#ifdef __cplusplus
}
#endif

#endif
