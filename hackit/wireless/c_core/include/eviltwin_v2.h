#ifndef HACKIT_EVILTWIN_V2_H
#define HACKIT_EVILTWIN_V2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int eviltwin_v2_start(const char* iface, const char* ssids[], int count, uint8_t channel);

void eviltwin_v2_stop(void);

long long eviltwin_v2_sent(void);

#ifdef __cplusplus
}
#endif

#endif
