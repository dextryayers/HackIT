#ifndef DEAUTH_ENGINE_V1_H
#define DEAUTH_ENGINE_V1_H

#include <stdint.h>

#define DEAUTH_V1_RADIOTAP_LEN 12
#define DEAUTH_V1_FRAME_LEN (DEAUTH_V1_RADIOTAP_LEN + 26)
#define DEAUTH_V1_BURST_SIZE 64
#define DEAUTH_V1_CHANNELS_24 {1,2,3,4,5,6,7,8,9,10,11,12,13}
#define DEAUTH_V1_CHANNELS_5 {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165,169}

typedef struct {
    const char* iface;
    uint8_t bssid[6];
    uint8_t station[6];
    uint16_t reason;
    int targeted;
    volatile int running;
    long long sent;
} DeauthEngineV1;

DeauthEngineV1* deauth_v1_create(const char* iface, const char* bssid, const char* station, uint16_t reason);
void deauth_v1_build_frame(uint8_t* frame, const uint8_t* bssid, const uint8_t* station, uint16_t reason, uint16_t seq);
int deauth_v1_run(DeauthEngineV1* eng);
void deauth_v1_stop(DeauthEngineV1* eng);
void deauth_v1_destroy(DeauthEngineV1* eng);

#endif
