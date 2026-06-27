#ifndef DEAUTH_ENGINE_V2_H
#define DEAUTH_ENGINE_V2_H

#include <stdint.h>

#define DEAUTH_V2_MAX_IFACES 8

typedef struct {
    int fd;
    const char* name;
    int channel;
} IfaceEntry;

typedef struct {
    IfaceEntry ifaces[DEAUTH_V2_MAX_IFACES];
    int iface_count;
    uint8_t bssid[6];
    uint8_t station[6];
    uint16_t reason;
    int targeted;
    volatile int running;
    long long total_sent;
} DeauthEngineV2;

DeauthEngineV2* deauth_v2_create(const char* ifaces[], int count, const char* bssid, const char* station, uint16_t reason);
int deauth_v2_run(DeauthEngineV2* eng);
void deauth_v2_stop(DeauthEngineV2* eng);
long long deauth_v2_total(const DeauthEngineV2* eng);
void deauth_v2_destroy(DeauthEngineV2* eng);

#endif
