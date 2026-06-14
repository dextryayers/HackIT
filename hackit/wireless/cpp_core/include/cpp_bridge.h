#ifndef HACKIT_CPP_BRIDGE_H
#define HACKIT_CPP_BRIDGE_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char attack_id[64];
    char status[32];
    double progress;
    int packets_sent;
    int packets_received;
    char details[512];
} AttackStatus;

typedef struct {
    char bssid[18];
    int signal_dbm;
    long timestamp_ms;
} SignalSample;

typedef struct {
    double packets_per_sec;
    int total_packets;
    double channel_util_pct;
    int active_bssids;
    int active_clients;
} MonitorStats;

const char* orchestrator_launch(const char* name, const char* params_json);
int orchestrator_stop(const char* id);
const char* orchestrator_get_status(void);
const char* orchestrator_get_results(const char* id);
const char* orchestrator_multi_engine(const char* engines_json, const char* params_json);

const char* craft_deauth(const char* bssid, const char* station, int reason);
const char* craft_beacon(const char* ssid, const char* bssid, int channel);
const char* craft_probe(const char* ssid, const char* client_mac);
const char* craft_eapol(void);

int monitor_start(const char* iface);
int monitor_stop(void);
const char* monitor_get_stats(void);
const char* monitor_get_channel_util(void);
const char* monitor_get_signal_history(const char* bssid);

#ifdef __cplusplus
}
#endif

#endif
