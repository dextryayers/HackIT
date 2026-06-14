#ifndef HACKIT_OFFENSIVE_PLUS_H
#define HACKIT_OFFENSIVE_PLUS_H

#include <cstdint>
#include <string>
#include <vector>

struct WpsPinParams {
    std::string bssid;
    std::string iface;
    int timeout_sec = 120;
    bool pixie = false;
    std::string pin;
};

struct WepAttackParams {
    std::string iface;
    std::string bssid;
    std::string target_mac;
    std::string output;
    int packets = 50000;
    int timeout_sec = 300;
};

struct EapolResult {
    std::string client_mac;
    std::string ap_mac;
    std::string replay_counter;
    std::string key_mic;
    std::string anonce;
    std::string snonce;
    int msg_type = 0;
};

struct EvilTwinParams {
    std::string iface;
    std::string ssid;
    std::string bssid;
    int channel = 6;
    bool captive_portal = false;
    std::string portal_page;
    int timeout_sec = 0;
};

extern "C" {
    int hackit_wps_attack(const char* iface, const char* bssid, const char* pin, int pixie);
    int hackit_wep_attack(const char* iface, const char* bssid, const char* output, int mode);
    int hackit_parse_eapol(const char* pcap_file, EapolResult* results, int* count);
    int hackit_evil_twin_start(const char* iface, const char* ssid, int channel, const char* bssid);
    int hackit_evil_twin_stop(void);
    int hackit_compute_wps_pin(const char* bssid, char* pin_out);
}

#endif
