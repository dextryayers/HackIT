#ifndef HACKIT_PACKET_INJECTOR_H
#define HACKIT_PACKET_INJECTOR_H

#include <stdbool.h>
#include <stdint.h>

#define HACKIT_MAX_FRAME_LEN 2048
#define HACKIT_80211_radiotap_LEN 12
#define HACKIT_80211_MGMT_HDR_LEN 24

#define HACKIT_DEAUTH_REASON_UNSPECIFIED 1
#define HACKIT_DEAUTH_REASON_AUTH_LEAVING 4
#define HACKIT_DEAUTH_REASON_INACTIVITY 5

bool hackit_inject_raw_frame(const char* iface, const uint8_t* frame, int len);
bool hackit_inject_deauth(const char* iface, const uint8_t* bssid, const uint8_t* station, uint16_t reason);
bool hackit_inject_beacon(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel);
bool hackit_inject_proberesp(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel);

#endif // HACKIT_PACKET_INJECTOR_H
