#ifndef HACKIT_REAL_ATTACK_ENGINE_H
#define HACKIT_REAL_ATTACK_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#define MAC_LEN 6
#define MAX_FRAME_SIZE 4096
#define HACKIT_RADIOTAP_LEN 12

int send_deauth(const char *iface, const char *bssid, const char *station, int count);
int flood_beacons(const char *iface, const char *ssid, int count);
int capture_handshake(const char *iface, const char *bssid, int timeout, const char *output);
int inject_frame(const char *iface, const uint8_t *frame, int len);
int parse_mac(const char *str, uint8_t *mac);
void format_mac(const uint8_t *mac, char *out);
int build_beacon_frame(uint8_t *buf, int buf_len, const char *ssid, const uint8_t *bssid, uint8_t channel);
int build_deauth_frame(uint8_t *buf, const uint8_t *bssid, const uint8_t *station, uint16_t reason);

#endif
