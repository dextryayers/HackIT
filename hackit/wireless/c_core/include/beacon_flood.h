#include <stddef.h>
#ifndef HACKIT_BEACON_FLOOD_H
#define HACKIT_BEACON_FLOOD_H

#include <stdbool.h>
#include <stdint.h>

int hackit_build_beacon_frame(uint8_t* buf, size_t buf_len, const char* ssid, const uint8_t* bssid, uint8_t channel);
int hackit_beacon_flood(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel, int count);
int hackit_beacon_flood_random(const char* iface, int count);

#endif // HACKIT_BEACON_FLOOD_H
