#ifndef HACKIT_WIRELESS_FRAME_H
#define HACKIT_WIRELESS_FRAME_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Mock structures for radiotap and ieee80211 parsing
typedef struct {
    int8_t signal_dbm;
    uint16_t channel_freq;
    bool has_fcs;
} radiotap_meta_t;

bool hackit_frame_parse_radiotap(const uint8_t* packet, size_t len, radiotap_meta_t* meta);
bool hackit_frame_is_beacon(const uint8_t* packet, size_t len);

#endif
