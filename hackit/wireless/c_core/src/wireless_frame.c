#include "wireless_frame.h"
#include <stdio.h>

bool hackit_frame_parse_radiotap(const uint8_t* packet, size_t len, radiotap_meta_t* meta) {
    if (len < 8 || !meta) return false;
    // Mock radiotap header parsing
    meta->signal_dbm = -55; // Simulated excellent signal
    meta->channel_freq = 2412; // Channel 1
    meta->has_fcs = true;
    return true;
}

bool hackit_frame_is_beacon(const uint8_t* packet, size_t len) {
    if (len < 24) return false;
    // Check Frame Control (FC) for 802.11 Management Beacon (Subtype 8)
    uint8_t fc = packet[0];
    uint8_t frame_type = (fc & 0x0C) >> 2;
    uint8_t subtype = (fc & 0xF0) >> 4;
    return (frame_type == 0 && subtype == 8);
}
