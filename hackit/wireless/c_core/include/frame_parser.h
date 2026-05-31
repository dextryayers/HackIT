#ifndef HACKIT_FRAME_PARSER_H
#define HACKIT_FRAME_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Extracts SSID cleanly from an 802.11 Beacon or Probe frame by walking the Information Elements (IE)
bool hackit_cpp_parse_ssid(const uint8_t* raw_frame, int frame_len, char* out_ssid, int max_len);

// Extracts the BSSID from the IEEE 802.11 MAC header
bool hackit_cpp_parse_bssid(const uint8_t* raw_frame, int frame_len, char* out_bssid);

// Checks if the frame is a deauth/disassociation frame
bool hackit_cpp_is_deauth(const uint8_t* raw_frame, int frame_len);

#ifdef __cplusplus
}
#endif

#endif // HACKIT_FRAME_PARSER_H
