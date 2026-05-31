#include "frame_parser.h"
#include <vector>
#include <cstring>
#include <cstdio>

extern "C" {

bool hackit_cpp_parse_ssid(const uint8_t* raw_frame, int frame_len, char* out_ssid, int max_len) {
    if (!raw_frame || !out_ssid || frame_len < 36 || max_len <= 0) return false;
    
    // Minimal 802.11 parsing logic.
    // Skip 24 bytes MAC header + 12 bytes fixed parameters (Timestamp, Beacon Interval, Cap Info)
    int offset = 36;
    
    while (offset < frame_len) {
        uint8_t ie_id = raw_frame[offset];
        uint8_t ie_len = raw_frame[offset + 1];
        
        if (offset + 2 + ie_len > frame_len) break; // Bounds check
        
        if (ie_id == 0) { // SSID IE
            int copy_len = (ie_len < max_len - 1) ? ie_len : max_len - 1;
            std::memcpy(out_ssid, &raw_frame[offset + 2], copy_len);
            out_ssid[copy_len] = '\0';
            
            // Check if hidden (all null bytes or zeros)
            bool hidden = true;
            for(int i=0; i<copy_len; i++) {
                if(out_ssid[i] != '\0' && out_ssid[i] != 0x00) {
                    hidden = false;
                    break;
                }
            }
            if(hidden) std::strcpy(out_ssid, "<HIDDEN>");
            return true;
        }
        
        offset += 2 + ie_len;
    }
    return false;
}

bool hackit_cpp_parse_bssid(const uint8_t* raw_frame, int frame_len, char* out_bssid) {
    if (!raw_frame || !out_bssid || frame_len < 24) return false;
    
    // Address 3 is usually the BSSID in management frames (offset 16)
    std::sprintf(out_bssid, "%02X:%02X:%02X:%02X:%02X:%02X",
                 raw_frame[16], raw_frame[17], raw_frame[18],
                 raw_frame[19], raw_frame[20], raw_frame[21]);
    return true;
}

bool hackit_cpp_is_deauth(const uint8_t* raw_frame, int frame_len) {
    if (!raw_frame || frame_len < 2) return false;
    
    uint8_t frame_control_0 = raw_frame[0];
    // Type bits 2-3 (Mgmt = 00), Subtype bits 4-7 (Deauth = 1100 = 0xC, Disassoc = 1010 = 0xA)
    uint8_t type = (frame_control_0 >> 2) & 0x03;
    uint8_t subtype = (frame_control_0 >> 4) & 0x0F;
    
    return (type == 0 && (subtype == 0xC || subtype == 0xA));
}

}
