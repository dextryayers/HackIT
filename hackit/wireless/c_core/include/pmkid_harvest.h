#ifndef HACKIT_PMKID_HARVEST_H
#define HACKIT_PMKID_HARVEST_H

#include <stdbool.h>
#include <stdint.h>

#define HACKIT_PMKID_HEX_LEN 33
#define HACKIT_MAC_STR_LEN 18
#define HASHCAT_22000_MAX_LINE 512

bool hackit_pmkid_extract_from_pcap(const char* pcap_path, char* out_pmkid_hex, int max_len);
bool hackit_pmkid_parse_eapol(const uint8_t* frame, int len, char* out_pmkid_hex, int max_len);
bool hackit_pmkid_format_hc22000(const char* pmkid_hex, const char* ap_mac, const char* client_mac, const char* essid, char* out_line, int max_len);
bool hackit_pmkid_verify_complete(const uint8_t* frame, int len);

#endif // HACKIT_PMKID_HARVEST_H
