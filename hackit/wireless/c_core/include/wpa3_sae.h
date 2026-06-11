#ifndef HACKIT_WPA3_SAE_H
#define HACKIT_WPA3_SAE_H

#include <stdbool.h>
#include <stdint.h>

#define HACKIT_SAE_GROUP_MAX 32
#define HACKIT_SAE_ANTI_CLOGGING_LEN 32
#define HACKIT_SAE_CONFIRM_LEN 32
#define HACKIT_SAE_SEND_CONFIRM_LEN 2

bool hackit_is_wpa3_sae(const uint8_t* beacon_frame, size_t len);
int hackit_parse_sae_commit(const uint8_t* frame, size_t len, uint8_t* group, uint8_t* anti_clogging);
int hackit_parse_sae_confirm(const uint8_t* frame, size_t len, uint8_t* confirm, uint8_t* send_confirm);
bool hackit_build_sae_commit_frame(uint8_t* buf, size_t buf_len, const uint8_t* bssid, const uint8_t* sta);

#endif // HACKIT_WPA3_SAE_H
