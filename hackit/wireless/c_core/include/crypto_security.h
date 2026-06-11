#ifndef HACKIT_CRYPTO_SECURITY_H
#define HACKIT_CRYPTO_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

bool hackit_crypto_pbkdf2_sha1(const char* password, const uint8_t* ssid, size_t ssid_len, uint8_t* psk_out);
bool hackit_crypto_verify_mic(const uint8_t* psk, const uint8_t* eapol_frame, size_t len, const uint8_t* expected_mic);
bool hackit_crypto_compute_pmkid(const uint8_t* pmk, const uint8_t* ap_mac, const uint8_t* client_mac, uint8_t* pmkid_out);

#endif
