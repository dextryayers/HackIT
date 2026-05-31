#ifndef HACKIT_CRYPTO_SECURITY_H
#define HACKIT_CRYPTO_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Mock OpenSSL/libsodium wrappers for WPA cracking/hashing in C
bool hackit_crypto_pbkdf2_sha1(const char* password, const uint8_t* ssid, size_t ssid_len, uint8_t* psk_out);
bool hackit_crypto_verify_mic(const uint8_t* psk, const uint8_t* eapol_frame, size_t len, const uint8_t* expected_mic);

#endif
