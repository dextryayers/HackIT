#ifndef HACKIT_DEAUTH_ENGINE_H
#define HACKIT_DEAUTH_ENGINE_H

#include <stdbool.h>
#include <stdint.h>

#define HACKIT_DEAUTH_DEFAULT_COUNT 5
#define HACKIT_DEAUTH_DEFAULT_DELAY_MS 100

bool hackit_deauth_burst(const char* iface, const uint8_t* bssid, const uint8_t* station, int count, int delay_ms);
bool hackit_deauth_all_clients(const char* iface, const uint8_t* bssid, int count);
bool hackit_deauth_targeted(const char* iface, const uint8_t* bssid, const uint8_t* target_station, int count);
bool hackit_deauth_association_req(const char* iface, const uint8_t* bssid);

#endif // HACKIT_DEAUTH_ENGINE_H
