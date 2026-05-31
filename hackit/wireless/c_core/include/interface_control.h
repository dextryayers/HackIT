#ifndef HACKIT_INTERFACE_CONTROL_H
#define HACKIT_INTERFACE_CONTROL_H

#include <stdbool.h>

// Low-level high-integrity FFI wrappers for interface tuning & configuration
bool hackit_wifi_change_mac(const char* interface_name, const char* new_mac);
bool hackit_wifi_restore_mac(const char* interface_name);
bool hackit_wifi_set_txpower(const char* interface_name, int value);
bool hackit_wifi_get_adapter_info(const char* interface_name, char* info_buf, int buf_size);
bool hackit_wifi_get_status(const char* interface_name, char* status_buf, int buf_size);

#endif // HACKIT_INTERFACE_CONTROL_H
