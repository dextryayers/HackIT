#ifndef HACKIT_WIFI_STACK_H
#define HACKIT_WIFI_STACK_H

#include <stdbool.h>

// Structure to hold interface information
typedef struct {
    char name[16];
    int ifindex;
    int type; // e.g., NL80211_IFTYPE_STATION, NL80211_IFTYPE_MONITOR
} wifi_interface_t;

// Initialize the netlink/nl80211 socket
bool hackit_wifi_init(void);

// Set a specific interface to monitor mode
// interface_name: e.g., "wlan0"
bool hackit_wifi_set_monitor_mode(const char* interface_name);

// Set a specific interface to managed (station) mode
bool hackit_wifi_set_managed_mode(const char* interface_name);

// Change the wireless channel of an interface
// channel: channel number (e.g., 1, 6, 11)
bool hackit_wifi_set_channel(const char* interface_name, int channel);

// Low-level high-integrity frame audit function
bool hackit_wifi_audit_ap(const char* ssid, const char* bssid);

// Dynamic Whitelist Auditor declarations
bool hackit_wifi_load_whitelist(const char* filepath);
int hackit_wifi_is_ap_whitelisted(const char* ssid, const char* bssid);

// Clean up netlink resources
void hackit_wifi_close(void);

#endif // HACKIT_WIFI_STACK_H
