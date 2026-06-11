#include "adapter_detection.h"
#include "wifi_stack.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <wlanapi.h>
#include <iphlpapi.h>
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <unistd.h>
#endif

int hackit_c_detect_adapters(c_wifi_adapter_t* out_adapters, int max_adapters) {
    if (!out_adapters || max_adapters <= 0) return 0;
    int count = 0;

#ifdef _WIN32
    HANDLE wlan_handle = NULL;
    DWORD negotiated_version = 0;
    DWORD result = WlanOpenHandle(2, NULL, &negotiated_version, &wlan_handle);
    if (result == ERROR_SUCCESS) {
        PWLAN_INTERFACE_INFO_LIST interface_list = NULL;
        result = WlanEnumInterfaces(wlan_handle, NULL, &interface_list);
        if (result == ERROR_SUCCESS) {
            for (DWORD i = 0; i < interface_list->dwNumberOfItems && count < max_adapters; i++) {
                PWLAN_INTERFACE_INFO info = &interface_list->InterfaceInfo[i];
                
                memset(&out_adapters[count], 0, sizeof(c_wifi_adapter_t));

                int len = wcstombs(out_adapters[count].name, info->strInterfaceDescription, sizeof(out_adapters[count].name) - 1);
                if (len >= 0) out_adapters[count].name[len] = '\0';

                wcstombs(out_adapters[count].driver, info->strInterfaceDescription, sizeof(out_adapters[count].driver) - 1);
                out_adapters[count].channel = hackit_wifi_get_current_channel(out_adapters[count].name);
                out_adapters[count].signal_dbm = -85; // default until measured
                out_adapters[count].is_monitor = false;
                out_adapters[count].supports_2ghz = true;
                out_adapters[count].supports_5ghz = true; // modern adapters almost all support 5GHz
                out_adapters[count].max_tx_power = 20;

                // Get MAC and signal from adapter addresses
                ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
                PIP_ADAPTER_ADDRESSES addresses = NULL;
                ULONG size = 15000;
                addresses = (IP_ADAPTER_ADDRESSES*)malloc(size);
                if (addresses) {
                    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addresses, &size) == ERROR_SUCCESS) {
                        PIP_ADAPTER_ADDRESSES curr = addresses;
                        while (curr) {
                            char friendly_desc[256] = {0};
                            wcstombs(friendly_desc, curr->Description, sizeof(friendly_desc) - 1);
                            if (strstr(friendly_desc, out_adapters[count].driver) != NULL || curr->IfType == IF_TYPE_IEEE80211) {
                                if (curr->PhysicalAddressLength == 6) {
                                    sprintf(out_adapters[count].mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                                            curr->PhysicalAddress[0], curr->PhysicalAddress[1],
                                            curr->PhysicalAddress[2], curr->PhysicalAddress[3],
                                            curr->PhysicalAddress[4], curr->PhysicalAddress[5]);
                                }
                                // Detect 5GHz capability from adapter name
                                if (strstr(friendly_desc, "802.11a") || strstr(friendly_desc, "802.11ac") || 
                                    strstr(friendly_desc, "802.11ax") || strstr(friendly_desc, "Dual Band") ||
                                    strstr(friendly_desc, "5GHz") || strstr(friendly_desc, "5G")) {
                                    out_adapters[count].supports_5ghz = true;
                                }
                                break;
                            }
                            curr = curr->Next;
                        }
                    }
                    free(addresses);
                }

                // Get dynamic signal quality from connection state
                PWLAN_CONNECTION_ATTRIBUTES conn_attrs = NULL;
                DWORD conn_attrs_size = sizeof(WLAN_CONNECTION_ATTRIBUTES);
                if (WlanQueryInterface(wlan_handle, &info->InterfaceGuid, wlan_intf_opcode_current_connection, NULL, &conn_attrs_size, (PVOID*)&conn_attrs, NULL) == ERROR_SUCCESS) {
                    if (conn_attrs->isState == wlan_interface_state_connected) {
                        ULONG quality = conn_attrs->wlanAssociationAttributes.wlanSignalQuality;
                        out_adapters[count].signal_dbm = -100 + (quality / 2);
                    }
                    WlanFreeMemory(conn_attrs);
                }

                count++;
            }
            WlanFreeMemory(interface_list);
        }
        WlanCloseHandle(wlan_handle, NULL);
    }
#else
    // Unix/Linux: use getifaddrs + ioctl(SIOCGIWNAME) for wireless detection
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL && count < max_adapters; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if (ifa->ifa_flags & IFF_LOOPBACK) continue;
            
            // Detect wireless interfaces via iw or SIOCGIWNAME
            bool is_wireless = false;
            {
                char cmd[256];
                sprintf(cmd, "iw dev %s info 2>/dev/null | grep -q 'type'", ifa->ifa_name);
                is_wireless = (system(cmd) == 0);
            }
            
            if (!is_wireless) continue;

            // Duplicate prevention
            bool is_duplicate = false;
            for (int i = 0; i < count; i++) {
                if (strcmp(out_adapters[i].name, ifa->ifa_name) == 0) { is_duplicate = true; break; }
            }
            if (is_duplicate) continue;

            memset(&out_adapters[count], 0, sizeof(c_wifi_adapter_t));
            strncpy(out_adapters[count].name, ifa->ifa_name, sizeof(out_adapters[count].name) - 1);
            strncpy(out_adapters[count].driver, "mac80211", sizeof(out_adapters[count].driver) - 1);

            // Get MAC from AF_PACKET socket
            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                sprintf(out_adapters[count].mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                        s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                        s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
            }

            out_adapters[count].channel = hackit_wifi_get_current_channel(ifa->ifa_name);
            out_adapters[count].signal_dbm = -70;
            out_adapters[count].is_monitor = false;

            // Detect band support from iw phy info
            {
                char cmd[256];
                char buf[1024] = {0};
                sprintf(cmd, "iw phy $(iw dev %s info 2>/dev/null | grep phy | awk '{print $2}') info 2>/dev/null | grep -E 'MHz|Band'", ifa->ifa_name);
                FILE* fp = popen(cmd, "r");
                if (fp) {
                    while (fgets(buf, sizeof(buf), fp)) {
                        if (strstr(buf, "2412 MHz") || strstr(buf, "2.4")) out_adapters[count].supports_2ghz = true;
                        if (strstr(buf, "5180 MHz") || strstr(buf, "5")) out_adapters[count].supports_5ghz = true;
                    }
                    pclose(fp);
                }
            }

            out_adapters[count].max_tx_power = 20;
            count++;
        }
        freeifaddrs(ifaddr);
    }
#endif

    return count;
}
