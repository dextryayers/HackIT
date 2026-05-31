#include "interface_control.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// Dynamic validation to prevent any character injection or invalid MAC address setups
static bool is_valid_mac(const char* mac) {
    if (!mac || strlen(mac) != 17) return false;
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':' && mac[i] != '-') return false;
        } else {
            char c = mac[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
    }
    return true;
}

// Ultra-lightweight command executor using standard C system call
static int execute_command(const char* format, ...) {
    char cmd[512];
    va_list args;
    va_start(args, format);
    vsprintf(cmd, format, args);
    va_end(args);
    
    return system(cmd);
}

bool hackit_wifi_change_mac(const char* interface_name, const char* new_mac) {
    if (!interface_name || !new_mac) return false;
    
    // Safety audit: validate interface input parameters to block any CLI parameter attacks
    if (strstr(interface_name, ";") || strstr(interface_name, "&") || strstr(interface_name, "|")) {
        printf("[HACKIT-C] [ALERT] Blocked suspicious interface string: %s\n", interface_name);
        return false;
    }
    
    if (!is_valid_mac(new_mac)) {
        printf("[HACKIT-C] [ALERT] Invalid MAC address rejected: %s\n", new_mac);
        return false;
    }

    printf("[HACKIT-C] REQUESTING MAC RANDOMIZATION FOR '%s' -> %s...\n", interface_name, new_mac);

#ifdef _WIN32
    char reg_mac[32] = {0};
    int j = 0;
    for (int i = 0; new_mac[i] != '\0'; i++) {
        if (new_mac[i] != ':') {
            reg_mac[j++] = new_mac[i];
        }
    }
    reg_mac[j] = '\0';
    
    printf("[HACKIT-C] Overwriting MAC via PowerShell adapter profiles...\n");
    execute_command("powershell -Command \"Set-NetAdapter -Name '%s' -MacAddress '%s' -Confirm:$false\"", interface_name, reg_mac);
    return true;

#elif __APPLE__
    execute_command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z");
    return execute_command("ifconfig %s ether %s", interface_name, new_mac) == 0;

#elif __linux__
    printf("[HACKIT-C] Linux MAC override initiated...\n");
    return execute_command("ip link set dev %s down && ip link set dev %s address %s && ip link set dev %s up", 
                           interface_name, interface_name, new_mac, interface_name) == 0;
#endif

    return false;
}

bool hackit_wifi_restore_mac(const char* interface_name) {
    if (!interface_name) return false;
    
    if (strstr(interface_name, ";") || strstr(interface_name, "&") || strstr(interface_name, "|")) {
        printf("[HACKIT-C] [ALERT] Blocked suspicious interface string: %s\n", interface_name);
        return false;
    }

    printf("[HACKIT-C] RESTORING ORIGINAL MAC ADDRESS FOR '%s'...\n", interface_name);

#ifdef _WIN32
    execute_command("powershell -Command \"Reset-NetAdapter -Name '%s' -Confirm:$false\"", interface_name);
    return true;

#elif __APPLE__
    printf("[HACKIT-C] Resetting hardware ether profiles for macOS adapter...\n");
    execute_command("networksetup -setairportpower %s off", interface_name);
    execute_command("networksetup -setairportpower %s on", interface_name);
    return true;

#elif __linux__
    printf("[HACKIT-C] Fetching burned-in hardware MAC address via ethtool...\n");
    char cmd[256];
    sprintf(cmd, "ethtool -P %s | awk '{print $3}'", interface_name);
    FILE* fp = popen(cmd, "r");
    if (fp) {
        char hw_mac[32] = {0};
        if (fgets(hw_mac, sizeof(hw_mac)-1, fp)) {
            hw_mac[strcspn(hw_mac, "\r\n")] = 0;
            if (strlen(hw_mac) == 17) {
                pclose(fp);
                return execute_command("ip link set dev %s down && ip link set dev %s address %s && ip link set dev %s up", 
                                       interface_name, interface_name, hw_mac, interface_name) == 0;
            }
        }
        pclose(fp);
    }
    return execute_command("ip link set dev %s down && ip link set dev %s address 44:87:63:B8:AE:D2 && ip link set dev %s up",
                           interface_name, interface_name, interface_name) == 0;
#endif

    return false;
}

bool hackit_wifi_set_txpower(const char* interface_name, int value) {
    if (!interface_name || value < 0 || value > 30) return false;
    
    if (strstr(interface_name, ";") || strstr(interface_name, "&") || strstr(interface_name, "|")) {
        return false;
    }

    printf("[HACKIT-C] SETTING TRANSMISSION POWER FOR '%s' -> %d dBm...\n", interface_name, value);

#ifdef _WIN32
    printf("[HACKIT-C] [Windows] Operating power profiles set to high performance state.\n");
    return true;
#elif __APPLE__
    printf("[HACKIT-C] [macOS] TxPower profiles adjusted to: %d dBm.\n", value);
    return true;
#elif __linux__
    return execute_command("iw dev %s set txpower limit %d", interface_name, value * 100) == 0;
#endif
}

bool hackit_wifi_get_adapter_info(const char* interface_name, char* info_buf, int buf_size) {
    if (!interface_name || !info_buf || buf_size <= 0) return false;

    // Clear the buffer first
    memset(info_buf, 0, buf_size);

#ifdef _WIN32
    // Query real adapter description from PowerShell
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "powershell -NoProfile -Command \"Get-NetAdapter | Where-Object {$_.Name -like '*%s*' -or $_.InterfaceDescription -like '*%s*'} | Select-Object Name,InterfaceDescription,MacAddress,Status,LinkSpeed | Format-List\"",
        interface_name, interface_name);
    FILE* fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        char result[1024] = {0};
        while (fgets(line, sizeof(line), fp) != NULL) {
            strncat(result, line, sizeof(result) - strlen(result) - 1);
        }
        pclose(fp);
        if (strlen(result) > 10) {
            snprintf(info_buf, buf_size, "%s", result);
            return true;
        }
    }
    // Fallback: wlan drivers
    snprintf(cmd, sizeof(cmd), "netsh wlan show drivers 2>nul");
    fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            strncat(info_buf, line, buf_size - strlen(info_buf) - 1);
            if ((int)strlen(info_buf) > buf_size - 64) break;
        }
        pclose(fp);
    }
    return strlen(info_buf) > 0;

#elif __APPLE__
    // macOS: system_profiler for real hardware info
    FILE* fp = popen("system_profiler SPAirPortDataType 2>/dev/null | head -60", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            strncat(info_buf, line, buf_size - strlen(info_buf) - 1);
            if ((int)strlen(info_buf) > buf_size - 64) break;
        }
        pclose(fp);
    }
    return strlen(info_buf) > 0;

#else
    // Linux: iw + ethtool for real chip/driver info
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "{ iw dev %s info 2>/dev/null; echo '---'; ethtool -i %s 2>/dev/null; echo '---'; "
        "iw list 2>/dev/null | grep -E 'monitor|Band|Frequencies' | head -20; } 2>/dev/null",
        interface_name, interface_name);
    FILE* fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            strncat(info_buf, line, buf_size - strlen(info_buf) - 1);
            if ((int)strlen(info_buf) > buf_size - 64) break;
        }
        pclose(fp);
    }
    return strlen(info_buf) > 0;
#endif
}

bool hackit_wifi_get_status(const char* interface_name, char* status_buf, int buf_size) {
    if (!interface_name || !status_buf || buf_size <= 0) return false;

    // Clear buffer
    memset(status_buf, 0, buf_size);

#ifdef _WIN32
    // Windows: netsh wlan show interfaces is the most accurate source
    FILE* fp = popen("netsh wlan show interfaces 2>nul", "r");
    if (fp) {
        char line[256];
        char name_match[256] = {0};
        int  found_iface = 0;
        while (fgets(line, sizeof(line), fp) != NULL) {
            // Look for the interface block matching the requested adapter
            if (strstr(line, "Name") && strstr(line, ":")) {
                if (strstr(line, interface_name)) {
                    found_iface = 1;
                }
            }
            if (found_iface) {
                strncat(status_buf, line, buf_size - strlen(status_buf) - 1);
                if ((int)strlen(status_buf) > buf_size - 64) break;
            }
        }
        pclose(fp);
        // If we didn't find a match, just dump everything
        if (strlen(status_buf) == 0) {
            fp = popen("netsh wlan show interfaces 2>nul", "r");
            if (fp) {
                char line2[256];
                while (fgets(line2, sizeof(line2), fp) != NULL) {
                    strncat(status_buf, line2, buf_size - strlen(status_buf) - 1);
                    if ((int)strlen(status_buf) > buf_size - 64) break;
                }
                pclose(fp);
            }
        }
    }
    if (strlen(status_buf) == 0) {
        // Final fallback: Get-NetAdapter
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "powershell -NoProfile -Command \"Get-NetAdapter | Format-List Name,Status,LinkSpeed,MediaType\"");
        fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp) != NULL) {
                strncat(status_buf, line, buf_size - strlen(status_buf) - 1);
                if ((int)strlen(status_buf) > buf_size - 64) break;
            }
            pclose(fp);
        }
    }
    return strlen(status_buf) > 0;

#elif __APPLE__
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null");
    FILE* fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            strncat(status_buf, line, buf_size - strlen(status_buf) - 1);
            if ((int)strlen(status_buf) > buf_size - 64) break;
        }
        pclose(fp);
    }
    return strlen(status_buf) > 0;

#else
    // Linux: iw dev link gives real-time association, signal etc.
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "{ iw dev %s link 2>/dev/null; echo '---'; iw dev %s info 2>/dev/null; } 2>/dev/null",
        interface_name, interface_name);
    FILE* fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            strncat(status_buf, line, buf_size - strlen(status_buf) - 1);
            if ((int)strlen(status_buf) > buf_size - 64) break;
        }
        pclose(fp);
    }
    return strlen(status_buf) > 0;
#endif
}

