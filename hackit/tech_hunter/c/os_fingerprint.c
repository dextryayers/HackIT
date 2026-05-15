#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* fingerprint_os(int ttl, int window_size) {
    char* os = "Unknown";
    
    // Heuristic OS Fingerprinting based on TTL and Window Size
    if (ttl == 64) {
        if (window_size <= 5840) os = "Linux (Kernel 2.4/2.6/3.x)";
        else os = "Google Custom Linux";
    } else if (ttl == 128) {
        os = "Windows (7/10/Server)";
    } else if (ttl == 255) {
        os = "Cisco IOS / Network Device";
    }

    char* result = (char*)malloc(strlen(os) + 1);
    strcpy(result, os);
    return result;
}

EXPORT void free_os_string(char* s) {
    free(s);
}
