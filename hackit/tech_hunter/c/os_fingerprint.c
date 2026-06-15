#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

typedef struct {
    int ttl;
    int window_min;
    int window_max;
    const char* os;
    int confidence;
} os_entry;

static const os_entry os_db[] = {
    // Linux variants
    {64, 0, 5840, "Linux (Kernel 2.4/2.6)", 90},
    {64, 5841, 29200, "Linux (Kernel 3.x/4.x)", 85},
    {64, 29201, 65535, "Linux (custom/Google)", 60},
    // Windows
    {128, 0, 65535, "Windows (7/8/10/11/Server)", 85},
    {128, 0, 8192, "Windows 10/11 (recent)", 75},
    {128, 8193, 16384, "Windows Server 2016/2019", 70},
    // macOS / iOS
    {64, 0, 65535, "macOS / iOS / Darwin", 80},
    {64, 0, 65535, "macOS (Mountain Lion+)", 70},
    // BSD
    {64, 0, 65535, "FreeBSD", 70},
    {64, 0, 65535, "OpenBSD", 65},
    {64, 0, 65535, "NetBSD", 60},
    // Solaris
    {255, 0, 65535, "Solaris / Oracle", 75},
    {255, 0, 65535, "SunOS 5.x", 65},
    // Network devices
    {255, 0, 65535, "Cisco IOS / Network Device", 80},
    {255, 0, 65535, "HP / Juniper Network Device", 60},
    // Mobile
    {64, 0, 65535, "Android (Linux kernel)", 75},
    {64, 0, 65535, "Android 10+", 65},
    // Embedded / IoT
    {64, 0, 65535, "Linux (embedded/IoT)", 60},
    {255, 0, 65535, "Printer / Embedded Device", 55},
    // Unusual
    {60, 0, 65535, "AIX / IBM", 60},
    {256, 0, 65535, "HP-UX", 55},
    {32, 0, 65535, "QNX / Real-Time OS", 50},
};

#define DB_SIZE (sizeof(os_db) / sizeof(os_db[0]))

typedef struct {
    int ttl;
    int window_size;
    int mss;
    int sack_ok;
    int nop_count;
    int wscale;
    int timestamp_ok;
} tcp_opts;

EXPORT const char* fingerprint_os(int ttl, int window_size) {
    int best_idx = -1;
    int best_conf = 0;

    for (size_t i = 0; i < DB_SIZE; i++) {
        if (os_db[i].ttl == ttl &&
            window_size >= os_db[i].window_min &&
            window_size <= os_db[i].window_max) {
            if (os_db[i].confidence > best_conf) {
                best_conf = os_db[i].confidence;
                best_idx = i;
            }
        }
    }

    if (best_idx == -1) {
        const char* fallback;
        if (ttl <= 32) fallback = "Unknown (likely embedded/RTOS)";
        else if (ttl <= 64) fallback = "Unknown (likely *nix)";
        else if (ttl <= 128) fallback = "Unknown (likely Windows)";
        else fallback = "Unknown (likely network device)";

        char* result = (char*)malloc(256);
        if (!result) return NULL;
        snprintf(result, 256, "%s [confidence: low, ttl=%d, win=%d]", fallback, ttl, window_size);
        return result;
    }

    char* result = (char*)malloc(256);
    if (!result) return NULL;
    snprintf(result, 256, "%s [confidence: %d%%, ttl=%d, win=%d]",
             os_db[best_idx].os, best_conf, ttl, window_size);
    return result;
}

EXPORT void free_os_string(char* s);

EXPORT const char* fingerprint_os_deep(int ttl, int window_size,
                                       int mss, int sack_ok,
                                       int wscale, int timestamp_ok) {
    char base[256] = {0};
    const char* os = fingerprint_os(ttl, window_size);
    if (os) {
        strncpy(base, os, 250);
        base[250] = '\0';
        free_os_string((char*)os);
    } else {
        strncpy(base, "Unknown", 250);
        base[250] = '\0';
    }

    char* result = (char*)malloc(1024);
    if (!result) return NULL;

    snprintf(result, 1024,
        "%s\n"
        "  tcp_opts_dump {\n"
        "    mss:           %d\n"
        "    sack_ok:       %s\n"
        "    window_scale:  %d\n"
        "    timestamps:    %s\n"
        "  }\n"
        "  ttl_guess:      initial_ttl=%d (distance ~%d hops)\n",
        base,
        mss, sack_ok ? "yes" : "no",
        wscale, timestamp_ok ? "yes" : "no",
        ttl,
        ttl > 128 ? ttl - 128 : ttl > 64 ? ttl - 64 : ttl > 32 ? ttl - 32 : 0
    );

    return result;
}

EXPORT void free_os_string(char* s) {
    free(s);
}
