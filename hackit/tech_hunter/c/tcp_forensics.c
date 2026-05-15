#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* analyze_tcp_sequence(const char* ip) {
    char buf[256];
    // Simulating sequence analysis
    sprintf(buf, "IP ID Sequence: Incremental | TCP Timestamps: Detected (Uptime Guess: 14 days, 3h)");
    
    char* result = (char*)malloc(strlen(buf) + 1);
    strcpy(result, buf);
    return result;
}

EXPORT void free_tcp_string(char* s) {
    free(s);
}
