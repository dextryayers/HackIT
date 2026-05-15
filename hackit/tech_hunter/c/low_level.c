#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* check_header_anomalies(const char* headers) {
    if (headers == NULL) return "";
    
    char* findings = (char*)malloc(1024);
    findings[0] = '\0';
    
    // Low-level C checks for header weirdness
    if (strstr(headers, "\r\n\r\n") == NULL) {
        strcat(findings, "anomaly:INVALID_TERMINATION|");
    }
    
    if (strstr(headers, "Server: ") != NULL && strstr(headers, "X-Powered-By: ") != NULL) {
        strcat(findings, "info:REDUNDANT_SERVER_INFO|");
    }
    
    if (strlen(headers) > 4096) {
        strcat(findings, "warning:EXCESSIVE_HEADER_SIZE|");
    }

    return findings; // Memory leak expected here for simplicity in this bridge, should be freed by caller
}
