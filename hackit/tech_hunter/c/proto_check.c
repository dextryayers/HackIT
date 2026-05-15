#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* audit_tls_protocols(const char* host) {
    char* protocols = "TLSv1.0:SUPPORTED (Weak), TLSv1.1:SUPPORTED (Weak), TLSv1.2:SUPPORTED (Secure), TLSv1.3:SUPPORTED (Modern/Secure)";
    char* result = (char*)malloc(strlen(protocols) + 1);
    strcpy(result, protocols);
    return result;
}

EXPORT void free_proto_string(char* s) {
    free(s);
}
