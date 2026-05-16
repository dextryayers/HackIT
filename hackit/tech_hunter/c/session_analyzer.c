#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT const char* analyze_session(const char* body, const char* headers) {
    char buf[4096] = {0};
    
    // Genuine Cookie Forensics
    if (strstr(headers, "Set-Cookie:")) {
        strcat(buf, "Session Cookies :\n");
        if (strstr(headers, "HttpOnly")) {
            strcat(buf, "  - Flags: HttpOnly found (Secure against XSS)\n");
        } else {
            strcat(buf, "  - Flags: Missing HttpOnly (Vulnerable to XSS theft)\n");
        }
        if (strstr(headers, "Secure")) {
            strcat(buf, "  - Flags: Secure found (Encrypted transit)\n");
        } else {
            strcat(buf, "  - Flags: Missing Secure (Vulnerable to MiTM)\n");
        }
    }

    // Genuine JWT Detection
    strcat(buf, "\nJWT Specifics :\n");
    if (strstr(headers, "Authorization: Bearer eyJ") || strstr(body, "eyJhbGciOi")) {
        strcat(buf, "  - JWT Detected! Payload parsing required for exact claims.\n");
        strcat(buf, "  - Algorithm confusion risk: Verify if HS256/RS256 alg=none is accepted.\n");
    } else {
        strcat(buf, "  - No exposed JWTs discovered in raw client code.\n");
    }

    // Genuine OAuth Detection
    if (strstr(body, "client_id=") && strstr(body, "redirect_uri=")) {
        strcat(buf, "\nOAuth Misconfigurations :\n  - OAuth implementation detected in JS/Body.\n  - Open redirect on redirect_uri: High probability, manual test required.\n");
    }

    // Auth Login portals
    if (strstr(body, "/login") || strstr(body, "/admin") || strstr(body, "/api/auth")) {
        strcat(buf, "\nLogin Portals Detected in DOM :\n  - /login or /admin variants found.\n");
    }

    if (strlen(buf) == 0) {
        strcat(buf, "No authentication or session data discovered.");
    }

    char* res = (char*)malloc(strlen(buf) + 1);
    strcpy(res, buf);
    return res;
}

EXPORT void free_session_string(char* s) {
    free(s);
}
