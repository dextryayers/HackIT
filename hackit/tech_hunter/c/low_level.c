#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

static char* my_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char* d = (char*)malloc(len + 1);
    if (!d) return NULL;
    memcpy(d, s, len + 1);
    return d;
}

#define OUT_SIZE 4096

static int count_occurrences(const char* str, const char* sub) {
    int count = 0;
    const char* p = str;
    while ((p = strstr(p, sub)) != NULL) {
        count++;
        p += strlen(sub);
    }
    return count;
}

static int has_control_chars(const char* str) {
    for (const char* p = str; *p; p++) {
        unsigned char c = *p;
        if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') return 1;
    }
    return 0;
}

static int has_null_bytes(const char* str) {
    return memchr(str, '\0', strlen(str)) != NULL;
}

EXPORT const char* check_header_anomalies(const char* headers) {
    if (headers == NULL) return my_strdup("");

    char* findings = (char*)malloc(OUT_SIZE);
    if (!findings) return NULL;
    findings[0] = '\0';

    int has_termination = (strstr(headers, "\r\n\r\n") != NULL);
    if (!has_termination) {
        strcat(findings, "anomaly:INVALID_TERMINATION|");
    }

    int cl_count = count_occurrences(headers, "Content-Length:");
    int te_count = count_occurrences(headers, "Transfer-Encoding:");
    if (cl_count > 0 && te_count > 0) {
        strcat(findings, "critical:HTTP_SMUGGLING_CL_TE|");
    }

    if (strstr(headers, "Transfer-Encoding:") && strstr(headers, "Content-Length:")) {
        strcat(findings, "warning:HTTP_SMUGGLING_TE_CL|");
    }

    if (count_occurrences(headers, "Host:") > 1) {
        strcat(findings, "anomaly:MULTIPLE_HOST_HEADERS|");
    }

    if (strstr(headers, "X-Forwarded-For:") || strstr(headers, "X-Real-IP:")) {
        strcat(findings, "info:PROXY_HEADERS_PRESENT|");
    }

    if (strstr(headers, "Server: ") != NULL && strstr(headers, "X-Powered-By: ") != NULL) {
        strcat(findings, "info:REDUNDANT_SERVER_INFO|");
    }

    if (strlen(headers) > 8192) {
        strcat(findings, "critical:EXCESSIVE_HEADER_SIZE|");
    } else if (strlen(headers) > 4096) {
        strcat(findings, "warning:LARGE_HEADER_SIZE|");
    }

    if (strstr(headers, "Cookie:") && strstr(headers, "HttpOnly") == NULL) {
        strcat(findings, "warning:HTTPONLY_MISSING|");
    }
    if (strstr(headers, "Cookie:") && strstr(headers, "Secure") == NULL) {
        strcat(findings, "warning:SECURE_FLAG_MISSING|");
    }
    if (strstr(headers, "Set-Cookie:") && strstr(headers, "SameSite=") == NULL) {
        strcat(findings, "warning:SAMESITE_MISSING|");
    }

    if (strstr(headers, "Access-Control-Allow-Origin: *")) {
        strcat(findings, "warning:CORS_WILDCARD|");
    }
    if (strstr(headers, "Access-Control-Allow-Credentials: true") &&
        strstr(headers, "Access-Control-Allow-Origin: *")) {
        strcat(findings, "critical:CORS_CREDENTIALS_WILDCARD|");
    }

    if (strstr(headers, "Strict-Transport-Security") == NULL) {
        strcat(findings, "info:HSTS_MISSING|");
    }

    if (strstr(headers, "X-Content-Type-Options: nosniff") == NULL) {
        strcat(findings, "info:X_CONTENT_TYPE_OPTIONS_MISSING|");
    }

    if (strstr(headers, "X-Frame-Options:") == NULL &&
        strstr(headers, "Content-Security-Policy:") == NULL) {
        strcat(findings, "info:CLICKJACKING_PROTECTION_MISSING|");
    }

    if (strstr(headers, "Content-Security-Policy:")) {
        strcat(findings, "info:CSP_FOUND|");
    }

    if (strstr(headers, "Referrer-Policy:")) {
        strcat(findings, "info:REFERRER_POLICY_FOUND|");
    }

    if (strstr(headers, "Expect:") && strstr(headers, "100-continue")) {
        strcat(findings, "info:EXPECT_100_CONTINUE|");
    }

    if (strstr(headers, "Upgrade:") && strstr(headers, "websocket")) {
        strcat(findings, "info:WEBSOCKET_UPGRADE|");
    }

    if (strstr(headers, "X-Forwarded-Host:") || strstr(headers, "X-Forwarded-Proto:")) {
        strcat(findings, "info:FORWARDED_HEADERS|");
    }

    if (strstr(headers, "X-Requested-With: XMLHttpRequest")) {
        strcat(findings, "info:AJAX_XHR_HEADER|");
    }

    if (has_control_chars(headers)) {
        strcat(findings, "anomaly:CONTROL_CHARS_IN_HEADERS|");
    }

    if (has_null_bytes(headers)) {
        strcat(findings, "critical:NULL_BYTE_INJECTION|");
    }

    if (strstr(headers, "\\r\\n") || strstr(headers, "\\n\\r")) {
        strcat(findings, "anomaly:ESCAPED_CRLF_INJECTION|");
    }

    if (strstr(headers, "Set-Cookie:") == NULL) {
        strcat(findings, "info:NO_COOKIES_SET|");
    }

    if (strlen(findings) == 0) {
        strcat(findings, "ok:NO_ANOMALIES_DETECTED|");
    }

    return findings;
}

EXPORT void free_low_level_string(char* s) {
    free(s);
}
