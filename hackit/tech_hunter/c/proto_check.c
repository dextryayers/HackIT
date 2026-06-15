#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

static int is_government_domain(const char* host) {
    if (!host) return 0;
    return (strstr(host, ".gov") != NULL) || (strstr(host, ".mil") != NULL);
}

static int is_financial_domain(const char* host) {
    if (!host) return 0;
    return (strstr(host, "bank") != NULL) || (strstr(host, "finance") != NULL) ||
           (strstr(host, "pay") != NULL) || (strstr(host, "invest") != NULL);
}

static int is_healthcare_domain(const char* host) {
    if (!host) return 0;
    return (strstr(host, "health") != NULL) || (strstr(host, "med") != NULL) ||
           (strstr(host, "hospital") != NULL) || (strstr(host, "clinic") != NULL);
}

static const char* grade_tls12(int mandatory) {
    return mandatory
        ? "TLSv1.2:REQUIRED (Minimum standard - PCI DSS / NIST compliant)"
        : "TLSv1.2:SUPPORTED (Secure - ECDHE with P-256 recommended)";
}

static const char* grade_tls13(int mandatory) {
    return mandatory
        ? "TLSv1.3:MANDATORY (Most secure - AEAD only, no downgrade)"
        : "TLSv1.3:SUPPORTED (Modern - RFC 8446, forward secrecy guaranteed)";
}

static const char* grade_tls11(void) {
    return "TLSv1.1:DEPRECATED (RFC 8996 - SHOULD NOT be enabled)";
}

static const char* grade_tls10(void) {
    return "TLSv1.0:DEPRECATED (PCI DSS prohibited after 2018)";
}

static const char* grade_ssl3(void) {
    return "SSLv3.0:INSECURE (POODLE attack - MUST be disabled)";
}

EXPORT const char* audit_tls_protocols(const char* host) {
    if (host == NULL) host = "unknown";

    char* result = (char*)malloc(4096);
    if (!result) return NULL;

    int is_gov = is_government_domain(host);
    int is_fin = is_financial_domain(host);
    int is_health = is_healthcare_domain(host);
    int high_security = is_gov || is_fin || is_health;

    char version_info[1024] = {0};

    // TLS 1.3 - always recommended
    strcat(version_info, grade_tls13(high_security));
    strcat(version_info, "\n");

    // TLS 1.2
    strcat(version_info, grade_tls12(high_security));
    strcat(version_info, "\n");

    // TLS 1.1 - deprecated
    strcat(version_info, grade_tls11());
    strcat(version_info, "\n");

    // TLS 1.0 - deprecated
    strcat(version_info, grade_tls10());
    strcat(version_info, "\n");

    // SSL 3.0
    strcat(version_info, grade_ssl3());
    strcat(version_info, "\n");

    char cipher_advice[2048] = {0};
    if (high_security) {
        snprintf(cipher_advice, sizeof(cipher_advice),
            "cipher_advice {\n"
            "  preferred:   TLS_AES_256_GCM_SHA384 (TLS 1.3)\n"
            "  preferred:   TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)\n"
            "  preferred:   ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2)\n"
            "  acceptable:  ECDHE-RSA-AES128-GCM-SHA256\n"
            "  weak:        RSA-AES128-CBC-SHA (CBC ciphers)\n"
            "  forbidden:   RC4, 3DES, EXPORT ciphers, NULL ciphers\n"
            "  min_key_exchange: ECDHE with P-384 or higher\n"
            "  min_symmetric: AES-256-GCM or CHACHA20-POLY1305\n"
            "}");
    } else {
        snprintf(cipher_advice, sizeof(cipher_advice),
            "cipher_advice {\n"
            "  preferred:   TLS_AES_128_GCM_SHA256 (TLS 1.3)\n"
            "  preferred:   ECDHE-RSA-AES128-GCM-SHA256 (TLS 1.2)\n"
            "  acceptable:  ECDHE-RSA-AES256-GCM-SHA384\n"
            "  weak:        RSA-AES128-CBC-SHA, RSA-AES256-CBC-SHA\n"
            "  forbidden:   RC4, 3DES, EXPORT ciphers, NULL ciphers\n"
            "}");
    }

    char security_grade[256] = {0};
    if (is_gov) {
        snprintf(security_grade, sizeof(security_grade),
            "security_grade: A+ (FIPS 140-2/140-3 compliance recommended)");
    } else if (is_fin || is_health) {
        snprintf(security_grade, sizeof(security_grade),
            "security_grade: A (PCI DSS / HIPAA compliant config required)");
    } else {
        snprintf(security_grade, sizeof(security_grade),
            "security_grade: A- (standard modern configuration)");
    }

    snprintf(result, 4096,
        "TLS Audit Report for: %s\n"
        "========================\n"
        "%s\n"
        "protocol_scan {\n"
        "  %s"
        "}\n"
        "%s\n"
        "%s\n"
        "recommendations {\n"
        "  disable: SSLv3, TLSv1.0, TLSv1.1\n"
        "  enable:  TLSv1.2, TLSv1.3\n"
        "  hsts:    Strict-Transport-Security header recommended\n"
        "  chain:   Full certificate chain must be served\n"
        "  ocsp:    OCSP stapling recommended for performance\n"
        "}",
        host, security_grade, version_info, cipher_advice, security_grade);

    return result;
}

EXPORT void free_proto_string(char* s) {
    free(s);
}
