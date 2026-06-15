#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#define OUT_SIZE 8192

static double estimate_token_entropy(const char* token) {
    int len = strlen(token);
    if (len == 0) return 0.0;

    int counts[256] = {0};
    for (int i = 0; i < len; i++) {
        counts[(unsigned char)token[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * (p > 0 ? log2(p) : 0);
        }
    }
    return entropy;
}

static const char* entropy_rating(double entropy, int max_bits) {
    double pct = (entropy / max_bits) * 100.0;
    if (pct < 30.0) return "WEAK (predictable)";
    if (pct < 60.0) return "MODERATE";
    if (pct < 85.0) return "STRONG";
    return "VERY_STRONG";
}

static int is_jwt_token(const char* data) {
    return strstr(data, "eyJ") == data || strstr(data, "eyJhbGciOi") != NULL;
}

static int extract_session_id(const char* headers, char* out, int out_size) {
    const char* session_markers[] = {
        "sessionid=", "session=", "sid=", "PHPSESSID=",
        "JSESSIONID=", "ASP.NET_SessionId=", "connect.sid=",
        "CFID=", "CFTOKEN=", "_session=", "sess=",
        "token=", "csrf=", "xsrf=", "_csrf=",
        "auth=", "jwt=", "bearer=", "id_token=",
        NULL
    };

    const char* cookie_start = strstr(headers, "Cookie:");
    if (!cookie_start) {
        cookie_start = strstr(headers, "Set-Cookie:");
    }
    if (!cookie_start) return 0;

    for (int i = 0; session_markers[i]; i++) {
        const char* p = strstr(cookie_start, session_markers[i]);
        if (p) {
            p += strlen(session_markers[i]);
            int j = 0;
            while (p[j] && p[j] != ';' && p[j] != '\r' && p[j] != '\n' && p[j] != ' ' && j < out_size - 1) {
                out[j] = p[j];
                j++;
            }
            out[j] = '\0';
            if (j > 0) return j;
        }
    }
    return 0;
}

static int check_session_fixation(const char* headers, const char* body) {
    (void)headers;
    // Check if session ID is passed in URL (fixation vector)
    if (strstr(body, "?sessionid=") || strstr(body, "&sessionid=") ||
        strstr(body, "?sid=") || strstr(body, "&sid=") ||
        strstr(body, "?PHPSESSID=") || strstr(body, "&PHPSESSID=") ||
        strstr(body, "?jsessionid=") || strstr(body, "&jsessionid=")) {
        return 1;
    }
    // Check if session ID appears before authentication
    if (strstr(body, "<input") && strstr(body, "type=\"hidden\"") &&
        (strstr(body, "session") || strstr(body, "token"))) {
        return 1;
    }
    return 0;
}

static int check_csrf_protection(const char* body) {
    if (strstr(body, "csrf") || strstr(body, "CSRF") ||
        strstr(body, "_token") || strstr(body, "authenticity_token") ||
        strstr(body, "__RequestVerificationToken") ||
        strstr(body, "csrf-token") || strstr(body, "csrfmiddlewaretoken") ||
        strstr(body, "xsrf-token") || strstr(body, "XSRF-TOKEN")) {
        return 1;
    }
    return 0;
}

static void check_samesite(const char* headers, char* out, size_t out_size) {
    const char* samesite = strstr(headers, "SameSite=");
    size_t used = strlen(out);
    if (samesite) {
        if (strstr(samesite, "Lax")) {
            snprintf(out + used, out_size - used, "  - SameSite: Lax (moderate CSRF protection)\n");
        } else if (strstr(samesite, "Strict")) {
            snprintf(out + used, out_size - used, "  - SameSite: Strict (strong CSRF protection)\n");
        } else if (strstr(samesite, "None")) {
            snprintf(out + used, out_size - used, "  - SameSite: None (no CSRF protection, requires Secure)\n");
            if (strstr(headers, "Secure") == NULL) {
                used = strlen(out);
                snprintf(out + used, out_size - used, "  - WARNING: SameSite=None without Secure flag!\n");
            }
        }
    } else {
        snprintf(out + used, out_size - used, "  - SameSite: Not Set (defaults vary by browser)\n");
    }
}

static void check_cookie_path(const char* headers, char* out, size_t out_size) {
    const char* path = strstr(headers, "Path=");
    size_t used = strlen(out);
    if (path) {
        path += 5;
        char path_val[256] = {0};
        int i = 0;
        while (path[i] && path[i] != ';' && path[i] != '\r' && path[i] != '\n' && i < 255) {
            path_val[i] = path[i];
            i++;
        }
        path_val[i] = '\0';
        if (strcmp(path_val, "/") == 0) {
            snprintf(out + used, out_size - used, "  - Path: / (global scope - accessible to all paths)\n");
        } else {
            snprintf(out + used, out_size - used,
                     "  - Path: %s (restricted scope)\n", path_val);
        }
    }
}

static void check_cookie_domain(const char* headers, char* out, size_t out_size) {
    const char* domain = strstr(headers, "Domain=");
    size_t used = strlen(out);
    if (domain) {
        snprintf(out + used, out_size - used, "  - Domain: set (wide scope - may be insecure)\n");
    } else {
        used = strlen(out);
        snprintf(out + used, out_size - used, "  - Domain: not set (bound to origin only - secure)\n");
    }
}

EXPORT const char* analyze_session(const char* body, const char* headers) {
    if (body == NULL) body = "";
    if (headers == NULL) headers = "";

    char* buf = (char*)malloc(OUT_SIZE);
    if (!buf) return NULL;
    buf[0] = '\0';

    // Cookie Forensics
    if (strstr(headers, "Set-Cookie:") || strstr(headers, "Cookie:")) {
        strcat(buf, "Session Cookies:\n");

        if (strstr(headers, "HttpOnly")) {
            strcat(buf, "  - HttpOnly: PRESENT (XSS-resistant)\n");
        } else {
            strcat(buf, "  - HttpOnly: MISSING (XSS-theft vulnerable)\n");
        }

        if (strstr(headers, "Secure")) {
            strcat(buf, "  - Secure: PRESENT (TLS-only)\n");
        } else {
            strcat(buf, "  - Secure: MISSING (cleartext transmission possible)\n");
        }

        check_samesite(headers, buf, OUT_SIZE);

        if (strstr(headers, "Max-Age=")) {
            strcat(buf, "  - Max-Age: set (session expiry defined)\n");
        } else if (strstr(headers, "Expires=")) {
            strcat(buf, "  - Expires: set (absolute expiry)\n");
        } else {
            strcat(buf, "  - Expires: session cookie (no expiry - browser close)\n");
        }

        check_cookie_path(headers, buf, OUT_SIZE);
        check_cookie_domain(headers, buf, OUT_SIZE);

        // Extract session token entropy analysis
        char session_id[256] = {0};
        int slen = extract_session_id(headers, session_id, sizeof(session_id));
        if (slen > 0) {
            double sentropy = estimate_token_entropy(session_id);
            int max_bits = 8;
            snprintf(buf + strlen(buf), OUT_SIZE - strlen(buf),
                     "  - Session ID: %s (len=%d, entropy=%.2f bits, rating=%s)\n",
                     session_id, slen, sentropy, entropy_rating(sentropy, max_bits));
        }
    } else {
        strcat(buf, "No cookies found in headers.\n");
    }

    // JWT Detection
    strcat(buf, "\nJWT Analysis:\n");
    if (is_jwt_token(headers) || is_jwt_token(body)) {
        strcat(buf, "  - JWT Detected!\n");
        strcat(buf, "  - Risks: algorithm confusion (alg=none), key confusion (RS256 vs HS256)\n");
        strcat(buf, "  - Recommend: verify signature algorithm, check 'kid' header injection\n");

        if (strstr(body, "alg=none") || strstr(body, "\"alg\":\"none\"")) {
            strcat(buf, "  - CRITICAL: alg=none detected! No signature validation.\n");
        }
    } else {
        strcat(buf, "  - No JWTs detected.\n");
    }

    // OAuth / SSO Detection
    strcat(buf, "\nOAuth / SSO Analysis:\n");
    int has_oauth = 0;
    if (strstr(body, "client_id=") && strstr(body, "redirect_uri=")) {
        has_oauth = 1;
        strcat(buf, "  - OAuth2 flow detected in page.\n");
        if (strstr(body, "response_type=token")) {
            strcat(buf, "  - Implicit Grant flow (deprecated by OAuth 2.1)\n");
            strcat(buf, "  - Risk: access token in URL fragment (leakable via Referer)\n");
        }
        strcat(buf, "  - Check for open redirect in redirect_uri parameter.\n");
    }
    if (strstr(body, "openid") || strstr(body, "OpenID")) {
        has_oauth = 1;
        strcat(buf, "  - OpenID Connect flow detected.\n");
    }
    if (strstr(body, "saml") || strstr(body, "SAML") || strstr(body, "RelayState")) {
        has_oauth = 1;
        strcat(buf, "  - SAML SSO detected.\n");
        strcat(buf, "  - Check for XML signature wrapping attacks.\n");
    }
    if (!has_oauth) {
        strcat(buf, "  - No OAuth/SSO flows detected.\n");
    }

    // Session Fixation
    strcat(buf, "\nSession Fixation:\n");
    if (check_session_fixation(headers, body)) {
        strcat(buf, "  - VULNERABLE: Session ID in URL or pre-auth form.\n");
    } else {
        strcat(buf, "  - No obvious fixation vectors.\n");
    }

    // CSRF Protection
    strcat(buf, "\nCSRF Protection:\n");
    if (check_csrf_protection(body)) {
        strcat(buf, "  - CSRF token detected (likely protected).\n");
    } else {
        strcat(buf, "  - No CSRF token detected. May be vulnerable.\n");
    }

    // Login Portal Detection
    strcat(buf, "\nAuthentication Endpoints:\n");
    int has_auth = 0;
    const char* auth_paths[] = {
        "/login", "/logout", "/register", "/signin", "/signup",
        "/auth", "/oauth", "/admin", "/api/auth", "/forgot",
        "/reset", "/profile", "/account", "/password", NULL
    };
    for (int i = 0; auth_paths[i]; i++) {
        if (strstr(body, auth_paths[i])) {
            has_auth = 1;
            snprintf(buf + strlen(buf), OUT_SIZE - strlen(buf),
                     "  - Endpoint found: %s\n", auth_paths[i]);
        }
    }
    if (!has_auth) {
        strcat(buf, "  - No auth endpoints detected in sample.\n");
    }

    if (strlen(buf) == 0) {
        strcat(buf, "No authentication or session data discovered.");
    }

    return buf;
}

EXPORT void free_session_string(char* s) {
    free(s);
}
