#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

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

#define BINS 256

static double calculate_shannon(const unsigned char* data, int len) {
    if (!data || len <= 0) return 0.0;
    int counts[BINS] = {0};
    for (int i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < BINS; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static double calculate_min_entropy(const unsigned char* data, int len) {
    if (!data || len <= 0) return 0.0;
    int counts[BINS] = {0};
    for (int i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    double max_p = 0.0;
    for (int i = 0; i < BINS; i++) {
        double p = (double)counts[i] / len;
        if (p > max_p) max_p = p;
    }
    return max_p > 0.0 ? -log2(max_p) : 0.0;
}

static double calculate_chi_square(const unsigned char* data, int len) {
    if (!data || len <= 0) return 0.0;
    int counts[BINS] = {0};
    for (int i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    double expected = (double)len / BINS;
    double chi2 = 0.0;
    for (int i = 0; i < BINS; i++) {
        double diff = counts[i] - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}

static double calculate_ioc(const unsigned char* data, int len) {
    if (!data || len <= 1) return 0.0;
    int counts[BINS] = {0};
    for (int i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    double sum = 0.0;
    for (int i = 0; i < BINS; i++) {
        sum += (double)counts[i] * (counts[i] - 1);
    }
    return sum / ((double)len * (len - 1));
}

static int is_base64_string(const char* s, int len) {
    if (len <= 20) return 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) {
            return 0;
        }
    }
    return 1;
}

static int is_hex_string(const char* s, int len) {
    if (len <= 10) return 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

static int count_high_ascii(const unsigned char* data, int len) {
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (data[i] > 127) count++;
    }
    return count;
}

static int count_html_js_comments(const char* s, int len) {
    int count = 0;
    for (int i = 0; i < len - 3; i++) {
        if (s[i] == '<' && s[i+1] == '!' && s[i+2] == '-' && s[i+3] == '-') {
            count++;
            i += 3;
        }
    }
    for (int i = 0; i < len - 1; i++) {
        if (s[i] == '/' && s[i+1] == '/') {
            count++;
            i += 1;
        }
        if (s[i] == '/' && s[i+1] == '*') {
            count++;
            i += 1;
        }
    }
    return count;
}

static int contains_binary_data(const unsigned char* data, int len) {
    int null_count = 0;
    int control_count = 0;
    for (int i = 0; i < len && i < 1024; i++) {
        if (data[i] == 0) null_count++;
        else if (data[i] < 32 && data[i] != '\n' && data[i] != '\r' && data[i] != '\t') control_count++;
    }
    return (null_count > 0 || control_count > len / 10);
}

EXPORT double calculate_payload_entropy(const char* data) {
    if (data == NULL) return 0.0;
    int len = strlen(data);
    if (len == 0) return 0.0;
    return calculate_shannon((const unsigned char*)data, len);
}

typedef struct {
    double shannon;
    double min_entropy;
    double chi_square;
    double ioc;
} entropy_result_t;

static char* format_entropy_report(const unsigned char* data, int len) {
    entropy_result_t r;
    r.shannon = calculate_shannon(data, len);
    r.min_entropy = calculate_min_entropy(data, len);
    r.chi_square = calculate_chi_square(data, len);
    r.ioc = calculate_ioc(data, len);

    int max_bits = 8;
    double shannon_pct = (r.shannon / max_bits) * 100.0;

    const char* verdict;
    if (shannon_pct < 30.0) {
        verdict = "LOW_ENTROPY (likely plaintext/structured)";
    } else if (shannon_pct < 60.0) {
        verdict = "MEDIUM_ENTROPY (possibly compressed)";
    } else if (shannon_pct < 85.0) {
        verdict = "HIGH_ENTROPY (likely encrypted/random)";
    } else {
        verdict = "VERY_HIGH_ENTROPY (likely encrypted/randomized)";
    }

    int high_ascii = count_high_ascii(data, len);
    double high_ascii_pct = len > 0 ? (double)high_ascii / len * 100.0 : 0.0;

    int is_b64 = is_base64_string((const char*)data, len);
    int is_hex = is_hex_string((const char*)data, len);
    int binary = contains_binary_data(data, len);
    int comments = count_html_js_comments((const char*)data, len);

    const char* encoding_hint = "standard_ascii";
    if (binary)      encoding_hint = "binary_data";
    else if (is_b64) encoding_hint = "base64_encoded";
    else if (is_hex) encoding_hint = "hex_encoded";

    const char* binary_indicator = binary ? "YES" : "NO";

    char* buf = (char*)malloc(4096);
    if (!buf) return NULL;
    snprintf(buf, 4096,
        "entropy_report {\n"
        "  shannon_entropy:         %.6f (%.1f%%)\n"
        "  min_entropy:             %.6f\n"
        "  chi_square:              %.2f\n"
        "  index_of_coincidence:    %.6f\n"
        "  bytes_analyzed:          %d\n"
        "  high_ascii_bytes:        %d (%.1f%%)\n"
        "  html_js_comments_found:  %d\n"
        "  encoding_hint:           %s\n"
        "  contains_binary:         %s\n"
        "  verdict:                 %s\n"
        "}",
        r.shannon, shannon_pct,
        r.min_entropy,
        r.chi_square,
        r.ioc,
        len,
        high_ascii, high_ascii_pct,
        comments,
        encoding_hint,
        binary_indicator,
        verdict
    );
    return buf;
}

EXPORT const char* analyze_entropy_deep(const char* data) {
    if (data == NULL) return my_strdup("entropy_report { error: NULL input }");
    int len = strlen(data);
    if (len == 0) return my_strdup("entropy_report { error: empty input }");
    return format_entropy_report((const unsigned char*)data, len);
}

EXPORT void free_entropy_string(char* s) {
    free(s);
}
