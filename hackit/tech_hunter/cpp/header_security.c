#include <stdio.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

// Calculate Shannon entropy of headers to detect unusual patterns
float calculate_entropy(const char *data) {
    int counts[256] = {0};
    int len = strlen(data);
    if (len == 0) return 0;

    for (int i = 0; i < len; i++) {
        counts[(unsigned char)data[i]]++;
    }

    float entropy = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            float p = (float)counts[i] / len;
            entropy -= p * log2f(p);
        }
    }
    return entropy;
}

EXPORT float analyze_header_security(const char* headers) {
    float entropy = calculate_entropy(headers);
    
    // Custom C logic for header security scoring
    int score = 0;
    if (strstr(headers, "Strict-Transport-Security")) score += 20;
    if (strstr(headers, "Content-Security-Policy")) score += 30;
    if (strstr(headers, "X-Frame-Options")) score += 10;
    if (strstr(headers, "X-Content-Type-Options")) score += 10;
    
    return (float)score + entropy;
}
