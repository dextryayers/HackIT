#include <stdio.h>
#include <math.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

// High-speed Shannon Entropy for payload analysis
EXPORT double calculate_payload_entropy(const char* data) {
    if (data == NULL) return 0.0;
    
    int len = strlen(data);
    if (len == 0) return 0.0;
    
    int counts[256] = {0};
    for (int i = 0; i < len; i++) {
        counts[(unsigned char)data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}
