#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#define MAX_SEQ_SAMPLES 64

typedef struct {
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned short ip_id;
    unsigned int timestamp;
    unsigned short window;
    unsigned short flags;
} tcp_sample;

static int isn_analysis(const tcp_sample* samples, int count, char* out, int out_size) {
    if (count < 2) {
        snprintf(out, out_size, "  ISN: insufficient samples (need >=2, got %d)\n", count);
        return 0;
    }

    unsigned int deltas[MAX_SEQ_SAMPLES - 1];
    for (int i = 1; i < count; i++) {
        deltas[i-1] = samples[i].seq_num - samples[i-1].seq_num;
    }

    // Check for constant delta (extremely predictable)
    int all_same = 1;
    for (int i = 1; i < count - 1; i++) {
        if (deltas[i] != deltas[0]) { all_same = 0; break; }
    }
    if (all_same && count >= 2) {
        snprintf(out, out_size,
            "  ISN: CONSTANT INCREMENT (%u) - HIGHLY PREDICTABLE! (RST hijacking risk)\n",
            deltas[0]);
        return 2;
    }

    // Check for small delta range
    unsigned int min_delta = deltas[0], max_delta = deltas[0];
    for (int i = 1; i < count - 1; i++) {
        if (deltas[i] < min_delta) min_delta = deltas[i];
        if (deltas[i] > max_delta) max_delta = deltas[i];
    }

    if ((max_delta - min_delta) < 1000) {
        snprintf(out, out_size,
            "  ISN: PREDICTABLE (delta range=%u, min=%u, max=%u) - sequence spoofing risk\n",
            max_delta - min_delta, min_delta, max_delta);
        return 1;
    }

    snprintf(out, out_size,
        "  ISN: RANDOMIZED (delta range=%u) - secure\n",
        max_delta - min_delta);
    return 0;
}

static int ipid_analysis(const tcp_sample* samples, int count, char* out, int out_size) {
    if (count < 3) {
        snprintf(out, out_size, "  IP ID: insufficient samples (need >=3, got %d)\n", count);
        return 0;
    }

    // Check for IP ID patterns
    int incremental = 1;
    int random = 1;
    int constant = 1;

    for (int i = 2; i < count; i++) {
        if (samples[i].ip_id != samples[i-1].ip_id + 1) incremental = 0;
        if (samples[i].ip_id == samples[0].ip_id) random = 0;
        if (samples[i].ip_id != samples[i-1].ip_id) constant = 0;
    }

    if (constant) {
        snprintf(out, out_size, "  IP ID: CONSTANT (%u) - information leak (packet count inference)\n",
                 samples[0].ip_id);
        return 2;
    }
    if (incremental) {
        snprintf(out, out_size, "  IP ID: INCREMENTAL - information leak (host enumeration, silent scan)\n");
        return 1;
    }
    if (random) {
        snprintf(out, out_size, "  IP ID: RANDOMIZED - no information leak\n");
        return 0;
    }

    snprintf(out, out_size, "  IP ID: UNCLASSIFIED pattern\n");
    return 0;
}

static int timestamp_analysis(const tcp_sample* samples, int count, char* out, int out_size) {
    if (count < 2) {
        snprintf(out, out_size, "  TCP Timestamps: insufficient samples\n");
        return 0;
    }

    if (samples[0].timestamp == 0 && samples[1].timestamp == 0) {
        snprintf(out, out_size, "  TCP Timestamps: NOT PRESENT (or zero) - no uptime leak\n");
        return 0;
    }

    unsigned int ts_delta = samples[count-1].timestamp - samples[0].timestamp;
    // Timestamps increment at 1ms (or 10ms/100ms depending on OS)
    // Typical rate: 1000 ticks/second (1ms)
    double uptime_seconds = (double)samples[count-1].timestamp / 1000.0;
    int days = (int)(uptime_seconds / 86400);
    int hours = (int)((uptime_seconds - days * 86400) / 3600);

    snprintf(out, out_size,
        "  TCP Timestamps: PRESENT\n"
        "    Timestamp values: %u -> %u (delta=%u)\n"
        "    Estimated uptime: %d days, %d hours (at 1ms/tick)\n"
        "    Risk: OS uptime leak aids targeted attacks\n",
        samples[0].timestamp, samples[count-1].timestamp, ts_delta,
        days, hours);

    return 1;
}

static int window_analysis(const tcp_sample* samples, int count, char* out, int out_size) {
    if (count < 2) {
        snprintf(out, out_size, "  Window Scaling: insufficient samples\n");
        return 0;
    }

    int window_changes = 0;
    for (int i = 1; i < count; i++) {
        if (samples[i].window != samples[i-1].window) window_changes++;
    }

    if (window_changes == 0) {
        snprintf(out, out_size,
            "  Window: CONSTANT (%u) - likely not using window scaling\n",
            samples[0].window);
    } else {
        snprintf(out, out_size,
            "  Window: VARIABLE (%d changes across %d samples) - window scaling active\n",
            window_changes, count);
    }
    return window_changes > 0 ? 1 : 0;
}

static int flag_analysis(const tcp_sample* samples, int count, char* out, int out_size) {
    int syn_count = 0, ack_count = 0, psh_count = 0, rst_count = 0, fin_count = 0;
    for (int i = 0; i < count; i++) {
        if (samples[i].flags & 0x02) syn_count++;
        if (samples[i].flags & 0x10) ack_count++;
        if (samples[i].flags & 0x08) psh_count++;
        if (samples[i].flags & 0x04) rst_count++;
        if (samples[i].flags & 0x01) fin_count++;
    }

    snprintf(out, out_size,
        "  TCP Flags breakdown (%d packets):\n"
        "    SYN: %d  ACK: %d  PSH: %d  RST: %d  FIN: %d\n",
        count, syn_count, ack_count, psh_count, rst_count, fin_count);

    if (rst_count > ack_count / 2) {
        strcat(out, "  WARNING: High RST ratio - possible scanning or connection issues\n");
    }
    return 0;
}

EXPORT const char* analyze_tcp_sequence(const char* ip) {
    char* result = (char*)malloc(8192);
    if (!result) return NULL;

    // This function is called with an IP address and should provide
    // TCP sequence analysis. Since we can't actually sniff packets
    // from a C function called via FFI, we return a comprehensive
    // analysis framework explaining what would be analyzed.

    snprintf(result, 8192,
        "TCP Forensics Report for: %s\n"
        "=============================\n"
        "This module requires raw packet capture input.\n"
        "Pass samples via analyze_tcp_samples() for real analysis.\n"
        "\n"
        "Available deep analyses via tcp_forensics:\n"
        "  - ISN Prediction (sequence number randomization)\n"
        "  - IP ID Fingerprinting (host enumeration risk)\n"
        "  - TCP Timestamp Analysis (uptime leak)\n"
        "  - Window Scale Detection\n"
        "  - TCP Flag Profiling\n"
        "  - MSS / Option Fingerprinting\n"
        "\n"
        "Call analyze_tcp_samples() with raw data for results.\n",
        ip ? ip : "unknown");

    return result;
}

EXPORT const char* analyze_tcp_samples(const unsigned int* seq_numbers,
                                       const unsigned short* ip_ids,
                                       const unsigned int* timestamps,
                                       const unsigned short* windows,
                                       const unsigned short* flags,
                                       int count) {
    char* result = (char*)malloc(8192);
    if (!result) return NULL;
    result[0] = '\0';

    if (count < 1 || seq_numbers == NULL) {
        snprintf(result, 8192, "tcp_forensics: no samples provided\n");
        return result;
    }

    if (count > MAX_SEQ_SAMPLES) count = MAX_SEQ_SAMPLES;

    // Build sample array
    tcp_sample samples[MAX_SEQ_SAMPLES];
    for (int i = 0; i < count; i++) {
        samples[i].seq_num = seq_numbers[i];
        samples[i].ip_id = ip_ids ? ip_ids[i] : 0;
        samples[i].timestamp = timestamps ? timestamps[i] : 0;
        samples[i].window = windows ? windows[i] : 0;
        samples[i].flags = flags ? flags[i] : 0;
    }

    size_t remaining = 8192;

    int hdr_len = snprintf(result, 8192,
        "TCP Forensics Analysis (%d samples)\n"
        "==================================\n",
        count);
    if (hdr_len < 0) hdr_len = 0;
    if ((size_t)hdr_len < remaining) remaining -= hdr_len; else remaining = 0;

    char line[1024];
    if (remaining > 0) {
        strncat(result, "\n--- Sequence Number Analysis ---\n", remaining);
        remaining -= strlen("\n--- Sequence Number Analysis ---\n");
    }
    isn_analysis(samples, count, line, sizeof(line));
    if (remaining > 0) {
        strncat(result, line, remaining);
        size_t llen = strlen(line);
        if (llen < remaining) remaining -= llen; else remaining = 0;
    }

    if (remaining > 0) {
        strncat(result, "\n--- IP ID Analysis ---\n", remaining);
        remaining -= strlen("\n--- IP ID Analysis ---\n");
    }
    ipid_analysis(samples, count, line, sizeof(line));
    if (remaining > 0) {
        strncat(result, line, remaining);
        size_t llen = strlen(line);
        if (llen < remaining) remaining -= llen; else remaining = 0;
    }

    if (remaining > 0) {
        strncat(result, "\n--- Timestamp Analysis ---\n", remaining);
        remaining -= strlen("\n--- Timestamp Analysis ---\n");
    }
    timestamp_analysis(samples, count, line, sizeof(line));
    if (remaining > 0) {
        strncat(result, line, remaining);
        size_t llen = strlen(line);
        if (llen < remaining) remaining -= llen; else remaining = 0;
    }

    if (remaining > 0) {
        strncat(result, "\n--- Window Analysis ---\n", remaining);
        remaining -= strlen("\n--- Window Analysis ---\n");
    }
    window_analysis(samples, count, line, sizeof(line));
    if (remaining > 0) {
        strncat(result, line, remaining);
        size_t llen = strlen(line);
        if (llen < remaining) remaining -= llen; else remaining = 0;
    }

    if (remaining > 0) {
        strncat(result, "\n--- Flag Analysis ---\n", remaining);
        remaining -= strlen("\n--- Flag Analysis ---\n");
    }
    flag_analysis(samples, count, line, sizeof(line));
    if (remaining > 0) {
        strncat(result, line, remaining);
        size_t llen = strlen(line);
        if (llen < remaining) remaining -= llen; else remaining = 0;
    }

    // Overall risk assessment
    if (remaining > 0) {
        strncat(result, "\n--- Risk Summary ---\n", remaining);
        size_t hlen = strlen("\n--- Risk Summary ---\n");
        if (hlen < remaining) remaining -= hlen; else remaining = 0;
    }
    int risk_score = 0;
    int max_risk = 10;
    if (count >= 2) {
        unsigned int deltas[MAX_SEQ_SAMPLES - 1];
        for (int i = 1; i < count; i++) deltas[i-1] = samples[i].seq_num - samples[i-1].seq_num;
        int all_same = 1;
        for (int i = 1; i < count - 1; i++) if (deltas[i] != deltas[0]) { all_same = 0; break; }
        if (all_same) risk_score += 4;

        if (count >= 3) {
            int constant = 1;
            for (int i = 1; i < count; i++) if (samples[i].ip_id != samples[i-1].ip_id) { constant = 0; break; }
            if (constant) risk_score += 3;

            int incremental = 1;
            for (int i = 1; i < count; i++) if (samples[i].ip_id != samples[i-1].ip_id + 1) { incremental = 0; break; }
            if (incremental) risk_score += 2;
        }

        if (samples[0].timestamp > 0) risk_score += 2;
    }

    snprintf(line, sizeof(line),
        "  Risk Score: %d/%d (%s)\n",
        risk_score, max_risk,
        risk_score >= 7 ? "HIGH - OS/device fingerprintable" :
        risk_score >= 4 ? "MEDIUM - some information leakage" :
        "LOW - good randomization");
    if (remaining > 0) {
        strncat(result, line, remaining);
    }

    return result;
}

EXPORT void free_tcp_string(char* s) {
    free(s);
}
