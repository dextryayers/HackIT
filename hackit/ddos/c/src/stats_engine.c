#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#define MAX_STATS_THREADS 256

struct thread_stats {
    uint64_t sent;
    uint64_t bytes;
    uint64_t errors;
};

static struct thread_stats *g_stats_table = NULL;
static int g_stats_num_threads = 0;
static time_t g_stats_start_time = 0;
static int g_stats_initialized = 0;
static char g_stats_err[256] = {0};

EXPORT int stats_init(int num_threads)
{
    if (num_threads <= 0) num_threads = 1;
    if (num_threads > MAX_STATS_THREADS) num_threads = MAX_STATS_THREADS;

    if (g_stats_table) {
        free(g_stats_table);
        g_stats_table = NULL;
    }

    g_stats_table = (struct thread_stats *)calloc((size_t)num_threads, sizeof(struct thread_stats));
    if (!g_stats_table) {
        snprintf(g_stats_err, sizeof(g_stats_err), "calloc: %s", strerror(errno));
        return -1;
    }

    g_stats_num_threads = num_threads;
    g_stats_start_time = time(NULL);
    g_stats_initialized = 1;

    return 0;
}

EXPORT void stats_record(int thread_id, uint64_t sent, uint64_t bytes, uint64_t errors)
{
    if (!g_stats_initialized || !g_stats_table) return;
    if (thread_id < 0 || thread_id >= g_stats_num_threads) return;

    __sync_fetch_and_add(&g_stats_table[thread_id].sent, sent);
    __sync_fetch_and_add(&g_stats_table[thread_id].bytes, bytes);
    __sync_fetch_and_add(&g_stats_table[thread_id].errors, errors);
}

EXPORT void stats_snapshot(uint64_t *total_sent, uint64_t *total_bytes, uint64_t *total_errors, double *rate)
{
    if (!g_stats_initialized || !g_stats_table) {
        if (total_sent) *total_sent = 0;
        if (total_bytes) *total_bytes = 0;
        if (total_errors) *total_errors = 0;
        if (rate) *rate = 0.0;
        return;
    }

    uint64_t tsent = 0, tbytes = 0, terrors = 0;

    for (int i = 0; i < g_stats_num_threads; i++) {
        tsent += __sync_add_and_fetch(&g_stats_table[i].sent, 0);
        tbytes += __sync_add_and_fetch(&g_stats_table[i].bytes, 0);
        terrors += __sync_add_and_fetch(&g_stats_table[i].errors, 0);
    }

    if (total_sent) *total_sent = tsent;
    if (total_bytes) *total_bytes = tbytes;
    if (total_errors) *total_errors = terrors;

    if (rate) {
        time_t elapsed = time(NULL) - g_stats_start_time;
        if (elapsed > 0)
            *rate = (double)tsent / (double)elapsed;
        else
            *rate = 0.0;
    }
}

EXPORT void stats_reset(void)
{
    if (!g_stats_initialized || !g_stats_table) return;

    for (int i = 0; i < g_stats_num_threads; i++) {
        __sync_lock_test_and_set(&g_stats_table[i].sent, 0);
        __sync_lock_test_and_set(&g_stats_table[i].bytes, 0);
        __sync_lock_test_and_set(&g_stats_table[i].errors, 0);
    }

    g_stats_start_time = time(NULL);
}

EXPORT time_t stats_elapsed(void)
{
    if (!g_stats_initialized) return 0;
    return time(NULL) - g_stats_start_time;
}

EXPORT void stats_format_json(char *buf, int buf_size)
{
    if (!buf || buf_size <= 0) return;

    uint64_t tsent = 0, tbytes = 0, terrors = 0;
    double rate = 0.0;

    stats_snapshot(&tsent, &tbytes, &terrors, &rate);

    time_t elapsed = stats_elapsed();

    snprintf(buf, (size_t)buf_size,
        "{\"sent\":%llu,\"bytes\":%llu,\"errors\":%llu,\"rate\":%.1f,\"elapsed\":%lld}",
        (unsigned long long)tsent,
        (unsigned long long)tbytes,
        (unsigned long long)terrors,
        rate,
        (long long)elapsed);
}

EXPORT struct thread_stats *stats_thread_local(int thread_id)
{
    if (!g_stats_initialized || !g_stats_table) return NULL;
    if (thread_id < 0 || thread_id >= g_stats_num_threads) return NULL;
    return &g_stats_table[thread_id];
}
