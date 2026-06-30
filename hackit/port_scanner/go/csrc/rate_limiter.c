#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include "optimize.h"

typedef struct {
    double rate_per_sec;
    double burst_size;
    double tokens;
    double max_tokens;
    struct timespec last_time;
    pthread_mutex_t lock;
} RateLimiter;

RateLimiter *rate_limiter_create(double rate_per_sec, int burst_size) {
    if (rate_per_sec <= 0.0 || burst_size <= 0) return NULL;

    RateLimiter *rl = calloc(1, sizeof(RateLimiter));
    if (!rl) return NULL;

    rl->rate_per_sec = rate_per_sec;
    rl->burst_size = (double)burst_size;
    rl->max_tokens = (double)burst_size;
    rl->tokens = (double)burst_size;

    if (clock_gettime(CLOCK_MONOTONIC, &rl->last_time) < 0) {
        free(rl);
        return NULL;
    }

    pthread_mutex_init(&rl->lock, NULL);
    return rl;
}

int rate_limiter_allow(RateLimiter *rl) {
    if (!rl) return 1;

    pthread_mutex_lock(&rl->lock);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double elapsed_sec = (double)(now.tv_sec - rl->last_time.tv_sec)
                       + (double)(now.tv_nsec - rl->last_time.tv_nsec) / 1.0e9;

    if (elapsed_sec > 0.0) {
        double new_tokens = elapsed_sec * rl->rate_per_sec;
        rl->tokens += new_tokens;
        if (rl->tokens > rl->max_tokens)
            rl->tokens = rl->max_tokens;
        rl->last_time = now;
    }

    int allowed = 0;
    if (rl->tokens >= 1.0) {
        rl->tokens -= 1.0;
        allowed = 1;
    }

    pthread_mutex_unlock(&rl->lock);
    return allowed;
}

void rate_limiter_destroy(RateLimiter *rl) {
    if (!rl) return;
    pthread_mutex_destroy(&rl->lock);
    memset(rl, 0, sizeof(RateLimiter));
    free(rl);
}
