#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

struct token_bucket {
    volatile uint64_t tokens;
    volatile uint64_t last_refill;
    volatile uint64_t rate;
    volatile uint64_t max_burst;
    volatile uint64_t max_rate;
    volatile uint64_t min_rate;
    volatile uint64_t target_rate;
    volatile int initialized;
};

static struct token_bucket g_bucket;
static char g_rate_err[256] = {0};

static uint64_t rate_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void refill_bucket(void)
{
    uint64_t now = rate_now_ms();
    uint64_t last = __sync_add_and_fetch(&g_bucket.last_refill, 0);

    if (now <= last) return;

    uint64_t elapsed = now - last;
    uint64_t rate = __sync_add_and_fetch(&g_bucket.rate, 0);

    uint64_t new_tokens = (rate * elapsed) / 1000;
    if (new_tokens == 0) return;

    if (__sync_bool_compare_and_swap(&g_bucket.last_refill, last, now)) {
        uint64_t current = __sync_add_and_fetch(&g_bucket.tokens, 0);
        uint64_t max_burst = __sync_add_and_fetch(&g_bucket.max_burst, 0);
        uint64_t total = current + new_tokens;
        if (total > max_burst) total = max_burst;
        __sync_lock_test_and_set(&g_bucket.tokens, total);
    }
}

EXPORT int rate_init(uint64_t initial_rate, uint64_t max_rate, uint64_t min_rate)
{
    if (initial_rate == 0) initial_rate = 1000;
    if (max_rate == 0) max_rate = 1000000;
    if (min_rate == 0) min_rate = 10;

    g_bucket.rate = initial_rate;
    g_bucket.max_rate = max_rate;
    g_bucket.min_rate = min_rate;
    g_bucket.target_rate = initial_rate;
    g_bucket.max_burst = initial_rate * 2;
    g_bucket.tokens = g_bucket.max_burst;
    g_bucket.last_refill = rate_now_ms();
    g_bucket.initialized = 1;

    return 0;
}

EXPORT int rate_allow(void)
{
    if (!g_bucket.initialized) {
        snprintf(g_rate_err, sizeof(g_rate_err), "rate controller not initialized");
        return 0;
    }

    refill_bucket();

    uint64_t t;
    int ok = 0;

    while ((t = __sync_add_and_fetch(&g_bucket.tokens, 0)) > 0) {
        if (__sync_bool_compare_and_swap(&g_bucket.tokens, t, t - 1)) {
            ok = 1;
            break;
        }
    }

    return ok;
}

EXPORT void rate_on_success(void)
{
    uint64_t current = __sync_add_and_fetch(&g_bucket.rate, 0);
    uint64_t increment = current / 16;
    if (increment < 1) increment = 1;
    uint64_t new_rate = current + increment;
    uint64_t max_r = __sync_add_and_fetch(&g_bucket.max_rate, 0);
    if (new_rate > max_r) new_rate = max_r;
    __sync_lock_test_and_set(&g_bucket.rate, new_rate);

    uint64_t new_burst = new_rate * 2;
    __sync_lock_test_and_set(&g_bucket.max_burst, new_burst);
}

EXPORT void rate_on_timeout(void)
{
    uint64_t current = __sync_add_and_fetch(&g_bucket.rate, 0);
    uint64_t new_rate = current / 2;
    uint64_t min_rate = __sync_add_and_fetch(&g_bucket.min_rate, 0);
    if (new_rate < min_rate) new_rate = min_rate;
    __sync_lock_test_and_set(&g_bucket.rate, new_rate);

    uint64_t new_burst = new_rate * 2;
    if (new_burst < 10) new_burst = 10;
    __sync_lock_test_and_set(&g_bucket.max_burst, new_burst);
}

EXPORT void rate_on_loss(void)
{
    uint64_t current = __sync_add_and_fetch(&g_bucket.rate, 0);
    uint64_t new_rate = current / 4;
    uint64_t min_rate = __sync_add_and_fetch(&g_bucket.min_rate, 0);
    if (new_rate < min_rate) new_rate = min_rate;
    __sync_lock_test_and_set(&g_bucket.rate, new_rate);

    uint64_t new_burst = new_rate * 2;
    if (new_burst < 10) new_burst = 10;
    __sync_lock_test_and_set(&g_bucket.max_burst, new_burst);
}

EXPORT uint64_t rate_get_current(void)
{
    return __sync_add_and_fetch(&g_bucket.rate, 0);
}

EXPORT void rate_set_target(uint64_t target_rate)
{
    __sync_lock_test_and_set(&g_bucket.target_rate, target_rate);
}

EXPORT void rate_adjust(int rtt_ms, int loss_percent)
{
    if (!g_bucket.initialized) return;

    (void)rtt_ms;

    uint64_t current = __sync_add_and_fetch(&g_bucket.rate, 0);
    uint64_t target = __sync_add_and_fetch(&g_bucket.target_rate, 0);

    if (loss_percent > 5) {
        rate_on_loss();
    } else if (loss_percent > 1) {
        rate_on_timeout();
    } else if (current < target) {
        rate_on_success();
    }
}
