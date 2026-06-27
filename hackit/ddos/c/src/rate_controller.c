#include "../include/engine.h"
#include <stdint.h>

/* Rate controller — DISABLED: always allows, infinite rate */

EXPORT int rate_init(uint64_t initial_rate, uint64_t max_rate, uint64_t min_rate) {
    (void)initial_rate; (void)max_rate; (void)min_rate;
    return 0;
}

EXPORT int rate_allow(void) {
    return 1; /* always allow, no throttling */
}

EXPORT void rate_on_success(void) {}
EXPORT void rate_on_timeout(void) {}
EXPORT void rate_on_loss(void) {}

EXPORT uint64_t rate_get_current(void) {
    return 999999999ULL;
}

EXPORT void rate_set_target(uint64_t target_rate) {
    (void)target_rate;
}

EXPORT void rate_adjust(int rtt_ms, int loss_percent) {
    (void)rtt_ms; (void)loss_percent;
}
