#include "engine.h"

volatile int g_engine_kill_flag = 0;
extern int g_sock;

EXPORT int engine_init(const attack_config_t *cfg) {
    g_engine_kill_flag = 0;
    if (cfg) {
        (void)cfg;
    }
    return init_raw_socket();
}

EXPORT void engine_shutdown(void) {
    g_engine_kill_flag = 1;
    close_raw_socket();
}

EXPORT int engine_start(void) {
    if (g_sock < 0) return -1;
    g_engine_kill_flag = 0;
    return 0;
}

EXPORT int engine_stop(void) {
    g_engine_kill_flag = 1;
    return 0;
}

EXPORT int engine_pause(void) {
    g_engine_kill_flag = 1;
    return 0;
}

EXPORT int engine_resume(void) {
    g_engine_kill_flag = 0;
    return 0;
}

EXPORT int engine_status(int *running, uint64_t *packets_sent) {
    if (running) *running = !g_engine_kill_flag;
    if (packets_sent) *packets_sent = batch_flood_sent();
    return 0;
}

EXPORT int engine_stats_reset(void) {
    return 0;
}

EXPORT int engine_reload(const attack_config_t *cfg) {
    (void)cfg;
    return 0;
}

EXPORT int engine_xdp_attach(const char *ifname) {
    (void)ifname;
    return 0;
}

EXPORT int engine_xdp_detach(const char *ifname) {
    (void)ifname;
    return 0;
}

EXPORT int engine_dpdk_bind(uint16_t port_id) {
    (void)port_id;
    return 0;
}

EXPORT int engine_dpdk_release(uint16_t port_id) {
    (void)port_id;
    return 0;
}
