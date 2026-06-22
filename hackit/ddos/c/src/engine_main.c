#include "engine.h"

extern int g_sock;

static int g_running = 0;
static uint64_t g_packets = 0;
static attack_config_t g_cfg;

EXPORT int engine_init(const attack_config_t *cfg) {
    if (cfg) g_cfg = *cfg;
    return init_raw_socket();
}

EXPORT void engine_shutdown(void) {
    g_running = 0;
    close_raw_socket();
}

EXPORT int engine_start(void) {
    if (g_sock < 0) return -1;
    g_running = 1;
    g_packets = 0;
    return 0;
}

EXPORT int engine_stop(void) {
    g_running = 0;
    return 0;
}

EXPORT int engine_pause(void) {
    g_running = 0;
    return 0;
}

EXPORT int engine_resume(void) {
    g_running = 1;
    return 0;
}

EXPORT int engine_status(int *running, uint64_t *packets_sent) {
    if (running) *running = g_running;
    if (packets_sent) *packets_sent = g_packets;
    return 0;
}

EXPORT int engine_stats_reset(void) {
    g_packets = 0;
    return 0;
}

EXPORT int engine_reload(const attack_config_t *cfg) {
    if (cfg) g_cfg = *cfg;
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
