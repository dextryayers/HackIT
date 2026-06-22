#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#define TRACKER_HASH_BITS 10
#define TRACKER_HASH_SIZE (1 << TRACKER_HASH_BITS)
#define TRACKER_HASH_MASK (TRACKER_HASH_SIZE - 1)

enum conn_state {
    CONN_SYN_SENT = 0,
    CONN_SYN_ACK_RECV = 1,
    CONN_ESTABLISHED = 2
};

struct conn_entry {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    int state;
    time_t timestamp;
    struct conn_entry *next;
};

static struct conn_entry **g_conn_table = NULL;
static int g_max_conns = 65535;
static int g_active_count = 0;
static int g_tracker_initialized = 0;
static char g_trk_err[256] = {0};

static uint32_t conn_hash(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | (uint32_t)dst_port;
    h ^= (h >> 16) ^ (h >> 8);
    return h & TRACKER_HASH_MASK;
}

static struct conn_entry *find_entry(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    if (!g_conn_table) return NULL;
    uint32_t h = conn_hash(src_ip, dst_ip, src_port, dst_port);
    struct conn_entry *cur = g_conn_table[h];
    while (cur) {
        if (cur->src_ip == src_ip && cur->dst_ip == dst_ip &&
            cur->src_port == src_port && cur->dst_port == dst_port) {
            return cur;
        }
        cur = cur->next;
    }
    return NULL;
}

EXPORT int tracker_init(int max_conns)
{
    if (g_tracker_initialized) {
        for (int i = 0; i < TRACKER_HASH_SIZE; i++) {
            struct conn_entry *cur = g_conn_table[i];
            while (cur) {
                struct conn_entry *tmp = cur;
                cur = cur->next;
                free(tmp);
            }
            g_conn_table[i] = NULL;
        }
    }

    g_conn_table = (struct conn_entry **)calloc((size_t)TRACKER_HASH_SIZE, sizeof(struct conn_entry *));
    if (!g_conn_table) {
        snprintf(g_trk_err, sizeof(g_trk_err), "calloc failed: %s", strerror(errno));
        return -1;
    }

    if (max_conns > 0 && max_conns <= 65535) {
        g_max_conns = max_conns;
    } else {
        g_max_conns = 65535;
    }
    g_active_count = 0;
    g_tracker_initialized = 1;
    return 0;
}

EXPORT int tracker_syn_sent(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq)
{
    if (!g_tracker_initialized || !g_conn_table) {
        snprintf(g_trk_err, sizeof(g_trk_err), "tracker not initialized");
        return -1;
    }
    if (g_active_count >= g_max_conns) {
        snprintf(g_trk_err, sizeof(g_trk_err), "max connections reached");
        return -1;
    }
    if (find_entry(src_ip, dst_ip, src_port, dst_port)) {
        return 0;
    }

    struct conn_entry *e = (struct conn_entry *)malloc(sizeof(struct conn_entry));
    if (!e) {
        snprintf(g_trk_err, sizeof(g_trk_err), "malloc: %s", strerror(errno));
        return -1;
    }
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->seq = seq;
    e->ack = 0;
    e->state = CONN_SYN_SENT;
    e->timestamp = time(NULL);

    uint32_t h = conn_hash(src_ip, dst_ip, src_port, dst_port);
    e->next = g_conn_table[h];
    g_conn_table[h] = e;
    __sync_fetch_and_add(&g_active_count, 1);
    return 0;
}

EXPORT int tracker_synack_recv(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack)
{
    if (!g_tracker_initialized || !g_conn_table) {
        snprintf(g_trk_err, sizeof(g_trk_err), "tracker not initialized");
        return -1;
    }

    struct conn_entry *e = find_entry(src_ip, dst_ip, src_port, dst_port);
    if (!e) {
        snprintf(g_trk_err, sizeof(g_trk_err), "connection not found");
        return -1;
    }
    e->seq = seq;
    e->ack = ack;
    e->state = CONN_SYN_ACK_RECV;
    e->timestamp = time(NULL);
    return 0;
}

EXPORT int tracker_established(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    if (!g_tracker_initialized || !g_conn_table) {
        snprintf(g_trk_err, sizeof(g_trk_err), "tracker not initialized");
        return -1;
    }

    struct conn_entry *e = find_entry(src_ip, dst_ip, src_port, dst_port);
    if (!e) {
        snprintf(g_trk_err, sizeof(g_trk_err), "connection not found");
        return -1;
    }
    e->state = CONN_ESTABLISHED;
    e->timestamp = time(NULL);
    return 0;
}

EXPORT int tracker_teardown(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
    if (!g_tracker_initialized || !g_conn_table) {
        snprintf(g_trk_err, sizeof(g_trk_err), "tracker not initialized");
        return -1;
    }

    uint32_t h = conn_hash(src_ip, dst_ip, src_port, dst_port);
    struct conn_entry *cur = g_conn_table[h];
    struct conn_entry *prev = NULL;

    while (cur) {
        if (cur->src_ip == src_ip && cur->dst_ip == dst_ip &&
            cur->src_port == src_port && cur->dst_port == dst_port) {
            if (prev)
                prev->next = cur->next;
            else
                g_conn_table[h] = cur->next;
            free(cur);
            __sync_fetch_and_sub(&g_active_count, 1);
            return 0;
        }
        prev = cur;
        cur = cur->next;
    }
    return 0;
}

EXPORT int tracker_count_active(void)
{
    return __sync_add_and_fetch(&g_active_count, 0);
}

EXPORT void tracker_cleanup(time_t timeout)
{
    if (!g_tracker_initialized || !g_conn_table) return;
    if (timeout <= 0) timeout = 60;

    time_t now = time(NULL);
    int cleaned = 0;

    for (int i = 0; i < TRACKER_HASH_SIZE; i++) {
        struct conn_entry *cur = g_conn_table[i];
        struct conn_entry *prev = NULL;

        while (cur) {
            if (now - cur->timestamp > timeout) {
                struct conn_entry *tmp = cur;
                if (prev)
                    prev->next = cur->next;
                else
                    g_conn_table[i] = cur->next;
                cur = cur->next;
                free(tmp);
                __sync_fetch_and_sub(&g_active_count, 1);
                cleaned++;
            } else {
                prev = cur;
                cur = cur->next;
            }
        }
    }

    if (cleaned > 0) {
        fprintf(stderr, "tracker_cleanup: removed %d stale connections\n", cleaned);
    }
}
