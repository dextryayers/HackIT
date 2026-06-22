#pragma once

/**
 * dpdk_handler.h — DPDK (Data Plane Development Kit) interface.
 *
 * Manages NIC ports, mempools, and high-performance burst send
 * routines for line-rate packet injection.
 */

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

/* ------------------------------------------------------------------ */
/*  Per-port pool descriptor                                           */
/* ------------------------------------------------------------------ */
struct dpdk_pool_t {
    uint16_t        port_id;               /* DPDK port identifier      */
    uint16_t        nb_rxd;                /* RX descriptor count       */
    uint16_t        nb_txd;                /* TX descriptor count       */
    char            pool_name[32];         /* mempool name (debug)      */
    struct rte_mempool *mbuf_pool;         /* associated mempool        */
    int             burst_size;            /* burst size for this port  */
    uint64_t        total_sent;            /* total packets transmitted */
};

/* ------------------------------------------------------------------ */
/*  Global DPDK configuration                                          */
/* ------------------------------------------------------------------ */
struct dpdk_config_t {
    struct dpdk_pool_t ports[16];          /* up to 16 ports            */
    int             port_count;            /* active port count         */
    int             lcore_count;           /* lcores in use             */
    unsigned        mempool_size;          /* elements per mempool      */
    unsigned        cache_size;            /* per-lcore cache           */
};

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */

/**
 * dpdk_init() - Initialise EAL and probe devices.
 * @argc, @argv: command-line arguments (may be modified by EAL).
 * Return: 0 on success, -1 on error.
 */
int dpdk_init(int argc, char **argv);

/**
 * dpdk_port_init() - Configure and bring up a single port.
 * @cfg:   port configuration (must have port_id, nb_rxd/nb_txd set).
 * @pool_name: unique name for the mempool.
 * Return: 0 on success, -1 on error.
 */
int dpdk_port_init(struct dpdk_pool_t *cfg, const char *pool_name);

/**
 * dpdk_burst_send() - Transmit a burst of packets on one port.
 * @port_id: target DPDK port.
 * @pkts:    array of mbuf pointers.
 * @nb_pkts: number of packets in the burst (<= cfg.burst_size).
 * Return: number of packets actually sent.
 */
uint16_t dpdk_burst_send(uint16_t port_id, struct rte_mbuf **pkts,
                         uint16_t nb_pkts);

/**
 * dpdk_burst_send_multi() - Transmit bursts across all active ports.
 * @pkts:    2-D array [port][burst].
 * @nb_each: per-port burst lengths.
 * Return: total packets sent across all ports.
 */
uint64_t dpdk_burst_send_multi(struct rte_mbuf ***pkts,
                               uint16_t *nb_each);

/**
 * dpdk_stats_get() - Read aggregate transmit statistics.
 * @port_id: target port.
 * @pkts_out: (out) total packets transmitted.
 * @bytes_out: (out) total bytes transmitted.
 * Return: 0 on success, -1 on error.
 */
int dpdk_stats_get(uint16_t port_id, uint64_t *pkts_out,
                   uint64_t *bytes_out);

/**
 * dpdk_cleanup() - Release all DPDK resources and stop ports.
 */
void dpdk_cleanup(void);
