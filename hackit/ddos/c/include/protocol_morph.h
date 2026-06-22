#pragma once

/**
 * protocol_morph.h — shape-shifting packet engine.
 *
 * Implements per-packet TCP header normalisation evasion by varying
 * TTL, window size, and option layout across every burst.
 */

#include "engine.h"

/* ------------------------------------------------------------------ */
/*  TCP option-kind constants                                          */
/* ------------------------------------------------------------------ */
#define TCPOPT_EOL        0
#define TCPOPT_NOP        1
#define TCPOPT_MSS        2
#define TCPOPT_WINDOW     3
#define TCPOPT_SACK_PERM  4
#define TCPOPT_TIMESTAMP  8

/* ------------------------------------------------------------------ */
/*  TCP option descriptor                                              */
/* ------------------------------------------------------------------ */
typedef struct tcp_option_t {
    uint8_t kind;                          /* option kind               */
    uint8_t len;                           /* option length (incl. header) */
    uint8_t data[40];                      /* option payload            */
} tcp_option_t;

/* ------------------------------------------------------------------ */
/*  Morph engine configuration                                         */
/* ------------------------------------------------------------------ */
typedef struct morph_config_t {
    uint8_t  ttl_min;                      /* minimum TTL               */
    uint8_t  ttl_max;                      /* maximum TTL               */
    uint16_t window_min;                   /* minimum TCP window        */
    uint16_t window_max;                   /* maximum TCP window        */
    bool     sack_ok;                      /* enable SACK-permitted     */
    bool     timestamp_ok;                 /* enable timestamps         */
    bool     nop_ok;                       /* enable NOP padding        */
    bool     ws_ok;                        /* enable window scale       */
    int      morph_interval;               /* packets before re-morph   */
} morph_config_t;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */

/**
 * morph_init() - Initialise the morph engine with a configuration.
 * @cfg: configuration to apply (may be NULL for defaults).
 * Return: 0 on success, -1 on error.
 */
int morph_init(const morph_config_t *cfg);

/**
 * morph_apply() - Apply morph transformations to a raw packet buffer.
 * @pkt:       mutable packet buffer (must have IP + TCP headers).
 * @pkt_len:   total packet length.
 * @seq:       (out) the next TCP sequence number used.
 * Return: 0 on success, -1 on error.
 */
int morph_apply(uint8_t *pkt, size_t pkt_len, uint32_t *seq);

/**
 * morph_random_ttl() - Generate a random TTL in [cfg.ttl_min, cfg.ttl_max].
 * Return: the chosen TTL value.
 */
uint8_t morph_random_ttl(void);

/**
 * morph_random_window() - Generate a random window in [cfg.window_min, cfg.window_max].
 * Return: the chosen window value.
 */
uint16_t morph_random_window(void);

/**
 * morph_build_options() - Build a TCP options block into a buffer.
 * @buf:    output buffer (at least 40 bytes).
 * @opts:   array of tcp_option_t descriptors.
 * @nopts:  number of descriptors.
 * Return: total length of the options block written.
 */
int morph_build_options(uint8_t *buf, const tcp_option_t *opts, int nopts);

/**
 * morph_next_sequence() - Advance the per-flow sequence number.
 * @current: current SEQ value.
 * @len:      payload length (advance = len).
 * Return: the next SEQ value.
 */
uint32_t morph_next_sequence(uint32_t current, uint32_t len);
