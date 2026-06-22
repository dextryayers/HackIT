#pragma once

/**
 * dpi_evader.h — Deep Packet Inspection evasion engine.
 *
 * Implements payload fragmentation, base64 / gzip encoding, and
 * out-of-order delivery to defeat common DPI classifiers.
 */

#include "engine.h"
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/*  Fragment descriptor                                                */
/* ------------------------------------------------------------------ */
typedef struct fragment_t {
    int      offset;                       /* offset within original      */
    int      length;                       /* fragment payload length     */
    uint8_t  data[1500];                   /* fragment payload            */
    uint8_t  flags;                        /* IP MF bit or custom flags   */
} fragment_t;

/* ------------------------------------------------------------------ */
/*  DPI evasion configuration                                          */
/* ------------------------------------------------------------------ */
typedef struct dpi_config_t {
    int  fragment_count;                   /* number of fragments (2-10) */
    int  min_frag_size;                    /* minimum fragment (48-200)  */
    int  max_frag_size;                    /* maximum fragment (500-1400)*/
    bool encode_base64;                    /* base64-encode payload      */
    bool encode_gzip;                      /* gzip-compress payload      */
    int  interleave_delay_us;              /* delay between frags (µs)   */
    bool randomize_order;                  /* send fragments OOO         */
} dpi_config_t;

/* ------------------------------------------------------------------ */
/*  Base64 encoding tables                                             */
/* ------------------------------------------------------------------ */
static const uint8_t dpi_base64_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const uint8_t dpi_base64_dec[256] = {
    [0 ... 255] = 0xFF,                    /* default: invalid          */
    ['+'] = 62,  ['/'] = 63,
    ['0'] = 52,  ['1'] = 53,  ['2'] = 54,  ['3'] = 55,  ['4'] = 56,
    ['5'] = 57,  ['6'] = 58,  ['7'] = 59,  ['8'] = 60,  ['9'] = 61,
    ['A'] = 0,   ['B'] = 1,   ['C'] = 2,   ['D'] = 3,   ['E'] = 4,
    ['F'] = 5,   ['G'] = 6,   ['H'] = 7,   ['I'] = 8,   ['J'] = 9,
    ['K'] = 10,  ['L'] = 11,  ['M'] = 12,  ['N'] = 13,  ['O'] = 14,
    ['P'] = 15,  ['Q'] = 16,  ['R'] = 17,  ['S'] = 18,  ['T'] = 19,
    ['U'] = 20,  ['V'] = 21,  ['W'] = 22,  ['X'] = 23,  ['Y'] = 24,
    ['Z'] = 25,
    ['a'] = 26,  ['b'] = 27,  ['c'] = 28,  ['d'] = 29,  ['e'] = 30,
    ['f'] = 31,  ['g'] = 32,  ['h'] = 33,  ['i'] = 34,  ['j'] = 35,
    ['k'] = 36,  ['l'] = 37,  ['m'] = 38,  ['n'] = 39,  ['o'] = 40,
    ['p'] = 41,  ['q'] = 42,  ['r'] = 43,  ['s'] = 44,  ['t'] = 45,
    ['u'] = 46,  ['v'] = 47,  ['w'] = 48,  ['x'] = 49,  ['y'] = 50,
    ['z'] = 51,
};

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */

/**
 * dpi_evader_init() - Initialise the DPI evader with configuration.
 * @cfg: evasion parameters (may be NULL for safe defaults).
 * Return: 0 on success, -1 on invalid config.
 */
int dpi_evader_init(const dpi_config_t *cfg);

/**
 * dpi_fragment_payload() - Split a payload into IP fragments.
 * @payload:    original payload.
 * @payload_len:payload length.
 * @frags:      (out) caller-owned array of fragment_t (size fragment_count).
 * Return: number of fragments produced, or -1 on error.
 */
int dpi_fragment_payload(const uint8_t *payload, size_t payload_len,
                         fragment_t *frags);

/**
 * dpi_encode_base64() - Base64-encode a buffer (in-place safe).
 * @in:      input data.
 * @in_len:  input length.
 * @out:     output buffer (must be at least 4 * ceil(in_len/3) + 1).
 * Return: encoded length (excluding NUL).
 */
size_t dpi_encode_base64(const uint8_t *in, size_t in_len, uint8_t *out);

/**
 * dpi_encode_gzip() - Gzip-compress a payload.
 * @in:      input data.
 * @in_len:  input length.
 * @out:     (out) allocated compressed buffer (caller must free).
 * @out_len: (out) compressed length.
 * Return: 0 on success, -1 on error.
 */
int dpi_encode_gzip(const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len);

/**
 * dpi_randomize_frags() - Shuffle fragment array into random order.
 * @frags:      array of fragments.
 * @frag_count: number of fragments.
 */
void dpi_randomize_frags(fragment_t *frags, int frag_count);

/**
 * dpi_send_fragmented() - Transmit fragments via the configured engine.
 * @frags:      array of fragments.
 * @frag_count: number of fragments.
 * Return: number of fragments successfully sent, or -1 on error.
 */
int dpi_send_fragmented(const fragment_t *frags, int frag_count);
