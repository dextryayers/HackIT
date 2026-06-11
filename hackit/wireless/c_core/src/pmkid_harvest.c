#include "pmkid_harvest.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifdef HACKIT_HAS_PCAP
#ifdef _WIN32
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
#endif

/* ---- hex conversion utilities ---------------------------------------- */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_byte_to_str(const uint8_t byte, char* out) {
    static const char hexdigits[] = "0123456789abcdef";
    out[0] = hexdigits[(byte >> 4) & 0x0F];
    out[1] = hexdigits[byte & 0x0F];
    return true;
}

static void bytes_to_hex(const uint8_t* data, int len, char* out) {
    for (int i = 0; i < len; i++)
        hex_byte_to_str(data[i], &out[i * 2]);
    out[len * 2] = '\0';
}

/* ---- IEEE 802.1X / EAPOL constants ----------------------------------- */

#define EAPOL_ETHERTYPE      0x888E
#define EAPOL_KEY_TYPE       3
#define PMKID_TAG_TYPE       0x01
#define PMKID_LEN            16
#define EAPOL_MIN_HDR        4     /* type(1) + body_len(2) + key_type(1) */

/* Minimal EAPOL-Key header offsets (after 802.3 ethernet header + LLC/SNAP) */
#define EAPOL_OFFSET_ETH_TYPE_LO  12
#define EAPOL_OFFSET_ETH_TYPE_HI  13

/* PMKID is the first 16 bytes of the Key Data field in a 4-way msg 1/3
 * when the EAPOL-Key frame has Key Information Key Descriptor Version = 2
 * and the PMKID sub-element is present (type 0x01).                         */

/* ---- public API ------------------------------------------------------- */

bool hackit_pmkid_parse_eapol(const uint8_t* frame, int len, char* out_pmkid_hex, int max_len) {
    if (!frame || !out_pmkid_hex || max_len < HACKIT_PMKID_HEX_LEN)
        return false;

    /*
     * Expect a raw 802.3 / LLC+SNAP encapsulated EAPOL frame:
     *   bytes  0-5   destination MAC
     *   bytes  6-11  source MAC
     *   bytes 12-13  EtherType  0x88 0x8E
     *   byte  14     EAPOL version
     *   byte  15     EAPOL type (3 = Key)
     *   bytes 16-17  body length (big-endian)
     *   ...          EAPOL-Key body
     */
    if (len < 40) /* minimum for a viable EAPOL-Key frame */
        return false;

    /* Verify EtherType 0x888E */
    if (frame[EAPOL_OFFSET_ETH_TYPE_LO] != 0x88 ||
        frame[EAPOL_OFFSET_ETH_TYPE_HI] != 0x8E)
        return false;

    int eapol_off = 14; /* start of EAPOL header */

    /* EAPOL type must be Key (3) */
    if (frame[eapol_off + 1] != EAPOL_KEY_TYPE)
        return false;

    /* Key body length (2 bytes big-endian) */
    uint16_t key_body_len = ((uint16_t)frame[eapol_off + 2] << 8) | frame[eapol_off + 3];
    int key_frame_start = eapol_off + 4; /* after EAPOL fixed header */

    /* Total frame must contain the key body */
    if (key_frame_start + (int)key_body_len > len)
        return false;

    /* Key Information field is at offset 1 from key body start (2 bytes LE) */
    int ki_off = key_frame_start + 1;
    if (ki_off + 1 >= len) return false;
    uint16_t key_info = ((uint16_t)frame[ki_off + 1] << 8) | frame[ki_off];

    /* Key Descriptor Version: bits 0-2 of Key Information */
    uint8_t kdv = (uint8_t)(key_info & 0x07);
    if (kdv != 2 && kdv != 3) /* WPA/WPA2 PMKID uses version 2 or 3 */
        return false;

    /* The Key Data length is at offset 97-98 from key body start (2 bytes LE).
     * For a standard EAPOL-Key frame layout:
     *   offset 0-1:   Key Info
     *   offset 2-3:   Key Length
     *   offset 4-11:  Replay Counter
     *   offset 12-19: Nonce
     *   offset 20-35: MIC (16 bytes)
     *   offset 36-37: Key Data Length
     *   offset 38+:   Key Data
     */
    if (key_body_len < 44) return false; /* need at least 38+6 bytes */

    int kd_len_off = key_frame_start + 36;
    if (kd_len_off + 1 >= len) return false;
    uint16_t kd_len = ((uint16_t)frame[kd_len_off + 1] << 8) | frame[kd_len_off];
    int kd_start = kd_len_off + 2;

    if (kd_start + (int)kd_len > len) return false;

    /* Walk through Key Data sub-elements looking for PMKID (type 0x01) */
    int pos = kd_start;
    int remaining = (int)kd_len;
    while (remaining >= 3) { /* minimum sub-element: type(1)+len(1)+data(1) */
        uint8_t sub_type = frame[pos];
        uint8_t sub_len  = frame[pos + 1];

        if (sub_len == 0 || (pos + 2 + sub_len) > (kd_start + kd_len))
            break;

        if (sub_type == PMKID_TAG_TYPE && sub_len == PMKID_LEN) {
            /* Found PMKID */
            bytes_to_hex(&frame[pos + 2], PMKID_LEN, out_pmkid_hex);
            return true;
        }

        pos += 2 + sub_len;
        remaining -= 2 + sub_len;
    }

    return false;
}

bool hackit_pmkid_extract_from_pcap(const char* pcap_path, char* out_pmkid_hex, int max_len) {
    if (!pcap_path || !out_pmkid_hex || max_len < HACKIT_PMKID_HEX_LEN)
        return false;

#ifdef HACKIT_HAS_PCAP
    char errbuf[256];
    memset(errbuf, 0, sizeof(errbuf));

    pcap_t* handle = pcap_open_offline(pcap_path, errbuf);
    if (!handle) {
        fprintf(stderr, "[PMKID] Cannot open pcap '%s': %s\n", pcap_path, errbuf);
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    bool found = false;

    while (pcap_next_ex(handle, &header, &pkt_data) == 1) {
        if ((int)header->caplen < 40) continue;

        if (pkt_data[12] == 0x88 && pkt_data[13] == 0x8E) {
            if (hackit_pmkid_parse_eapol(pkt_data, (int)header->caplen, out_pmkid_hex, max_len)) {
                found = true;
                break;
            }
        }
    }

    pcap_close(handle);
    return found;
#else
    fprintf(stderr, "[PMKID] pcap not available. Install libpcap/Npcap for PCAP parsing.\n");
    return false;
#endif
}

bool hackit_pmkid_format_hc22000(const char* pmkid_hex, const char* ap_mac,
                                 const char* client_mac, const char* essid,
                                 char* out_line, int max_len) {
    if (!pmkid_hex || !ap_mac || !client_mac || !essid || !out_line || max_len < 16)
        return false;

    int written = snprintf(out_line, max_len,
        "*1*%s*%s*%s*%s*",
        pmkid_hex,
        ap_mac,
        client_mac,
        essid);

    if (written < 0 || written >= max_len) {
        out_line[0] = '\0';
        return false;
    }
    return true;
}

bool hackit_pmkid_verify_complete(const uint8_t* frame, int len) {
    if (!frame || len < 40)
        return false;

    /* Verify EtherType */
    if (frame[EAPOL_OFFSET_ETH_TYPE_LO] != 0x88 ||
        frame[EAPOL_OFFSET_ETH_TYPE_HI] != 0x8E)
        return false;

    int eapol_off = 14;
    if (eapol_off + 4 > len) return false;

    /* EAPOL type must be Key */
    if (frame[eapol_off + 1] != EAPOL_KEY_TYPE)
        return false;

    uint16_t key_body_len = ((uint16_t)frame[eapol_off + 2] << 8) | frame[eapol_off + 3];
    int key_frame_start = eapol_off + 4;

    if (key_frame_start + (int)key_body_len > len)
        return false;

    /* Key Info check – version must be 2 or 3 */
    if (key_body_len < 44) return false;
    int ki_off = key_frame_start + 1;
    uint16_t key_info = ((uint16_t)frame[ki_off + 1] << 8) | frame[ki_off];
    uint8_t kdv = (uint8_t)(key_info & 0x07);

    if (kdv != 2 && kdv != 3)
        return false;

    /* Key Data Length must be non-zero */
    int kd_len_off = key_frame_start + 36;
    if (kd_len_off + 1 >= len) return false;
    uint16_t kd_len = ((uint16_t)frame[kd_len_off + 1] << 8) | frame[kd_len_off];

    return (kd_len > 0);
}
