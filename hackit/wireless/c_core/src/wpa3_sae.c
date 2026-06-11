#include "wpa3_sae.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SAE_AKM_OUI_0 0x00
#define SAE_AKM_OUI_1 0x0F
#define SAE_AKM_OUI_2 0xAC
#define SAE_AKM_TYPE  0x08
#define RSN_ELEMENT_ID 0x30
#define SAE_AUTH_ALGO 3

/* ------------------------------------------------------------------ */

static const uint8_t* find_rsn_ie(const uint8_t* frame, size_t len) {
    size_t off = 36;

    if (len < 36)
        return NULL;

    while (off + 1 < len) {
        uint8_t id = frame[off];
        uint8_t elen = frame[off + 1];

        if (off + 2 + elen > len)
            break;

        if (id == RSN_ELEMENT_ID) {
            if (elen >= 2)
                return &frame[off];
            return NULL;
        }

        off += 2 + elen;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */

bool hackit_is_wpa3_sae(const uint8_t* beacon_frame, size_t len) {
    if (!beacon_frame || len < 36)
        return false;

    const uint8_t* rsnie = find_rsn_ie(beacon_frame, len);
    if (!rsnie)
        return false;

    uint8_t rsn_len = rsnie[1];
    uint16_t version = (uint16_t)(rsnie[2] | (rsnie[3] << 8));
    if (version != 1)
        return false;

    size_t off = 4;
    if (off + 4 > rsn_len) return false;
    off += 4;

    if (off + 2 > rsn_len) return false;
    uint16_t pairwise_count = (uint16_t)(rsnie[off] | (rsnie[off + 1] << 8));
    off += 2 + (size_t)pairwise_count * 4;

    if (off + 2 > rsn_len) return false;
    uint16_t akm_count = (uint16_t)(rsnie[off] | (rsnie[off + 1] << 8));
    off += 2;

    for (uint16_t i = 0; i < akm_count; i++) {
        if (off + 4 > rsn_len) break;
        if (rsnie[off]     == SAE_AKM_OUI_0 &&
            rsnie[off + 1] == SAE_AKM_OUI_1 &&
            rsnie[off + 2] == SAE_AKM_OUI_2 &&
            rsnie[off + 3] == SAE_AKM_TYPE) {
            return true;
        }
        off += 4;
    }

    return false;
}

/* ------------------------------------------------------------------ */

int hackit_parse_sae_commit(const uint8_t* frame, size_t len, uint8_t* group, uint8_t* anti_clogging) {
    if (!frame || len < 26)
        return -1;

    if ((frame[0] & 0xFC) != 0xB0)
        return 0;

    size_t off = 24;
    if (off + 6 > len) return -1;

    uint16_t algo = (uint16_t)(frame[off] | (frame[off + 1] << 8));
    uint16_t seq  = (uint16_t)(frame[off + 2] | (frame[off + 3] << 8));

    if (algo != SAE_AUTH_ALGO || seq != 1)
        return 0;

    off += 6;

    if (off + 2 > len)
        return -1;

    uint16_t group_id = (uint16_t)(frame[off] | (frame[off + 1] << 8));
    if (group)
        *group = (uint8_t)group_id;

    off += 2;

    if (anti_clogging && off < len) {
        size_t token_len = len - off;
        if (token_len > HACKIT_SAE_ANTI_CLOGGING_LEN)
            token_len = HACKIT_SAE_ANTI_CLOGGING_LEN;
        memcpy(anti_clogging, &frame[off], token_len);
    }

    return 1;
}

/* ------------------------------------------------------------------ */

int hackit_parse_sae_confirm(const uint8_t* frame, size_t len, uint8_t* confirm, uint8_t* send_confirm) {
    if (!frame || len < 26)
        return -1;

    if ((frame[0] & 0xFC) != 0xB0)
        return 0;

    size_t off = 24;
    if (off + 6 > len) return -1;

    uint16_t algo = (uint16_t)(frame[off] | (frame[off + 1] << 8));
    uint16_t seq  = (uint16_t)(frame[off + 2] | (frame[off + 3] << 8));

    if (algo != SAE_AUTH_ALGO || seq != 2)
        return 0;

    off += 6;

    if (off + 2 > len)
        return -1;

    if (send_confirm) {
        send_confirm[0] = frame[off];
        send_confirm[1] = frame[off + 1];
    }

    off += 2;

    if (confirm && off < len) {
        size_t confirm_len = len - off;
        if (confirm_len > HACKIT_SAE_CONFIRM_LEN)
            confirm_len = HACKIT_SAE_CONFIRM_LEN;
        memcpy(confirm, &frame[off], confirm_len);
    }

    return 1;
}

/* ------------------------------------------------------------------ */

bool hackit_build_sae_commit_frame(uint8_t* buf, size_t buf_len, const uint8_t* bssid, const uint8_t* sta) {
    if (!buf || !bssid || !sta)
        return false;

    size_t total = 12 + 24 + 8;
    if (buf_len < total)
        return false;

    memset(buf, 0, total);

    buf[2] = 0x0C;
    buf[12] = 0xB0;
    buf[13] = 0x00;
    buf[14] = 0x00;
    buf[15] = 0x00;

    memcpy(&buf[16], bssid, 6);
    memcpy(&buf[22], sta, 6);
    memcpy(&buf[28], bssid, 6);

    buf[36] = (uint8_t)(SAE_AUTH_ALGO & 0xFF);
    buf[37] = (uint8_t)((SAE_AUTH_ALGO >> 8) & 0xFF);
    buf[38] = 0x01;
    buf[39] = 0x00;
    buf[40] = 0x00;
    buf[41] = 0x00;
    buf[42] = 0x13;
    buf[43] = 0x00;

    return true;
}
