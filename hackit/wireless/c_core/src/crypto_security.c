#include "crypto_security.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    uint32_t state[5];
    uint64_t count;
    unsigned char buffer[SHA1_BLOCK_SIZE];
    unsigned int buffer_len;
} sha1_ctx;

static uint32_t sha1_rotl32(uint32_t value, unsigned int bits) {
    return (value << bits) | (value >> (32 - bits));
}

static void sha1_transform(sha1_ctx *ctx) {
    uint32_t w[80];
    uint32_t a, b, c, d, e, temp;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)ctx->buffer[i * 4] << 24) |
               ((uint32_t)ctx->buffer[i * 4 + 1] << 16) |
               ((uint32_t)ctx->buffer[i * 4 + 2] << 8) |
               ((uint32_t)ctx->buffer[i * 4 + 3]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = sha1_rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = sha1_rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rotl32(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_init(sha1_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
    ctx->buffer_len = 0;
}

static void sha1_update(sha1_ctx *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->buffer_len++] = data[i];
        ctx->count += 8;
        if (ctx->buffer_len == SHA1_BLOCK_SIZE) {
            sha1_transform(ctx);
            ctx->buffer_len = 0;
        }
    }
}

static void sha1_final(sha1_ctx *ctx, unsigned char *digest) {
    uint64_t bits = ctx->count;
    int i;

    ctx->buffer[ctx->buffer_len++] = 0x80;
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < SHA1_BLOCK_SIZE)
            ctx->buffer[ctx->buffer_len++] = 0;
        sha1_transform(ctx);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 56)
        ctx->buffer[ctx->buffer_len++] = 0;

    for (i = 0; i < 8; i++)
        ctx->buffer[56 + i] = (unsigned char)((bits >> (56 - i * 8)) & 0xFF);

    sha1_transform(ctx);

    for (i = 0; i < 5; i++) {
        digest[i * 4]     = (unsigned char)((ctx->state[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = (unsigned char)((ctx->state[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = (unsigned char)((ctx->state[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = (unsigned char)(ctx->state[i] & 0xFF);
    }
}

static void hmac_sha1(const unsigned char *key, size_t key_len,
                      const unsigned char *data, size_t data_len,
                      unsigned char *mac) {
    sha1_ctx ctx;
    unsigned char k_ipad[SHA1_BLOCK_SIZE];
    unsigned char k_opad[SHA1_BLOCK_SIZE];
    unsigned char tk[SHA1_DIGEST_SIZE];
    int i;

    if (key_len > SHA1_BLOCK_SIZE) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, tk);
        key = tk;
        key_len = SHA1_DIGEST_SIZE;
    }

    memset(k_ipad, 0, SHA1_BLOCK_SIZE);
    memset(k_opad, 0, SHA1_BLOCK_SIZE);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }

    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, mac);

    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, mac, SHA1_DIGEST_SIZE);
    sha1_final(&ctx, mac);
}

static void pbkdf2_sha1(const char *password, const unsigned char *salt, size_t salt_len,
                        int iterations, unsigned char *output, size_t output_len) {
    unsigned char *U = malloc(SHA1_DIGEST_SIZE);
    unsigned char *T = malloc(SHA1_DIGEST_SIZE);
    unsigned char *block = malloc(salt_len + 4);
    int block_count = (int)((output_len + SHA1_DIGEST_SIZE - 1) / SHA1_DIGEST_SIZE);
    int i, j, k;

    memcpy(block, salt, salt_len);

    for (i = 1; i <= block_count; i++) {
        block[salt_len]     = (unsigned char)((i >> 24) & 0xFF);
        block[salt_len + 1] = (unsigned char)((i >> 16) & 0xFF);
        block[salt_len + 2] = (unsigned char)((i >> 8) & 0xFF);
        block[salt_len + 3] = (unsigned char)(i & 0xFF);

        hmac_sha1((const unsigned char*)password, strlen(password), block, salt_len + 4, T);

        memcpy(U, T, SHA1_DIGEST_SIZE);

        for (j = 1; j < iterations; j++) {
            hmac_sha1((const unsigned char*)password, strlen(password), U, SHA1_DIGEST_SIZE, U);
            for (k = 0; k < SHA1_DIGEST_SIZE; k++)
                T[k] ^= U[k];
        }

        for (j = 0; j < SHA1_DIGEST_SIZE && (i - 1) * SHA1_DIGEST_SIZE + j < (int)output_len; j++)
            output[(i - 1) * SHA1_DIGEST_SIZE + j] = T[j];
    }

    free(U);
    free(T);
    free(block);
}

bool hackit_crypto_pbkdf2_sha1(const char* password, const uint8_t* ssid, size_t ssid_len, uint8_t* psk_out) {
    if (!password || !ssid || !psk_out || ssid_len == 0) return false;
    pbkdf2_sha1(password, ssid, ssid_len, 4096, psk_out, 32);
    return true;
}

bool hackit_crypto_verify_mic(const uint8_t* psk, const uint8_t* eapol_frame, size_t len, const uint8_t* expected_mic) {
    unsigned char computed_mic[SHA1_DIGEST_SIZE];
    hmac_sha1(psk, 16, eapol_frame, len, computed_mic);
    return memcmp(computed_mic, expected_mic, 16) == 0;
}

bool hackit_crypto_compute_pmkid(const uint8_t* pmk, const uint8_t* ap_mac, const uint8_t* client_mac, uint8_t* pmkid_out) {
    unsigned char data[20];
    const char label[] = "PMK Name";
    memcpy(data, label, 8);
    memcpy(data + 8, ap_mac, 6);
    memcpy(data + 14, client_mac, 6);
    unsigned char full[SHA1_DIGEST_SIZE];
    hmac_sha1(pmk, 32, data, 20, full);
    memcpy(pmkid_out, full, 16);
    return true;
}
