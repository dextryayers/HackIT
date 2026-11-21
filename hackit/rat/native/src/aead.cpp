// ChaCha20 + Poly1305 (RFC 8439) and the AEAD construction around them.
// Self-contained: no OpenSSL, no libsodium, so the .so stays tiny and loads on
// every Android ABI without a dependency on a platform crypto build.
#include "hackit.h"

#include <cstring>

namespace hackit {
namespace {

inline uint32_t rotl(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

inline void quarter(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

const char kSigma[17] = "expand 32-byte k";

inline uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void store32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}


}  // namespace

void chacha20_block(uint32_t out[16], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    uint32_t state[16];
    state[0] = load32((const uint8_t *)kSigma + 0);
    state[1] = load32((const uint8_t *)kSigma + 4);
    state[2] = load32((const uint8_t *)kSigma + 8);
    state[3] = load32((const uint8_t *)kSigma + 12);
    for (int i = 0; i < 8; ++i) state[4 + i] = load32(key + i * 4);
    state[12] = counter;
    state[13] = load32(nonce + 0);
    state[14] = load32(nonce + 4);
    state[15] = load32(nonce + 8);

    uint32_t work[16];
    std::memcpy(work, state, sizeof(work));
    for (int i = 0; i < 10; ++i) {
        quarter(work[0], work[4], work[8], work[12]);
        quarter(work[1], work[5], work[9], work[13]);
        quarter(work[2], work[6], work[10], work[14]);
        quarter(work[3], work[7], work[11], work[15]);
        quarter(work[0], work[5], work[10], work[15]);
        quarter(work[1], work[6], work[11], work[12]);
        quarter(work[2], work[7], work[8], work[13]);
        quarter(work[3], work[4], work[9], work[14]);
    }
    for (int i = 0; i < 16; ++i) out[i] = work[i] + state[i];
}

void chacha20_xor(uint8_t *data, size_t len, const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    uint32_t block[16];
    uint8_t stream[64];
    size_t offset = 0;
    while (offset < len) {
        chacha20_block(block, key, counter++, nonce);
        for (int i = 0; i < 16; ++i) store32(stream + i * 4, block[i]);
        size_t take = len - offset < 64 ? len - offset : 64;
        for (size_t i = 0; i < take; ++i) data[offset + i] ^= stream[i];
        offset += take;
    }
}

// Poly1305 with 26-bit limbs (5 accumulators, 130-bit carries).
void poly1305(const uint8_t *msg, size_t len, const uint8_t key[32], uint8_t tag[16]) {
    uint32_t r0 = load32(key + 0) & 0x3ffffff;
    uint32_t r1 = (load32(key + 3) >> 2) & 0x3ffff03;
    uint32_t r2 = (load32(key + 6) >> 4) & 0x3ffc0ff;
    uint32_t r3 = (load32(key + 9) >> 6) & 0x3f03fff;
    uint32_t r4 = (load32(key + 12) >> 8) & 0x00fffff;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint8_t block[17];
    while (len > 0) {
        size_t take = len < 16 ? len : 16;
        std::memset(block, 0, sizeof(block));
        std::memcpy(block, msg, take);
        block[take] = 1;  // pad bit; byte 16 needs the extra slot on full blocks
        msg += take;
        len -= take;

        uint32_t t0 = load32(block + 0) & 0x3ffffff;
        uint32_t t1 = (load32(block + 3) >> 2) & 0x3ffffff;
        uint32_t t2 = (load32(block + 6) >> 4) & 0x3ffffff;
        uint32_t t3 = (load32(block + 9) >> 6) & 0x3ffffff;
        uint32_t t4 = (load32(block + 12) >> 8) & 0x3ffffff;
        if (take == 16) t4 += (1u << 24);  // 2^128 pad bit sits in limb 4 bit 24
        h0 += t0;
        h1 += t1 + ((h0 >> 26)); h0 &= 0x3ffffff;
        h2 += t2 + ((h1 >> 26)); h1 &= 0x3ffffff;
        h3 += t3 + ((h2 >> 26)); h2 &= 0x3ffffff;
        h4 += t4 + ((h3 >> 26)); h3 &= 0x3ffffff;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        h0 = (uint32_t)(d0 & 0x3ffffff); d1 += d0 >> 26;
        h1 = (uint32_t)(d1 & 0x3ffffff); d2 += d1 >> 26;
        h2 = (uint32_t)(d2 & 0x3ffffff); d3 += d2 >> 26;
        h3 = (uint32_t)(d3 & 0x3ffffff); d4 += d3 >> 26;
        h4 = (uint32_t)(d4 & 0x3ffffff);
        h0 = (uint32_t)((d4 >> 26) * 5 + h0);
        h1 += h0 >> 26; h0 &= 0x3ffffff;
    }

    uint32_t c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    if (!(g4 & 0x80000000)) {
        h0 = g0; h1 = g1; h2 = g2; h3 = g3; h4 = g4;
    }

    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    uint64_t f = (uint64_t)h0 + load32(key + 16);
    h0 = (uint32_t)f;
    f = (uint64_t)h1 + load32(key + 20) + (f >> 32);
    h1 = (uint32_t)f;
    f = (uint64_t)h2 + load32(key + 24) + (f >> 32);
    h2 = (uint32_t)f;
    f = (uint64_t)h3 + load32(key + 28) + (f >> 32);
    h3 = (uint32_t)f;

    store32(tag + 0, h0);
    store32(tag + 4, h1);
    store32(tag + 8, h2);
    store32(tag + 12, h3);
}

size_t aead_seal(uint8_t *out, size_t cap, const uint8_t key[32], const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len, const uint8_t *plain, size_t len) {
    if (cap < len + kTagLen) return 0;
    uint32_t block[16];
    uint8_t poly_key[64];
    chacha20_block(block, key, 0, nonce);
    for (int i = 0; i < 16; ++i) store32(poly_key + i * 4, block[i]);

    std::memcpy(out, plain, len);
    chacha20_xor(out, len, key, 1, nonce);

    // MAC over aad || pad16 || ciphertext || pad16 || len64(aad) || len64(ct)
    std::vector<uint8_t> mac;
    mac.reserve(aad_len + len + 32);
    mac.insert(mac.end(), aad, aad + aad_len);
    if (aad_len % 16) mac.insert(mac.end(), 16 - aad_len % 16, 0);
    mac.insert(mac.end(), out, out + len);
    if (len % 16) mac.insert(mac.end(), 16 - len % 16, 0);
    uint8_t lens[16];
    store32(lens, (uint32_t)aad_len);
    store32(lens + 4, 0);
    store32(lens + 8, (uint32_t)len);
    store32(lens + 12, 0);
    mac.insert(mac.end(), lens, lens + 16);

    uint8_t tag[16];
    poly1305(mac.data(), mac.size(), poly_key, tag);
    std::memcpy(out + len, tag, kTagLen);
    std::memset(poly_key, 0, sizeof(poly_key));
    return len + kTagLen;
}

long aead_open(uint8_t *out, size_t cap, const uint8_t key[32], const uint8_t *nonce,
               const uint8_t *aad, size_t aad_len, const uint8_t *cipher, size_t len) {
    if (len < kTagLen || cap < len - kTagLen) return -1;
    size_t ct = len - kTagLen;

    uint32_t block[16];
    uint8_t poly_key[64];
    chacha20_block(block, key, 0, nonce);
    for (int i = 0; i < 16; ++i) store32(poly_key + i * 4, block[i]);

    std::vector<uint8_t> mac;
    mac.reserve(aad_len + ct + 32);
    mac.insert(mac.end(), aad, aad + aad_len);
    if (aad_len % 16) mac.insert(mac.end(), 16 - aad_len % 16, 0);
    mac.insert(mac.end(), cipher, cipher + ct);
    if (ct % 16) mac.insert(mac.end(), 16 - ct % 16, 0);
    uint8_t lens[16];
    store32(lens, (uint32_t)aad_len);
    store32(lens + 4, 0);
    store32(lens + 8, (uint32_t)ct);
    store32(lens + 12, 0);
    mac.insert(mac.end(), lens, lens + 16);

    uint8_t tag[16];
    poly1305(mac.data(), mac.size(), poly_key, tag);
    if (std::memcmp(tag, cipher + ct, kTagLen) != 0) return -1;

    std::memcpy(out, cipher, ct);
    chacha20_xor(out, ct, key, 1, nonce);
    return (long)ct;
}

}  // namespace hackit
