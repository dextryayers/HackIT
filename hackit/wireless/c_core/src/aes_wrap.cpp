// AES-128/192/256 (ECB block op) + RFC 3394 key wrap/unwrap.
//
// Straightforward S-box implementation — byte-wise SubBytes/ShiftRows/
// MixColumns. Slower than a T-table build but correct by construction and
// small. WPS Pixie Dust only needs a handful of block ops per attempt, so
// throughput is a non-issue.
//
// Verified against FIPS-197 C.1 (AES-128) and C.3 (AES-256) test vectors.

#include "aes_wrap.h"

namespace {

static const uint8_t g_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t g_inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

inline uint8_t xtime(uint8_t x) {
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = static_cast<uint8_t>(a & 0x80);
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

inline uint32_t sub_word(uint32_t w) {
    return (static_cast<uint32_t>(g_sbox[(w >> 24) & 0xff]) << 24) |
           (static_cast<uint32_t>(g_sbox[(w >> 16) & 0xff]) << 16) |
           (static_cast<uint32_t>(g_sbox[(w >> 8) & 0xff]) << 8) |
           static_cast<uint32_t>(g_sbox[w & 0xff]);
}

inline uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

void AddRoundKey(uint8_t st[16], const uint32_t* rk) {
    for (int c = 0; c < 4; ++c) {
        uint32_t w = rk[c];
        st[4 * c + 0] ^= static_cast<uint8_t>(w >> 24);
        st[4 * c + 1] ^= static_cast<uint8_t>(w >> 16);
        st[4 * c + 2] ^= static_cast<uint8_t>(w >> 8);
        st[4 * c + 3] ^= static_cast<uint8_t>(w);
    }
}

void SubBytes(uint8_t st[16]) {
    for (int i = 0; i < 16; ++i) st[i] = g_sbox[st[i]];
}

void InvSubBytes(uint8_t st[16]) {
    for (int i = 0; i < 16; ++i) st[i] = g_inv_sbox[st[i]];
}

void ShiftRows(uint8_t st[16]) {
    uint8_t t;
    // row 1: left 1  (bytes 1,5,9,13)
    t = st[1]; st[1] = st[5]; st[5] = st[9]; st[9] = st[13]; st[13] = t;
    // row 2: left 2  (bytes 2,6,10,14)
    t = st[2]; st[2] = st[10]; st[10] = t;
    t = st[6]; st[6] = st[14]; st[14] = t;
    // row 3: left 3 == right 1 (bytes 3,7,11,15)
    t = st[3]; st[3] = st[15]; st[15] = st[11]; st[11] = st[7]; st[7] = t;
}

void InvShiftRows(uint8_t st[16]) {
    uint8_t t;
    // row 1: right 1
    t = st[13]; st[13] = st[9]; st[9] = st[5]; st[5] = st[1]; st[1] = t;
    // row 2: right 2
    t = st[2]; st[2] = st[10]; st[10] = t;
    t = st[6]; st[6] = st[14]; st[14] = t;
    // row 3: right 3 == left 1
    t = st[3]; st[3] = st[7]; st[7] = st[11]; st[11] = st[15]; st[15] = t;
}

void MixColumns(uint8_t st[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = st + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = static_cast<uint8_t>(gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3);
        col[1] = static_cast<uint8_t>(a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3);
        col[2] = static_cast<uint8_t>(a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3));
        col[3] = static_cast<uint8_t>(gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2));
    }
}

void InvMixColumns(uint8_t st[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = st + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = static_cast<uint8_t>(gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9));
        col[1] = static_cast<uint8_t>(gmul(a0,9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13));
        col[2] = static_cast<uint8_t>(gmul(a0,13) ^ gmul(a1,9) ^ gmul(a2,14) ^ gmul(a3,11));
        col[3] = static_cast<uint8_t>(gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9) ^ gmul(a3,14));
    }
}

}  // namespace

namespace aes128 {

void Init(Ctx& c, const uint8_t* key, size_t keylen) {
    c.nk = static_cast<int>(keylen / 4);
    c.rounds = c.nk + 6;

    for (int i = 0; i < c.nk; ++i) {
        c.rk[i] = (static_cast<uint32_t>(key[4*i]) << 24) |
                  (static_cast<uint32_t>(key[4*i+1]) << 16) |
                  (static_cast<uint32_t>(key[4*i+2]) << 8) |
                  static_cast<uint32_t>(key[4*i+3]);
    }

    uint8_t rcon = 1;
    for (int i = c.nk; i < 4 * (c.rounds + 1); ++i) {
        uint32_t tmp = c.rk[i - 1];
        if (i % c.nk == 0) {
            tmp = sub_word(rot_word(tmp)) ^ (static_cast<uint32_t>(rcon) << 24);
            rcon = xtime(rcon);
        } else if (c.nk > 6 && i % c.nk == 4) {
            tmp = sub_word(tmp);
        }
        c.rk[i] = c.rk[i - c.nk] ^ tmp;
    }
}

void EncryptBlock(const Ctx& c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t st[16];
    std::memcpy(st, in, 16);

    AddRoundKey(st, c.rk);
    for (int r = 1; r < c.rounds; ++r) {
        SubBytes(st);
        ShiftRows(st);
        MixColumns(st);
        AddRoundKey(st, c.rk + r * 4);
    }
    SubBytes(st);
    ShiftRows(st);
    AddRoundKey(st, c.rk + c.rounds * 4);

    std::memcpy(out, st, 16);
}

void DecryptBlock(const Ctx& c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t st[16];
    std::memcpy(st, in, 16);

    AddRoundKey(st, c.rk + c.rounds * 4);
    for (int r = c.rounds - 1; r >= 1; --r) {
        InvShiftRows(st);
        InvSubBytes(st);
        AddRoundKey(st, c.rk + r * 4);
        InvMixColumns(st);
    }
    InvShiftRows(st);
    InvSubBytes(st);
    AddRoundKey(st, c.rk);

    std::memcpy(out, st, 16);
}

}  // namespace aes128

// ---- RFC 3394 -----------------------------------------------------------
bool AesKeyUnwrap(const uint8_t* kek, size_t kek_len,
                  const uint8_t* wrapped, size_t wrapped_len,
                  uint8_t* plain, size_t* plain_len) {
    if (wrapped_len < 16 || wrapped_len % 8 != 0) return false;
    if (kek_len != 16 && kek_len != 24 && kek_len != 32) return false;

    size_t n = wrapped_len / 8;
    aes128::Ctx ctx;
    aes128::Init(ctx, kek, kek_len);

    uint8_t A[8];
    std::memcpy(A, wrapped, 8);
    std::memcpy(plain, wrapped + 8, (n - 1) * 8);

    for (int j = 5; j >= 0; --j) {
        for (size_t i = n; i >= 2; --i) {
            uint64_t t = static_cast<uint64_t>(j) * n + (i - 1);
            uint8_t block[16];
            std::memcpy(block, A, 8);
            for (int k = 0; k < 8; ++k)
                block[k] ^= static_cast<uint8_t>((t >> (8 * (7 - k))) & 0xff);
            std::memcpy(block + 8, plain + (i - 2) * 8, 8);
            uint8_t dec[16];
            aes128::DecryptBlock(ctx, block, dec);
            std::memcpy(A, dec, 8);
            std::memcpy(plain + (i - 2) * 8, dec + 8, 8);
        }
    }

    static const uint8_t iv[8] = {0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6};
    bool ok = std::memcmp(A, iv, 8) == 0;
    if (plain_len) *plain_len = ok ? (n - 1) * 8 : 0;
    return ok;
}

bool AesKeyWrap(const uint8_t* kek, size_t kek_len,
                const uint8_t* plain, size_t plain_len,
                uint8_t* wrapped, size_t* wrapped_len) {
    if (plain_len < 8 || plain_len % 8 != 0) return false;
    if (kek_len != 16 && kek_len != 24 && kek_len != 32) return false;

    size_t n = plain_len / 8 + 1;
    aes128::Ctx ctx;
    aes128::Init(ctx, kek, kek_len);

    uint8_t A[8] = {0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6};
    std::memcpy(wrapped + 8, plain, plain_len);

    for (uint64_t j = 0; j < 6; ++j) {
        for (size_t i = 1; i < n; ++i) {
            uint8_t block[16];
            std::memcpy(block, A, 8);
            std::memcpy(block + 8, wrapped + i * 8, 8);
            aes128::EncryptBlock(ctx, block, block);
            std::memcpy(A, block, 8);
            uint64_t t = static_cast<uint64_t>(j) * n + i;
            for (int k = 0; k < 8; ++k)
                A[k] ^= static_cast<uint8_t>((t >> (8 * (7 - k))) & 0xff);
            std::memcpy(wrapped + i * 8, block + 8, 8);
        }
    }
    std::memcpy(wrapped, A, 8);
    if (wrapped_len) *wrapped_len = n * 8;
    return true;
}
