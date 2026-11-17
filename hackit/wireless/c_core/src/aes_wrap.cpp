// AES-128/192/256 + RFC 3394 key wrap/unwrap. See aes_wrap.h.
// S-box + T-tables are computed rather than baked so the table is correct by
// construction and the file stays small.

#include "aes_wrap.h"

namespace {

uint8_t g_sbox[256];
uint8_t g_inv_sbox[256];
uint32_t g_te0[256], g_te1[256], g_te2[256], g_te3[256];
uint32_t g_td0[256], g_td1[256], g_td2[256], g_td3[256];
bool g_tables_ready = false;

inline uint8_t xtime(uint8_t x) {
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

inline uint8_t gf_mul(uint8_t a, uint8_t b) {
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

void InitTables() {
    if (g_tables_ready) return;

    // S-box via multiplicative inverse + affine transform.
    uint8_t p = 1, q = 1;
    do {
        p = static_cast<uint8_t>(p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0x00));
        q = static_cast<uint8_t>((q ^ (q << 1)) ^ ((q & 0x80) ? 0x09 : 0x00));
        q = static_cast<uint8_t>((q ^ (q << 2)) ^ ((q & 0x80) ? 0x09 : 0x00));
        q = static_cast<uint8_t>((q ^ (q << 4)) ^ ((q & 0x80) ? 0x09 : 0x00));
        uint8_t x = static_cast<uint8_t>(q ^ (q << 1) ^ (q << 2) ^ (q << 3) ^ (q << 4));
        x = static_cast<uint8_t>(x ^ 0x63);
        // p is the multiplicative inverse in GF(2^8) here; storing under p
        g_sbox[p] = x;
        g_inv_sbox[x] = p;
    } while (p != 1);

    // Round-table entries derived from the box.
    for (int i = 0; i < 256; ++i) {
        uint8_t s = g_sbox[i];
        uint8_t s2 = gf_mul(s, 2);
        uint8_t s3 = gf_mul(s, 3);
        uint32_t w = (static_cast<uint32_t>(s2) << 24) |
                     (static_cast<uint32_t>(s) << 16) |
                     (static_cast<uint32_t>(s) << 8) |
                     static_cast<uint32_t>(s3);
        g_te0[i] = w;
        g_te1[i] = (w >> 8) | (w << 24);
        g_te2[i] = (w >> 16) | (w << 16);
        g_te3[i] = (w >> 24) | (w << 8);

        uint8_t is = g_inv_sbox[i];
        uint8_t i2 = gf_mul(is, 0x0e);
        uint8_t i3 = gf_mul(is, 0x0b);
        uint8_t i1 = gf_mul(is, 0x0d);
        uint8_t i9 = gf_mul(is, 0x09);
        uint32_t dw = (static_cast<uint32_t>(i2) << 24) |
                      (static_cast<uint32_t>(i9) << 16) |
                      (static_cast<uint32_t>(i3) << 8) |
                      static_cast<uint32_t>(i1);
        g_td0[i] = dw;
        g_td1[i] = (dw >> 8) | (dw << 24);
        g_td2[i] = (dw >> 16) | (dw << 16);
        g_td3[i] = (dw >> 24) | (dw << 8);
    }

    g_tables_ready = true;
}

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

inline uint32_t load_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline uint32_t sub_word(uint32_t w) {
    return (static_cast<uint32_t>(g_sbox[(w >> 24) & 0xff]) << 24) |
           (static_cast<uint32_t>(g_sbox[(w >> 16) & 0xff]) << 16) |
           (static_cast<uint32_t>(g_sbox[(w >> 8) & 0xff]) << 8) |
           static_cast<uint32_t>(g_sbox[w & 0xff]);
}

}  // namespace

namespace aes128 {

void Init(Ctx& c, const uint8_t* key, size_t keylen) {
    InitTables();
    int nk = static_cast<int>(keylen / 4);
    c.nk = nk;
    c.rounds = nk + 6;

    for (int i = 0; i < nk; ++i) {
        c.rk[i] = load_le32(key + 4 * i);
    }

    uint32_t rcon = 1;
    for (int i = nk; i < 4 * (c.rounds + 1); ++i) {
        uint32_t tmp = c.rk[i - 1];
        if (i % nk == 0) {
            tmp = sub_word(rotr(tmp, 8)) ^ (rcon << 24);
            rcon = gf_mul(static_cast<uint8_t>(rcon), 0x02);
        } else if (nk > 6 && i % nk == 4) {
            tmp = sub_word(tmp);
        }
        c.rk[i] = c.rk[i - nk] ^ tmp;
    }
}

void EncryptBlock(const Ctx& c, const uint8_t in[16], uint8_t out[16]) {
    uint32_t s0 = load_le32(in + 0) ^ c.rk[0];
    uint32_t s1 = load_le32(in + 4) ^ c.rk[1];
    uint32_t s2 = load_le32(in + 8) ^ c.rk[2];
    uint32_t s3 = load_le32(in + 12) ^ c.rk[3];

    int nr = c.rounds;
    for (int r = 1; r < nr; ++r) {
        const uint32_t* rk = &c.rk[r * 4];
        uint32_t t0 = g_te0[s0 & 0xff] ^ g_te1[(s1 >> 8) & 0xff] ^
                      g_te2[(s2 >> 16) & 0xff] ^ g_te3[(s3 >> 24) & 0xff] ^ rk[0];
        uint32_t t1 = g_te0[s1 & 0xff] ^ g_te1[(s2 >> 8) & 0xff] ^
                      g_te2[(s3 >> 16) & 0xff] ^ g_te3[(s0 >> 24) & 0xff] ^ rk[1];
        uint32_t t2 = g_te0[s2 & 0xff] ^ g_te1[(s3 >> 8) & 0xff] ^
                      g_te2[(s0 >> 16) & 0xff] ^ g_te3[(s1 >> 24) & 0xff] ^ rk[2];
        uint32_t t3 = g_te0[s3 & 0xff] ^ g_te1[(s0 >> 8) & 0xff] ^
                      g_te2[(s1 >> 16) & 0xff] ^ g_te3[(s2 >> 24) & 0xff] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    const uint32_t* rk = &c.rk[nr * 4];
    uint32_t o0 = ((static_cast<uint32_t>(g_sbox[(s0 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_sbox[(s1 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_sbox[(s2 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_sbox[(s3 >> 24) & 0xff]) << 24)) ^ rk[0];
    uint32_t o1 = ((static_cast<uint32_t>(g_sbox[(s1 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_sbox[(s2 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_sbox[(s3 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_sbox[(s0 >> 24) & 0xff]) << 24)) ^ rk[1];
    uint32_t o2 = ((static_cast<uint32_t>(g_sbox[(s2 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_sbox[(s3 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_sbox[(s0 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_sbox[(s1 >> 24) & 0xff]) << 24)) ^ rk[2];
    uint32_t o3 = ((static_cast<uint32_t>(g_sbox[(s3 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_sbox[(s0 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_sbox[(s1 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_sbox[(s2 >> 24) & 0xff]) << 24)) ^ rk[3];

    store_le32(out + 0, o0);
    store_le32(out + 4, o1);
    store_le32(out + 8, o2);
    store_le32(out + 12, o3);
}

void DecryptBlock(const Ctx& c, const uint8_t in[16], uint8_t out[16]) {
    uint32_t s0 = load_le32(in + 0) ^ c.rk[c.rounds * 4 + 0];
    uint32_t s1 = load_le32(in + 4) ^ c.rk[c.rounds * 4 + 1];
    uint32_t s2 = load_le32(in + 8) ^ c.rk[c.rounds * 4 + 2];
    uint32_t s3 = load_le32(in + 12) ^ c.rk[c.rounds * 4 + 3];

    int nr = c.rounds;
    for (int r = nr - 1; r > 0; --r) {
        const uint32_t* rk = &c.rk[r * 4];
        uint32_t t0 = g_td0[s0 & 0xff] ^ g_td1[(s3 >> 8) & 0xff] ^
                      g_td2[(s2 >> 16) & 0xff] ^ g_td3[(s1 >> 24) & 0xff] ^ rk[0];
        uint32_t t1 = g_td0[s1 & 0xff] ^ g_td1[(s0 >> 8) & 0xff] ^
                      g_td2[(s3 >> 16) & 0xff] ^ g_td3[(s2 >> 24) & 0xff] ^ rk[1];
        uint32_t t2 = g_td0[s2 & 0xff] ^ g_td1[(s1 >> 8) & 0xff] ^
                      g_td2[(s0 >> 16) & 0xff] ^ g_td3[(s3 >> 24) & 0xff] ^ rk[2];
        uint32_t t3 = g_td0[s3 & 0xff] ^ g_td1[(s2 >> 8) & 0xff] ^
                      g_td2[(s1 >> 16) & 0xff] ^ g_td3[(s0 >> 24) & 0xff] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    const uint32_t* rk = &c.rk[0];
    uint32_t o0 = ((static_cast<uint32_t>(g_inv_sbox[(s0 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_inv_sbox[(s3 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_inv_sbox[(s2 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_inv_sbox[(s1 >> 24) & 0xff]) << 24)) ^ rk[0];
    uint32_t o1 = ((static_cast<uint32_t>(g_inv_sbox[(s1 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_inv_sbox[(s0 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_inv_sbox[(s3 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_inv_sbox[(s2 >> 24) & 0xff]) << 24)) ^ rk[1];
    uint32_t o2 = ((static_cast<uint32_t>(g_inv_sbox[(s2 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_inv_sbox[(s1 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_inv_sbox[(s0 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_inv_sbox[(s3 >> 24) & 0xff]) << 24)) ^ rk[2];
    uint32_t o3 = ((static_cast<uint32_t>(g_inv_sbox[(s3 >> 0) & 0xff]) << 0) |
                   (static_cast<uint32_t>(g_inv_sbox[(s2 >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(g_inv_sbox[(s1 >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(g_inv_sbox[(s0 >> 24) & 0xff]) << 24)) ^ rk[3];

    store_le32(out + 0, o0);
    store_le32(out + 4, o1);
    store_le32(out + 8, o2);
    store_le32(out + 12, o3);
}

}  // namespace aes128

// ---- RFC 3394 -----------------------------------------------------------
bool AesKeyUnwrap(const uint8_t* kek, size_t kek_len,
                  const uint8_t* wrapped, size_t wrapped_len,
                  uint8_t* plain, size_t* plain_len) {
    // AES block size 16; wrapped must be n*8 with n>=2, KEK length a valid AES size.
    if (wrapped_len < 16 || wrapped_len % 8 != 0) return false;
    if (kek_len != 16 && kek_len != 24 && kek_len != 32) return false;

    size_t n = wrapped_len / 8;
    aes128::Ctx ctx;
    aes128::Init(ctx, kek, kek_len);

    uint8_t A[8];
    std::memcpy(A, wrapped, 8);
    std::memcpy(plain, wrapped + 8, (n - 1) * 8);

    for (int j = 5; j >= 0; --j) {
        for (size_t i = n - 1; i >= 1; --i) {
            uint64_t t = j * static_cast<uint64_t>(n) + i;
            // A = MSB64( AES-D(A XOR t) )
            uint8_t block[16];
            std::memcpy(block, A, 8);
            for (int k = 0; k < 8; ++k) {
                block[k] ^= static_cast<uint8_t>((t >> (8 * (7 - k))) & 0xff);
            }
            std::memcpy(block + 8, plain + (i - 1) * 8, 8);
            uint8_t dec[16];
            aes128::DecryptBlock(ctx, block, dec);
            std::memcpy(A, dec, 8);
            std::memcpy(plain + (i - 1) * 8, dec + 8, 8);
            if (i == 1) break;
        }
    }

    static const uint8_t iv[8] = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
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

    uint8_t A[8] = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
    std::memcpy(wrapped + 8, plain, plain_len);

    for (uint64_t j = 0; j < 6; ++j) {
        for (size_t i = 1; i < n; ++i) {
            uint8_t block[16];
            std::memcpy(block, A, 8);
            std::memcpy(block + 8, wrapped + i * 8, 8);
            aes128::EncryptBlock(ctx, block, block);
            std::memcpy(A, block, 8);
            uint64_t t = j * static_cast<uint64_t>(n) + i;
            for (int k = 0; k < 8; ++k) {
                A[k] ^= static_cast<uint8_t>((t >> (8 * (7 - k))) & 0xff);
            }
            std::memcpy(wrapped + i * 8, block + 8, 8);
        }
    }
    std::memcpy(wrapped, A, 8);
    if (wrapped_len) *wrapped_len = n * 8;
    return true;
}
