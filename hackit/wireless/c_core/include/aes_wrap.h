#pragma once
// Minimal, dependency-free AES-128/192/256 (ECB block op only) used by the
// WPS Pixie Dust path. We only need raw block encrypt/decrypt — pull in a
// full TLS stack for the DH exchange would be overkill and break the
// "no external crypto library" property the rest of c_core has.
//
// T-table implementation (Bernstein/Gladman lineage). Constant-time only in the
// sense that it's a fixed schedule — WPS is a weak protocol, not a side-channel
// concern for our threat model. NOT suitable for TLS traffic.

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace aes128 {

struct Ctx {
    uint32_t rk[60];   // up to 15 round keys (AES-256 needs 60 words)
    int rounds;        // 10, 12, 14
    int nk;            // 4, 6, 8 (key words)
};

void Init(Ctx& c, const uint8_t* key, size_t keylen);
void EncryptBlock(const Ctx& c, const uint8_t in[16], uint8_t out[16]);
void DecryptBlock(const Ctx& c, const uint8_t in[16], uint8_t out[16]);

// Convenience: single-block encrypt/decrypt that re-inits the context. Used in
// RFC 3394 unwrap where we call with the same key repeatedly — callers should
// use Init once + EncryptBlock instead for throughput.
inline void EncryptEcb(const uint8_t* key, size_t keylen,
                       const uint8_t in[16], uint8_t out[16]) {
    Ctx c;
    Init(c, key, keylen);
    EncryptBlock(c, in, out);
}

}  // namespace aes128

// ---------- RFC 3394 AES Key Wrap (KF = AES-ECB) -------------------------
// Returns true on success. `plain` is sized to wrapped.size()-8 on success.
bool AesKeyUnwrap(const uint8_t* kek, size_t kek_len,
                  const uint8_t* wrapped, size_t wrapped_len,
                  uint8_t* plain, size_t* plain_len);

// RFC 3394 key wrap (used by the WPS-NEW-* request builders).
bool AesKeyWrap(const uint8_t* kek, size_t kek_len,
                const uint8_t* plain, size_t plain_len,
                uint8_t* wrapped, size_t* wrapped_len);
