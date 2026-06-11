#include "eapol_analyzer.h"
#include <cstring>
#include <vector>
#include <cstdint>

// ============================================================================
// EAPOL / 802.1X frame layout (after the 802.11 LLC/SNAP header):
//
//  Offset  Length  Field
//  ------  ------  -----
//     0       1     Version
//     1       1     Type            (3 = EAPOL-Key)
//     2       2     Body Length     (big-endian)
//     4      36+    Key Descriptor Body:
//       4     2     Key Info
//       6     2     Key Length
//       8     8     Key Replay Counter
//      16    32     Key Nonce
//      48    16     Key MIC
//      64     2     Key Data Length
//      66    var    Key Data
//
// Key Info bit layout (2 bytes, big-endian):
//   bit  7 (MSB of high byte):  ACK
//   bit  6:                     Install
//   bit  5:                     Secure
//   bit  3:                     Request
//   bit  0-1 (low byte):       Key Descriptor Version
//   bit  2 (low byte):         Has MIC (key type: PTK=0, GTK=1)
//
// Handshake steps:
//   Msg 1: ACK=1, MIC=0, Install=0  → ANonce from authenticator
//   Msg 2: ACK=0, MIC=1, Install=0  → SNonce from supplicant
//   Msg 3: ACK=1, MIC=1, Install=1  → ANonce + GTK from authenticator
//   Msg 4: ACK=0, MIC=1, Install=0  → Confirmation from supplicant
// ============================================================================

// Minimal EAPOL-Key body size: Key Info(2) + Key Len(2) + Replay(8) +
// Nonce(32) + MIC(16) + KeyDataLen(2) = 62 bytes.
// Total frame from EAPOL header: 4 + 62 = 66 bytes minimum.
static constexpr int kEapolMinBodyLen  = 62;
static constexpr int kEapolHeaderLen   = 4;
static constexpr int kEapolMinFrameLen = kEapolHeaderLen + kEapolMinBodyLen; // 66

// Key Info bit positions (within the 16-bit Key Info field, big-endian)
static constexpr uint16_t kKeyInfoAck     = 1u << 15;  // bit 7 of high byte
static constexpr uint16_t kKeyInfoInstall = 1u << 14;  // bit 6 of high byte
static constexpr uint16_t kKeyInfoSecure  = 1u << 13;  // bit 5 of high byte
static constexpr uint16_t kKeyInfoMic     = 1u << 8;   // bit 0 of high byte (key type)
static constexpr uint16_t kKeyInfoRequest = 1u << 11;  // bit 3 of high byte

// Offset of Key Nonce inside EAPOL body (after 802.1X header)
static constexpr int kNonceOffset  = 16;  // bytes 16..47 of Key Body
static constexpr int kMicOffset    = 48;  // bytes 48..63 of Key Body
static constexpr int kKeyDataLenOffset = 64;
static constexpr int kKeyDataOffset    = 66;

// Read a big-endian 16-bit value from a buffer at the given offset.
static inline uint16_t read_be16(const uint8_t* buf, int offset) {
    return static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
}

// ---------------------------------------------------------------------------

extern "C" {

bool hackit_eapol_parse_frame(const uint8_t* frame, int frame_len, EapolResult* out) {
    if (!frame || !out) return false;
    std::memset(out, 0, sizeof(EapolResult));

    if (frame_len < kEapolMinFrameLen) return false;

    uint16_t key_info_raw = read_be16(frame, kEapolHeaderLen + 0);
    uint16_t key_data_len = read_be16(frame, kEapolHeaderLen + kKeyDataLenOffset);

    out->key_info    = key_info_raw;
    out->has_mic     = (key_info_raw & kKeyInfoMic) != 0;
    out->has_install = (key_info_raw & kKeyInfoInstall) != 0;
    out->step        = hackit_eapol_detect_step(frame, frame_len);

    // Copy ANonce (bytes 16..47 of EAPOL body)
    std::memcpy(out->anonce, frame + kEapolHeaderLen + kNonceOffset,
                HACKIT_EAPOL_ANONCE_LEN);

    // Copy SNonce — only meaningful for msg 2, but we always extract it.
    // For msg 1/3 the Nonce field holds ANonce, so we replicate it here
    // for completeness. Callers should use detect_step to decide.
    std::memcpy(out->snonce, frame + kEapolHeaderLen + kNonceOffset,
                HACKIT_EAPOL_SNONCE_LEN);

    // Copy MIC (bytes 48..63 of EAPOL body)
    std::memcpy(out->mic, frame + kEapolHeaderLen + kMicOffset,
                HACKIT_EAPOL_MIC_LEN);

    out->key_data_len = static_cast<int>(key_data_len);

    return true;
}

// ---------------------------------------------------------------------------

int hackit_eapol_detect_step(const uint8_t* frame, int frame_len) {
    if (!frame || frame_len < kEapolMinFrameLen) return 0;

    uint16_t key_info = read_be16(frame, kEapolHeaderLen + 0);
    bool ack     = (key_info & kKeyInfoAck) != 0;
    bool mic     = (key_info & kKeyInfoMic) != 0;
    bool install = (key_info & kKeyInfoInstall) != 0;

    if (ack && !mic && !install) return 1;  // Message 1
    if (!ack && mic && !install) return 2;  // Message 2
    if (ack && mic && install)  return 3;  // Message 3
    if (!ack && mic && !install) {
        // Could be message 4. Distinguish from message 2 by key replay
        // counter or other context. Without state, we fall back to 2.
        // However, if the Secure bit is set it is almost certainly msg 4.
        bool secure = (key_info & kKeyInfoSecure) != 0;
        if (secure) return 4;
        return 2; // ambiguous — default to 2
    }
    return 0; // unknown
}

// ---------------------------------------------------------------------------

bool hackit_eapol_extract_anonce(const uint8_t* frame, int frame_len,
                                 uint8_t* out_anonce, int* out_len) {
    if (!frame || !out_anonce || !out_len) return false;
    if (frame_len < kEapolMinFrameLen) return false;

    std::memcpy(out_anonce, frame + kEapolHeaderLen + kNonceOffset,
                HACKIT_EAPOL_ANONCE_LEN);
    *out_len = HACKIT_EAPOL_ANONCE_LEN;
    return true;
}

// ---------------------------------------------------------------------------

bool hackit_eapol_extract_snonce(const uint8_t* frame, int frame_len,
                                 uint8_t* out_snonce, int* out_len) {
    if (!frame || !out_snonce || !out_len) return false;
    if (frame_len < kEapolMinFrameLen) return false;

    // In message 2 the Nonce field contains the SNonce.
    // For other messages it still contains *a* nonce, but the caller
    // should use detect_step to interpret it correctly.
    std::memcpy(out_snonce, frame + kEapolHeaderLen + kNonceOffset,
                HACKIT_EAPOL_SNONCE_LEN);
    *out_len = HACKIT_EAPOL_SNONCE_LEN;
    return true;
}

// ---------------------------------------------------------------------------

bool hackit_eapol_extract_mic(const uint8_t* frame, int frame_len,
                              uint8_t* out_mic, int* out_len) {
    if (!frame || !out_mic || !out_len) return false;
    if (frame_len < kEapolMinFrameLen) return false;

    std::memcpy(out_mic, frame + kEapolHeaderLen + kMicOffset,
                HACKIT_EAPOL_MIC_LEN);
    *out_len = HACKIT_EAPOL_MIC_LEN;
    return true;
}

// ---------------------------------------------------------------------------

bool hackit_eapol_validate_integrity(const uint8_t* frame, int frame_len) {
    if (!frame || frame_len < kEapolMinFrameLen) return false;

    // Check EAPOL version (must be 1, 2, or 3)
    uint8_t version = frame[0];
    if (version < 1 || version > 3) return false;

    // Check type is EAPOL-Key (3)
    uint8_t type = frame[1];
    if (type != 3) return false;

    // Check body length fits within available data
    uint16_t body_len = read_be16(frame, 2);
    if (kEapolHeaderLen + static_cast<int>(body_len) > frame_len) return false;

    // Validate Key Descriptor Version (bits 0-2 of Key Info)
    uint16_t key_info = read_be16(frame, kEapolHeaderLen + 0);
    uint8_t  kdv      = key_info & 0x07;
    // Valid versions: 1 (HMAC-MD5/RC4), 2 (HMAC-SHA1-128/AES), 3-4 (AES-128-CMAC)
    if (kdv == 0 || kdv > 4) return false;

    // Check that key_data_len field does not exceed remaining bytes
    uint16_t key_data_len = read_be16(frame, kEapolHeaderLen + kKeyDataLenOffset);
    int available_for_key_data = frame_len - kEapolHeaderLen - kKeyDataOffset;
    if (available_for_key_data < 0) return false;
    if (static_cast<int>(key_data_len) > available_for_key_data) return false;

    // At least one of ACK or MIC should normally be set for a valid handshake frame
    bool ack = (key_info & kKeyInfoAck) != 0;
    bool mic = (key_info & kKeyInfoMic) != 0;
    if (!ack && !mic) return false;

    return true;
}

} // extern "C"
