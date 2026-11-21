// Datagram transport: sealed frames, one worker thread, bounded queue.
#include "hackit.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

namespace hackit {
namespace {

constexpr uint8_t kMagic[4] = {'H', 'K', '1', 0};
constexpr size_t kHeader = 4 + 1 + 2 + 2 + kNonceLen;  // 21
constexpr uint8_t kTypeEvent = 1;
constexpr uint8_t kTypeProbe = 2;

std::mutex g_queue_mutex;
std::vector<std::string> g_queue;
std::atomic<bool> g_running{false};
std::thread g_worker;
Session *g_session = nullptr;
std::atomic<uint64_t> g_dropped{0};

uint64_t now_ms() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

void worker(Session &session) {
    uint64_t last_probe = 0;
    while (g_running.load()) {
        std::string payload;
        {
            std::lock_guard<std::mutex> lock(g_queue_mutex);
            if (!g_queue.empty()) {
                payload = std::move(g_queue.front());
                g_queue.erase(g_queue.begin());
            }
        }
        if (payload.empty()) {
            uint64_t beat = now_ms();
            if (beat - last_probe > 300000) {
                last_probe = beat;
                payload = probe_snapshot();
            }
        }
        if (!payload.empty()) {
            if (!session_send_json(session, payload, kTypeProbe)) {
                session.failed++;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

}  // namespace

bool session_init(Session &s, const std::string &host, uint16_t port, const std::vector<uint8_t> &psk,
                  const std::string &sid) {
    std::memset(&s, 0, sizeof(s));
    s.host = host;
    s.port = port;
    s.sid = sid;
    s.fd = -1;
    s.backoff_ms = 1000;
    if (psk.size() != kKeyLen) return false;
    std::memcpy(s.key, psk.data(), kKeyLen);

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = nullptr;
    char service[8];
    std::snprintf(service, sizeof(service), "%u", (unsigned)port);
    if (getaddrinfo(host.c_str(), service, &hints, &res) != 0 || res == nullptr) {
        return false;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return false;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);
    s.fd = fd;
    return true;
}

void session_close(Session &s) {
    if (s.fd >= 0) {
        close(s.fd);
        s.fd = -1;
    }
}

bool session_send_json(Session &s, const std::string &json, uint8_t type) {
    if (s.fd < 0 || json.empty() || json.size() > kMaxFrame - kTagLen - 8) {
        s.dropped++;
        return false;
    }
    uint8_t frame[kMaxFrame + kTagLen + 8];
    std::memcpy(frame, kMagic, 4);
    frame[4] = type;
    put16(frame + 5, s.seq++);
    put16(frame + 7, (uint16_t)json.size());
    std::memcpy(frame + 9, s.key, 0);  // nonce filled below
    uint8_t nonce[kNonceLen];
    uint32_t counter = (uint32_t)(s.seq ^ now_ms());
    nonce[0] = (uint8_t)(counter >> 24);
    nonce[1] = (uint8_t)(counter >> 16);
    nonce[2] = (uint8_t)(counter >> 8);
    nonce[3] = (uint8_t)counter;
    for (int i = 4; i < kNonceLen; ++i) nonce[i] = (uint8_t)(now_ms() >> (8 * (i - 4)));
    std::memcpy(frame + 9, nonce, kNonceLen);

    size_t sealed = aead_seal(frame + 9 + kNonceLen, kMaxFrame + kTagLen, s.key, nonce, frame,
                              kHeader, (const uint8_t *)json.data(), json.size());
    if (sealed == 0) {
        s.dropped++;
        return false;
    }
    size_t total = kHeader + sealed;
    ssize_t sent = send(s.fd, frame, total, 0);
    if (sent < 0) {
        s.failed++;
        return false;
    }
    s.sent++;
    s.last_ok_ms = now_ms();
    s.backoff_ms = 1000;
    return true;
}

std::string session_state(const Session &s) {
    char buffer[512];
    std::snprintf(buffer, sizeof(buffer),
                  "{\"sent\":%llu,\"dropped\":%llu,\"failed\":%llu,\"seq\":%u,\"fd\":%d,"
                  "\"queued\":%zu,\"host\":\"%s\",\"port\":%u}",
                  (unsigned long long)s.sent, (unsigned long long)(s.dropped + g_dropped.load()),
                  (unsigned long long)s.failed, (unsigned)s.seq, s.fd, g_queue.size(), s.host.c_str(),
                  (unsigned)s.port);
    return std::string(buffer);
}

void native_start(Session &session) {
    if (g_running.exchange(true)) return;
    g_session = &session;
    g_worker = std::thread(worker, std::ref(session));
}

void native_stop() {
    if (!g_running.exchange(false)) return;
    if (g_worker.joinable()) g_worker.join();
    g_session = nullptr;
}

int native_enqueue(const std::string &json, uint8_t type) {
    (void)type;
    {
        std::lock_guard<std::mutex> lock(g_queue_mutex);
        if (g_queue.size() >= kQueueCap) {
            g_queue.erase(g_queue.begin());
            g_dropped++;
        }
        g_queue.push_back(json);
    }
    return (int)g_queue.size();
}

}  // namespace hackit