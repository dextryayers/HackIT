// Host CLI: same probes, no JVM. Used to verify the engine on a workstation
// and to grab a quick device snapshot over adb.
#include "hackit.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace hackit;

static void selftest() {
    uint8_t key[32], nonce[12], aad[3] = {'h', 'd', 'r'};
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; ++i) nonce[i] = (uint8_t)(0xa0 + i);
    const char *plain = "selftest payload";
    uint8_t sealed[128];
    size_t n = aead_seal(sealed, sizeof sealed, key, nonce, aad, sizeof aad,
                         (const uint8_t *)plain, std::strlen(plain));
    uint8_t opened[128];
    long m = aead_open(opened, sizeof opened, key, nonce, aad, sizeof aad, sealed, n);
    std::printf("selftest: seal=%zu open=%ld %s\\n", n, m,
                (m > 0 && std::memcmp(opened, plain, std::strlen(plain)) == 0) ? "OK" : "FAIL");
    sealed[0] ^= 1;
    long bad = aead_open(opened, sizeof opened, key, nonce, aad, sizeof aad, sealed, n);
    std::printf("selftest: tamper rejected=%s\\n", bad < 0 ? "OK" : "FAIL");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::printf("usage: stalker selftest|snapshot|maps|status|net|mounts|cpu|proc|watch <dir>|drain|state <host> <port> <sid> <psk_hex>|send <json>\\n");
        return 2;
    }
    std::string cmd = argv[1];
    if (cmd == "selftest") {
        selftest();
        return 0;
    }
    if (cmd == "snapshot") return std::puts(probe_snapshot().c_str()) < 0 ? 1 : 0;
    if (cmd == "maps") return std::puts(probe_maps().c_str()) < 0 ? 1 : 0;
    if (cmd == "status") return std::puts(probe_status().c_str()) < 0 ? 1 : 0;
    if (cmd == "net") return std::puts(probe_net().c_str()) < 0 ? 1 : 0;
    if (cmd == "mounts") return std::puts(probe_mounts().c_str()) < 0 ? 1 : 0;
    if (cmd == "cpu") return std::puts(probe_cpu().c_str()) < 0 ? 1 : 0;
    if (cmd == "proc") return std::puts(probe_proc_list().c_str()) < 0 ? 1 : 0;
    if (cmd == "watch" && argc > 2) {
        if (!watch_start(argv[2])) {
            std::puts("{\"error\":\"inotify unavailable\"}");
            return 1;
        }
        std::printf("watching %s\\n", argv[2]);
        for (int i = 0; i < 20; ++i) {
            std::string events = watch_drain();
            if (events != "[]") std::printf("%s\\n", events.c_str());
            sleep(1);
        }
        watch_stop();
        return 0;
    }
    if (cmd == "state" && argc > 5) {
        std::vector<uint8_t> key(32);
        const char *hex = argv[5];
        for (int i = 0; i < 32; ++i) {
            unsigned value = 0;
            std::sscanf(hex + i * 2, "%2x", &value);
            key[i] = (uint8_t)value;
        }
        Session session;
        if (!session_init(session, argv[2], (uint16_t)std::atoi(argv[3]), key, argv[4])) {
            std::puts("{\"error\":\"init failed\"}");
            return 1;
        }
        std::printf("%s\\n", session_state(session).c_str());
        std::printf("%s\\n", session_send_json(session, "{\"op\":\"probe\"}", 2) ? "sent" : "send failed");
        std::printf("%s\\n", session_state(session).c_str());
        session_close(session);
        return 0;
    }
    std::fprintf(stderr, "unknown command %s\\n", cmd.c_str());
    return 2;
}
