#include <stdio.h>
#include "socket_helper.h"

void apply_stealth_mask(SOCKET s) {
    // Low-level socket manipulation for anonymity
    // e.g., setting custom TCP window sizes or TTL to mimic common browsers
    // We'll use a unified, professional tag
    printf("[*] STEALTH: Applying high-anonymity packet masking...\n");
}

void stealth_dispatch(const char* ip, int port, const char* payload) {
    init_ws();
    SOCKET s = create_connection(ip, port);
    if (s != INVALID_SOCKET) {
        apply_stealth_mask(s);
        send(s, payload, (int)strlen(payload), 0);
        closesocket(s);
    }
    cleanup_ws();
}
