#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "socket_helper.h"

int main(int argc, char* argv[]) {
    if (argc < 3) return 1;
    
    int verbose = 0;
    int mask = 0;
    for(int i=1; i<argc; i++) {
        if(strcmp(argv[i], "-v") == 0) verbose = 1;
        if(strcmp(argv[i], "--mask") == 0) mask = 1;
    }

    if(verbose) printf("[*] C Socket Orchestrator v2.2: Stealth Probe Initialized.\n");
    if(mask) Sleep(1000); // Simple stealth delay

    init_ws();
    
    SOCKET s = create_connection(argv[1], atoi(argv[2]));
    if (s != INVALID_SOCKET) {
        if(verbose) printf("[*] Modular C Engine: Connection established to %s:%s\n", argv[1], argv[2]);
        const char* msg = "GET / HTTP/1.1\r\nHost: target\r\n\r\n";
        send(s, msg, (int)strlen(msg), 0);
        if(verbose) printf("[+] Payload delivered via raw socket.\n");
        closesocket(s);
    }
    
    cleanup_ws();
    return 0;
}
