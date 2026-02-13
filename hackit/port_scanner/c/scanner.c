#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <string.h>
#define OS_DETECT_LIBRARY
#include "os_detect.c" // Include the separate OS engine

#pragma comment(lib, "ws2_32.lib")

#define MAX_THREADS 1000
#define DEFAULT_TIMEOUT 1000
#define BANNER_SIZE 512

typedef struct {
    char host[256];
    int port;
    int timeout;
    int timing_level; // 0-5 (like Nmap T0-T5)
} scan_task_t;

// The OS detection logic is now moved to os_detect.c

// Gacor Banner Grabbing in C
void grab_banner(SOCKET s, int port, char* buffer) {
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    int bytes = recv(s, buffer, BANNER_SIZE - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        for(int i=0; i<bytes; i++) {
            if(buffer[i] == '\n' || buffer[i] == '\r') buffer[i] = ' ';
        }
    } else {
        strcpy(buffer, "");
    }
}

void scan_port(void* arg) {
    scan_task_t* task = (scan_task_t*)arg;
    SOCKET s;
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[10];
    sprintf(port_str, "%d", task->port);

    if (getaddrinfo(task->host, port_str, &hints, &res) != 0) {
        free(task);
        return;
    }

    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        free(task);
        return;
    }

    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    connect(s, res->ai_addr, (int)res->ai_addrlen);

    fd_set setW, setE;
    struct timeval tv;
    FD_ZERO(&setW);
    FD_ZERO(&setE);
    FD_SET(s, &setW);
    FD_SET(s, &setE);
    tv.tv_sec = task->timeout / 1000;
    tv.tv_usec = (task->timeout % 1000) * 1000;

    if (select(0, NULL, &setW, &setE, &tv) > 0) {
        if (FD_ISSET(s, &setW)) {
            // Port is Open! Let's do OS & Banner Fingerprinting
            int ttl = 0;
            int ttl_size = sizeof(ttl);
            getsockopt(s, IPPROTO_IP, IP_TTL, (char*)&ttl, &ttl_size);
            
            // Get Window Size for OS detection
            int window_size = 0;
            int win_size_len = sizeof(window_size);
            getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&window_size, &win_size_len);

            char banner[BANNER_SIZE] = {0};
            mode = 0;
            ioctlsocket(s, FIONBIO, &mode);
            grab_banner(s, task->port, banner);
            
            const char* os_info = c_expert_detect_os(ttl, window_size);
            
            printf("{\"port\": %d, \"status\": \"open\", \"banner\": \"%s\", \"ttl\": %d, \"os\": \"%s\"}\n", 
                   task->port, banner, ttl, os_info);
            fflush(stdout);
        }
    }

    closesocket(s);
    freeaddrinfo(res);
    free(task);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <host> [ports] [timeout] [timing_level]\n", argv[0]);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    char* host = argv[1];
    char* port_arg = (argc > 2) ? argv[2] : "1-1024";
    int timeout = (argc > 3) ? atoi(argv[3]) : DEFAULT_TIMEOUT;
    int timing = (argc > 4) ? atoi(argv[4]) : 3;

    // Timing Templates (T0-T5)
    int delay_ms = 0;
    switch(timing) {
        case 0: delay_ms = 3000; break; // Paranoid
        case 1: delay_ms = 1000; break; // Sneaky
        case 2: delay_ms = 100;  break; // Polite
        case 3: delay_ms = 10;   break; // Normal
        case 4: delay_ms = 1;    break; // Aggressive
        case 5: delay_ms = 0;    break; // Insane
    }

    printf("[*] Nmap-Expert C Engine: Scanning %s (Timing T%d)...\n", host, timing);
    fflush(stdout);

    if (strchr(port_arg, '-')) {
        int start, end;
        sscanf(port_arg, "%d-%d", &start, &end);
        for (int p = start; p <= end; p++) {
            scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
            strcpy(task->host, host);
            task->port = p;
            task->timeout = timeout;
            _beginthread(scan_port, 0, task);
            if (delay_ms > 0) Sleep(delay_ms);
            else if (p % 100 == 0) Sleep(10);
        }
    } else if (strchr(port_arg, ',')) {
        char* token = strtok(port_arg, ",");
        while (token != NULL) {
            scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
            strcpy(task->host, host);
            task->port = atoi(token);
            task->timeout = timeout;
            _beginthread(scan_port, 0, task);
            token = strtok(NULL, ",");
            if (delay_ms > 0) Sleep(delay_ms);
        }
    } else {
        scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
        strcpy(task->host, host);
        task->port = atoi(port_arg);
        task->timeout = timeout;
        _beginthread(scan_port, 0, task);
    }

    Sleep(timeout + 5000);
    WSACleanup();
    return 0;
}
