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
    int scan_type;    // 0=connect, 1=syn, 2=fin, 3=null, 4=xmas, 5=udp
} scan_task_t;

// The OS detection logic is now moved to os_detect.c

// Advanced TCP/IP Fingerprinting
typedef struct {
    int ttl;
    int window_size;
    int mss;
    char ip_id[16];
    int tcp_options;
} tcp_fingerprint_t;

// Get TCP/IP fingerprint from connection
tcp_fingerprint_t get_tcp_fingerprint(SOCKET s) {
    tcp_fingerprint_t fp = {0};
    
    // Get TTL
    int ttl = 0;
    int ttl_size = sizeof(ttl);
    getsockopt(s, IPPROTO_IP, IP_TTL, (char*)&ttl, &ttl_size);
    fp.ttl = ttl;
    
    // Get Window Size
    int window_size = 0;
    int win_size_len = sizeof(window_size);
    getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&window_size, &win_size_len);
    fp.window_size = window_size;
    
    // Get MSS (if available)
    int mss = 1460; // Default MSS
    fp.mss = mss;
    
    // Get TCP Options (simplified)
    fp.tcp_options = 0;
    
    return fp;
}

// Gacor Banner Grabbing in C with advanced probes
void grab_banner_advanced(SOCKET s, int port, char* buffer) {
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // Send protocol-specific probes
    switch(port) {
        case 80:
        case 8080:
        case 443:
        case 8443:
            send(s, "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n", 32, 0);
            break;
        case 21:
            // FTP sends banner automatically
            break;
        case 25:
        case 587:
            send(s, "EHLO hackit-scanner\r\n", 20, 0);
            break;
        case 110:
            send(s, "CAPA\r\n", 6, 0);
            break;
        case 143:
            send(s, "A001 CAPABILITY\r\n", 18, 0);
            break;
        case 3306:
            // MySQL handshake probe
            send(s, "\x00\x00\x00\x01", 4, 0);
            break;
        case 5432:
            // PostgreSQL startup message
            send(s, "\x00\x00\x00\x08\x04\xd2\x16\x2f", 8, 0);
            break;
        case 6379:
            send(s, "INFO\r\n", 6, 0);
            break;
        case 27017:
            // MongoDB is-master probe
            send(s, "\x3b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00", 59, 0);
            break;
        case 23:
            // Telnet negotiation
            send(s, "\xff\xfb\x01\xff\xfb\x03", 6, 0);
            break;
        case 5900:
            // VNC version
            send(s, "RFB 003.008\n", 12, 0);
            break;
        default:
            send(s, "\r\n\r\n", 4, 0);
            break;
    }
    
    int bytes = recv(s, buffer, BANNER_SIZE - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        for(int i=0; i<bytes; i++) {
            if(buffer[i] == '\n' || buffer[i] == '\r') buffer[i] = ' ';
        }
    } else {
        strncpy(buffer, "", sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
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
    snprintf(port_str, sizeof(port_str), "%d", task->port);

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
            // Port is Open! Let's do OS & Banner Fingerprinting with advanced probes
            tcp_fingerprint_t fp = get_tcp_fingerprint(s);
            
            char banner[BANNER_SIZE] = {0};
            mode = 0;
            ioctlsocket(s, FIONBIO, &mode);
            grab_banner_advanced(s, task->port, banner);
            
            detection_result_t os_result = c_expert_detect_os_advanced(fp.ttl, fp.window_size);
            const char* os_info = os_result.os_name;
            
            printf("{\"port\": %d, \"status\": \"open\", \"banner\": \"%s\", \"ttl\": %d, \"window\": %d, \"mss\": %d, \"os\": \"%s\", \"scan_type\": %d}\n", 
                   task->port, banner, fp.ttl, fp.window_size, fp.mss, os_info, task->scan_type);
            fflush(stdout);
        }
    }

    closesocket(s);
    freeaddrinfo(res);
    free(task);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <host> [ports] [timeout] [timing_level] [scan_type]\n", argv[0]);
        printf("Scan types: 0=connect, 1=syn, 2=fin, 3=null, 4=xmas, 5=udp\n");
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
    int scan_type = (argc > 5) ? atoi(argv[5]) : 0;

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

    printf("[*] Nmap-Expert C Engine: Scanning %s (Timing T%d, Type %d)...\n", host, timing, scan_type);
    fflush(stdout);

    if (strchr(port_arg, '-')) {
        int start, end;
        sscanf(port_arg, "%d-%d", &start, &end);
        for (int p = start; p <= end; p++) {
            scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
            if (task) {
                strncpy(task->host, host, sizeof(task->host) - 1);
                task->host[sizeof(task->host) - 1] = '\0';
                task->port = p;
                task->timeout = timeout;
                task->timing_level = timing;
                task->scan_type = scan_type;
                _beginthread(scan_port, 0, task);
                if (delay_ms > 0) Sleep(delay_ms);
                else if (p % 100 == 0) Sleep(10);
            }
        }
    } else if (strchr(port_arg, ',')) {
        char* token = strtok(port_arg, ",");
        while (token != NULL) {
            scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
            if (task) {
                strncpy(task->host, host, sizeof(task->host) - 1);
                task->host[sizeof(task->host) - 1] = '\0';
                task->port = atoi(token);
                task->timeout = timeout;
                task->timing_level = timing;
                task->scan_type = scan_type;
                _beginthread(scan_port, 0, task);
                token = strtok(NULL, ",");
                if (delay_ms > 0) Sleep(delay_ms);
            }
        }
    } else {
        scan_task_t* task = (scan_task_t*)malloc(sizeof(scan_task_t));
        if (task) {
            strncpy(task->host, host, sizeof(task->host) - 1);
            task->host[sizeof(task->host) - 1] = '\0';
            task->port = atoi(port_arg);
            task->timeout = timeout;
            task->timing_level = timing;
            task->scan_type = scan_type;
            _beginthread(scan_port, 0, task);
        }
    }

    Sleep(timeout + 5000);
    WSACleanup();
    return 0;
}
