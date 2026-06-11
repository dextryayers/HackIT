#include "syn_scanner.h"
#include "tcp_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#endif

#ifdef HACKIT_HAS_PCAP
#include <pcap.h>
#endif

#ifndef _WIN32

#define IP4_HDRLEN 20
#define TCP_HDRLEN 20

static unsigned short checksum(unsigned short* buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

static int syn_scan_raw(const char* host, int port, int timeout_ms, bool* filtered_out) {
    if (!host || !filtered_out) return -1;
    *filtered_out = false;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((unsigned short)port);

    struct hostent* he = gethostbyname(host);
    if (he) {
        memcpy(&dest.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        dest.sin_addr.s_addr = inet_addr(host);
        if (dest.sin_addr.s_addr == INADDR_NONE) return -1;
    }

    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_fd < 0) return -1;

    int optval = 1;
    setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    char packet[IP4_HDRLEN + TCP_HDRLEN];
    memset(packet, 0, sizeof(packet));

    struct iphdr* ip = (struct iphdr*)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons((unsigned short)(rand() % 65535));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = INADDR_ANY;
    ip->daddr = dest.sin_addr.s_addr;
    ip->check = 0;
    ip->check = checksum((unsigned short*)ip, IP4_HDRLEN);

    struct tcphdr* tcp = (struct tcphdr*)(packet + IP4_HDRLEN);
    tcp->source = htons((unsigned short)(10000 + (rand() % 55535)));
    tcp->dest = htons((unsigned short)port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    struct pseudo_header {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = tcp->source;
    sin.sin_addr.s_addr = ip->saddr;

    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(TCP_HDRLEN);

    char pseudogram[sizeof(psh) + TCP_HDRLEN];
    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcp, TCP_HDRLEN);
    tcp->check = checksum((unsigned short*)pseudogram, sizeof(pseudogram));

    if (sendto(raw_fd, packet, sizeof(packet), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        close(raw_fd);
        return -1;
    }

    fd_set rset;
    struct timeval tv;
    FD_ZERO(&rset);
    FD_SET(raw_fd, &rset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int rc = select(raw_fd + 1, &rset, NULL, NULL, &tv);
    if (rc <= 0) {
        *filtered_out = true;
        close(raw_fd);
        return 0;
    }

    char recv_buf[256];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    int n = recvfrom(raw_fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&sender, &sender_len);
    close(raw_fd);

    if (n < (int)(IP4_HDRLEN + TCP_HDRLEN)) {
        *filtered_out = true;
        return 0;
    }

    if (sender.sin_addr.s_addr != dest.sin_addr.s_addr) {
        *filtered_out = true;
        return 0;
    }

    struct iphdr* rip = (struct iphdr*)recv_buf;
    int ip_hdr_len = (rip->ihl & 0x0F) * 4;
    if (n < ip_hdr_len + TCP_HDRLEN) {
        *filtered_out = true;
        return 0;
    }

    struct tcphdr* rtcp = (struct tcphdr*)(recv_buf + ip_hdr_len);

    if (rtcp->syn && rtcp->ack) {
        return 1;
    }
    if (rtcp->rst) {
        return 0;
    }

    *filtered_out = true;
    return 0;
}

#endif

int hackit_syn_scan_port(const char* host, int port, int timeout_ms, bool* filtered_out) {
    if (!host || !filtered_out) return -1;
    *filtered_out = false;

#ifdef _WIN32
    ScannerPortResult tcp_result;
    int rc = hackit_scan_tcp_port(host, port, timeout_ms, &tcp_result);
    if (rc != 0) return -1;
    if (tcp_result.state == SCAN_STATE_OPEN) return 1;
    if (tcp_result.state == SCAN_STATE_FILTERED) {
        *filtered_out = true;
    }
    return 0;
#else
    return syn_scan_raw(host, port, timeout_ms, filtered_out);
#endif
}

#ifdef _WIN32
typedef struct {
    CRITICAL_SECTION lock;
    const int* ports;
    int port_count;
    int current_index;
} SynWorkQueue;

typedef struct {
    const char* host;
    int timeout_ms;
    SynWorkQueue* queue;
    bool* open_results;
    int max_results;
    int* result_count;
} SynThreadData;

static DWORD WINAPI syn_worker(LPVOID arg) {
    SynThreadData* td = (SynThreadData*)arg;
    while (1) {
        EnterCriticalSection(&td->queue->lock);
        int idx = td->queue->current_index++;
        LeaveCriticalSection(&td->queue->lock);
        if (idx >= td->queue->port_count) break;
        ScannerPortResult r;
        int rc = hackit_scan_tcp_port(td->host, td->queue->ports[idx], td->timeout_ms, &r);
        if (rc == 0 && r.state == SCAN_STATE_OPEN) {
            EnterCriticalSection(&td->queue->lock);
            if (*td->result_count < td->max_results) {
                td->open_results[*td->result_count] = true;
                (*td->result_count)++;
            }
            LeaveCriticalSection(&td->queue->lock);
        }
    }
    return 0;
}
#else
typedef struct {
    pthread_mutex_t lock;
    const int* ports;
    int port_count;
    int current_index;
} SynWorkQueue;

typedef struct {
    const char* host;
    int timeout_ms;
    SynWorkQueue* queue;
    bool* open_results;
    int max_results;
    int* result_count;
} SynThreadData;

static void* syn_worker(void* arg) {
    SynThreadData* td = (SynThreadData*)arg;
    while (1) {
        pthread_mutex_lock(&td->queue->lock);
        int idx = td->queue->current_index++;
        pthread_mutex_unlock(&td->queue->lock);
        if (idx >= td->queue->port_count) break;
        bool filtered;
        int rc = hackit_syn_scan_port(td->host, td->queue->ports[idx], td->timeout_ms, &filtered);
        if (rc == 1) {
            pthread_mutex_lock(&td->queue->lock);
            if (*td->result_count < td->max_results) {
                td->open_results[*td->result_count] = true;
                (*td->result_count)++;
            }
            pthread_mutex_unlock(&td->queue->lock);
        }
    }
    return NULL;
}
#endif

int hackit_syn_scan_ports(const char* host, const int* ports, int port_count,
                          int timeout_ms, int threads, int rate_limit,
                          bool* open_results, int max_results) {
    if (!host || !ports || port_count <= 0 || !open_results || max_results <= 0) return -1;
    if (threads < 1) threads = 1;
    if (threads > 256) threads = 256;

    (void)rate_limit;

    SynWorkQueue queue;
#ifdef _WIN32
    InitializeCriticalSection(&queue.lock);
#else
    pthread_mutex_init(&queue.lock, NULL);
#endif
    queue.ports = ports;
    queue.port_count = port_count;
    queue.current_index = 0;

    int result_count = 0;
    SynThreadData td;
    td.host = host;
    td.timeout_ms = timeout_ms;
    td.queue = &queue;
    td.open_results = open_results;
    td.max_results = max_results;
    td.result_count = &result_count;

    memset(open_results, 0, max_results * sizeof(bool));

#ifdef _WIN32
    HANDLE* handles = (HANDLE*)malloc(threads * sizeof(HANDLE));
    for (int i = 0; i < threads; i++) {
        handles[i] = CreateThread(NULL, 0, syn_worker, &td, 0, NULL);
    }
    WaitForMultipleObjects(threads, handles, TRUE, INFINITE);
    for (int i = 0; i < threads; i++) {
        CloseHandle(handles[i]);
    }
    free(handles);
    DeleteCriticalSection(&queue.lock);
#else
    pthread_t* handles = (pthread_t*)malloc(threads * sizeof(pthread_t));
    for (int i = 0; i < threads; i++) {
        pthread_create(&handles[i], NULL, syn_worker, &td);
    }
    for (int i = 0; i < threads; i++) {
        pthread_join(handles[i], NULL);
    }
    free(handles);
    pthread_mutex_destroy(&queue.lock);
#endif

    return result_count;
}

bool hackit_raw_socket_available(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
    SOCKET fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }
    closesocket(fd);
    WSACleanup();
    return true;
#else
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) return false;
    close(fd);
    return true;
#endif
}
