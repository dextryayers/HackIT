/* network_path.c — Network Path Discovery (Traceroute + MTU)
#define _GNU_SOURCE
 * Compile: gcc -O3 -o ../bin/network_path network_path.c -lpthread
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <errno.h>

#include "optimize.h"

#define MAX_HOPS 64

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static unsigned short csum(void *b, int len) {
    unsigned short *buf = b; unsigned int sum = 0;
    for (int i = 0; i < len; i += 2) sum += *buf++;
    if (len & 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF); sum += (sum >> 16);
    return (unsigned short)~sum;
}

static void udp_traceroute(const char *target, int timeout_ms) {
    struct hostent *he = gethostbyname(target);
    if (!he) { fprintf(stderr, "[!] Unknown host: %s\n", target); return; }
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], he->h_length);
    printf("STATUS:{\"message\":\"Traceroute to %s (%s)\",\"progress\":0}\n", target, inet_ntoa(addr));
    fflush(stdout);

    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0) { fprintf(stderr, "[!] Root required\n"); return; }
    struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        long long start = now_ms();
        int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (send_sock < 0) continue;
        setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct sockaddr_in dest = {.sin_family = AF_INET, .sin_addr = addr, .sin_port = htons(33434 + ttl)};
        sendto(send_sock, "x", 1, 0, (struct sockaddr*)&dest, sizeof(dest));
        close(send_sock);

        char buf[512];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        int n = recvfrom(recv_sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
        long long elapsed = now_ms() - start;
        char hop_ip[64] = "*";
        int hop_ttl = 0;
        if (n > 0) {
            struct ip *ip_hdr = (struct ip *)buf;
            struct icmp *icmp_hdr = (struct icmp *)(buf + (ip_hdr->ip_hl << 2));
            strncpy(hop_ip, inet_ntoa(from.sin_addr), sizeof(hop_ip) - 1);
            hop_ttl = ip_hdr->ip_ttl;
            if (icmp_hdr->icmp_type == 3 && icmp_hdr->icmp_code == 3) {
                printf("RESULT:{\"hop\":%d,\"ip\":\"%s\",\"status\":\"destination_reached\","
                       "\"rtt_ms\":%lld}\n", ttl, hop_ip, elapsed);
                fflush(stdout);
                break;
            }
        }
        printf("RESULT:{\"hop\":%d,\"ip\":\"%s\",\"status\":\"%s\",\"ttl\":%d,\"rtt_ms\":%lld}\n",
               ttl, hop_ip, strcmp(hop_ip, "*") ? "hop" : "timeout", hop_ttl, elapsed);
        fflush(stdout);
    }
    close(recv_sock);
}

static void mtu_discovery(const char *target) {
    struct hostent *he = gethostbyname(target);
    if (!he) return;
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], he->h_length);
    printf("STATUS:{\"message\":\"MTU Discovery to %s\",\"progress\":0}\n", target);
    fflush(stdout);
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return;
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int sizes[] = {1500, 1492, 1472, 1468, 1452, 1440, 1420, 1400, 1380, 1360, 1340, 1320, 1300, 1280, 1200, 1100, 1000, 900, 800, 700, 600, 500, 400, 300, 200, 100, 68};
    int mtu = 0;
    for (int i = 0; i < (int)(sizeof(sizes)/sizeof(sizes[0])); ++i) {
        int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (send_sock < 0) continue;
        setsockopt(send_sock, IPPROTO_IP, IP_MTU_DISCOVER, &(int){1}, sizeof(int));
        struct sockaddr_in dest = {.sin_family = AF_INET, .sin_addr = addr};
        char *buf = malloc(sizes[i]);
        memset(buf, 0, sizes[i]);
        if (sendto(send_sock, buf, sizes[i], 0, (struct sockaddr*)&dest, sizeof(dest)) > 0) {
            mtu = sizes[i];
        }
        free(buf);
        close(send_sock);
    }
    if (mtu > 0) {
        printf("RESULT:{\"target\":\"%s\",\"mtu\":%d,\"module\":\"mtu_discovery\"}\n", target, mtu);
        fflush(stdout);
    }
    close(sock);
}

int main(int argc, char **argv) {
    char target[256] = {0}; int timeout = 3000, mode = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) strncpy(target, argv[++i], 255);
        else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) timeout = atoi(argv[++i]) * 1000;
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            if (!strcmp(argv[i+1], "traceroute")) mode = 1;
            else if (!strcmp(argv[i+1], "mtu")) mode = 2;
            else if (!strcmp(argv[i+1], "all")) mode = 3;
            i++;
        }
    }
    if (!target[0]) { fprintf(stderr, "Usage: %s --target <host> [--mode traceroute|mtu|all]\n", argv[0]); return 1; }
    if (mode == 1 || mode == 3) udp_traceroute(target, timeout);
    if (mode == 2 || mode == 3) mtu_discovery(target);
    printf("FINAL:{\"target\":\"%s\",\"module\":\"network_path\"}\n", target);
    fflush(stdout);
    return 0;
}

// vim: ts=4 sw=4 et tw=80
