#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "optimize.h"

#define SNAP_LEN 65535
#define TIMEOUT_SEC 30
#define MAX_PACKETS 100000
#define TARGET_PORTS 20

typedef struct {
    unsigned long total_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long syn_packets;
    unsigned long ack_packets;
    unsigned long rst_packets;
    unsigned long fin_packets;
    unsigned long psh_packets;
    unsigned long other_packets;
    int ttl_values[256];
    int window_sizes[65536];
    int ip_id_values[65536];
    int src_ports[65536];
    pthread_mutex_t lock;
} PacketStats;

typedef struct {
    int ttl;
    int win;
    int ip_id;
    char src_ip[64];
    int src_port;
    int dst_port;
    unsigned char flags;
    int payload_len;
} PacketInfo;

typedef struct {
    char os_name[128];
    int ttl_min;
    int ttl_max;
    int win_min;
    int win_max;
    int score;
} OSProfile;

static PacketStats stats;
static volatile int capture_running = 1;

static const OSProfile os_profiles[] = {
    {"Windows 10/11", 128, 128, 65535, 65535, 0},
    {"Windows 7/8", 128, 128, 8192, 65535, 0},
    {"Windows XP", 128, 128, 65535, 65535, 0},
    {"Linux 2.4+", 64, 64, 65535, 65535, 0},
    {"Linux 2.6+", 64, 64, 5840, 5840, 0},
    {"Linux 3.x+", 64, 64, 29200, 29200, 0},
    {"Linux 4.x+", 64, 64, 28960, 28960, 0},
    {"FreeBSD", 64, 64, 65535, 65535, 0},
    {"macOS/Darwin", 64, 64, 65535, 65535, 0},
    {"Solaris", 255, 255, 8760, 8760, 0},
    {"Cisco IOS", 255, 255, 16384, 16384, 0},
    {"Android", 64, 64, 5840, 65535, 0},
    {"MikroTik", 64, 64, 65535, 65535, 0},
    {"OpenBSD", 64, 64, 16384, 16384, 0},
    {"", 0, 0, 0, 0, 0},
};

static HOT void analyze_packet(const unsigned char *RESTRICT buf, int len, struct sockaddr_in *RESTRICT src) {
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp;
    PacketInfo pi;
    int ip_hdr_len;
    if (unlikely(ip->version != 4 || (int)(ip->ihl * 4) > len)) return;
    memset(&pi, 0, sizeof(pi));
    pi.ttl = ip->ttl;
    pi.ip_id = ntohs(ip->id);
    strncpy(pi.src_ip, inet_ntoa(src->sin_addr), sizeof(pi.src_ip) - 1);
    ip_hdr_len = ip->ihl * 4;
    if (likely(ip->protocol == IPPROTO_TCP && len >= ip_hdr_len + (int)sizeof(struct tcphdr))) {
        tcp = (struct tcphdr *)(buf + ip_hdr_len);
        pi.win = ntohs(tcp->window);
        pi.flags = tcp->syn | (tcp->ack << 1) | (tcp->rst << 2) | (tcp->fin << 3) | (tcp->psh << 4);
        pi.src_port = ntohs(tcp->source);
        pi.dst_port = ntohs(tcp->dest);
        pi.payload_len = len - ip_hdr_len - tcp->doff * 4;
        pthread_mutex_lock(&stats.lock);
        stats.total_packets++;
        stats.tcp_packets++;
        if (tcp->syn && !tcp->ack) stats.syn_packets++;
        if (tcp->ack && !tcp->syn) stats.ack_packets++;
        if (tcp->rst) stats.rst_packets++;
        if (tcp->fin) stats.fin_packets++;
        if (tcp->psh) stats.psh_packets++;
        if (likely(pi.ttl < 256)) stats.ttl_values[pi.ttl]++;
        if (likely(pi.win < 65536)) stats.window_sizes[pi.win]++;
        if (likely(pi.ip_id < 65536)) stats.ip_id_values[pi.ip_id]++;
        if (likely(pi.src_port < 65536)) stats.src_ports[pi.src_port]++;
        pthread_mutex_unlock(&stats.lock);
    } else if (ip->protocol == IPPROTO_UDP) {
        pthread_mutex_lock(&stats.lock);
        stats.total_packets++; stats.udp_packets++;
        pthread_mutex_unlock(&stats.lock);
    } else if (ip->protocol == IPPROTO_ICMP) {
        pthread_mutex_lock(&stats.lock);
        stats.total_packets++; stats.icmp_packets++;
        pthread_mutex_unlock(&stats.lock);
    }
}

static void guess_os_from_stats(char *RESTRICT os_out, int os_len, double *RESTRICT confidence) {
    int i, best_ttl, best_ttl_count, best_win, best_win_count, best_score, score;
    const char *best_os;
    best_ttl = best_ttl_count = best_win = best_win_count = 0;
    pthread_mutex_lock(&stats.lock);
    for (i = 0; i < 256; ++i) {
        if (stats.ttl_values[i] > best_ttl_count) {
            best_ttl_count = stats.ttl_values[i];
            best_ttl = i;
        }
    }
    for (i = 0; i < 65536; ++i) {
        if (stats.window_sizes[i] > best_win_count) {
            best_win_count = stats.window_sizes[i];
            best_win = i;
        }
    }
    pthread_mutex_unlock(&stats.lock);
    best_score = 0;
    best_os = "Unknown";
    for (i = 0; os_profiles[i].os_name[0]; ++i) {
        score = 0;
        if (best_ttl >= os_profiles[i].ttl_min && best_ttl <= os_profiles[i].ttl_max) score += 50;
        if (best_win >= os_profiles[i].win_min && best_win <= os_profiles[i].win_max) score += 50;
        if (score > best_score) { best_score = score; best_os = os_profiles[i].os_name; }
    }
    snprintf(os_out, (size_t)os_len, "%s", best_os);
    *confidence = (double)best_score;
}

static HOT void *capture_thread(void *arg) {
    int sock, n;
    unsigned char buf[SNAP_LEN];
    struct sockaddr_in src;
    socklen_t src_len;
    struct timeval tv;

    (void)arg;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (unlikely(sock < 0)) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (unlikely(sock < 0)) { fwrite("Need root for raw sockets\n", 1, 26, stderr); capture_running = 0; return NULL; }
    }
    tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    src_len = sizeof(src);
    while (capture_running) {
        n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&src, &src_len);
        if (likely(n > 0)) analyze_packet(buf, n, &src);
    }
    close(sock);
    return NULL;
}

static HOT void *analysis_thread(void *arg) {
    int elapsed;
    unsigned long pkts;
    char os_guess[128];
    double confidence;
    char outbuf[2048];
    int olen;
    struct timespec ts;

    (void)arg;
    elapsed = 0;
    ts.tv_sec = 1; ts.tv_nsec = 0;
    while (capture_running && elapsed < TIMEOUT_SEC) {
        nanosleep(&ts, NULL);
        elapsed++;
        pthread_mutex_lock(&stats.lock);
        pkts = stats.total_packets;
        pthread_mutex_unlock(&stats.lock);
        if (likely(pkts > 0)) {
            olen = snprintf(outbuf, sizeof(outbuf),
                "RESULT:{\"type\":\"stats\",\"packets\":%lu,\"tcp\":%lu,\"udp\":%lu,\"icmp\":%lu,"
                "\"syn\":%lu,\"ack\":%lu,\"rst\":%lu,\"fin\":%lu,\"psh\":%lu}\n",
                pkts, stats.tcp_packets, stats.udp_packets, stats.icmp_packets,
                stats.syn_packets, stats.ack_packets, stats.rst_packets,
                stats.fin_packets, stats.psh_packets);
            fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
        }
    }
    guess_os_from_stats(os_guess, sizeof(os_guess), &confidence);
    olen = snprintf(outbuf, sizeof(outbuf),
        "RESULT:{\"type\":\"os_guess\",\"os\":\"%s\",\"confidence\":\"%.0f%%\","
        "\"total_packets\":%lu,\"tcp_packets\":%lu,\"udp_packets\":%lu}\n",
        os_guess, confidence, stats.total_packets, stats.tcp_packets, stats.udp_packets);
    fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    olen = snprintf(outbuf, sizeof(outbuf),
        "FINAL:{\"total_packets\":%lu,\"os_guess\":\"%s\",\"confidence\":\"%.0f%%\"}\n",
        stats.total_packets, os_guess, confidence);
    fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    memset(&stats, 0, sizeof(stats));
    pthread_mutex_init(&stats.lock, NULL);
    int opt;
    while ((opt = getopt(argc, argv, "t:p:")) != -1) {
        switch (opt) {
            case 't': break;
            case 'p': break;
        }
    }
    pthread_t cap_thr, ana_thr;
    pthread_create(&cap_thr, NULL, capture_thread, NULL);
    pthread_create(&ana_thr, NULL, analysis_thread, NULL);
    pthread_join(cap_thr, NULL);
    capture_running = 0;
    pthread_join(ana_thr, NULL);
    pthread_mutex_destroy(&stats.lock);
    return 0;
}

// vim: ts=4 sw=4 et tw=80
