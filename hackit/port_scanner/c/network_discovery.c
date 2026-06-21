#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netdb.h>
#include <ifaddrs.h>

#include "optimize.h"

#define MAX_HOSTS         65536
#define MAX_WORKERS       32
#define ARP_TIMEOUT_MS    500
#define ICMP_TIMEOUT_MS   1000
#define MAX_TTL_GUESSES   5
#define BROADCAST_IP      "255.255.255.255"

typedef struct {
    uint32_t    ip;
    uint8_t     mac[6];
    char        mac_str[18];
    char        hostname[256];
    int         ttl;
    int         rtt_ms;
    bool        responding;
    bool        is_gateway;
    bool        is_router;
    int         hops_away;
    char        os_guess[64];
    int         confidence;
} DiscoveredHost;

typedef struct {
    uint32_t    network;
    uint32_t    netmask;
    uint32_t    broadcast;
    uint32_t    gateway;
    char        iface[64];
    char        iface_mac[18];
    uint8_t     iface_mac_bytes[6];
} NetworkConfig;

typedef struct {
    NetworkConfig net;
    DiscoveredHost hosts[MAX_HOSTS];
    atomic_int  host_count;
    int         arp_timeout_ms;
    int         icmp_timeout_ms;
    int         thread_count;
    int         max_hosts;
    bool        scan_arp;
    bool        scan_icmp;
    bool        scan_os;
    long long   start_time;
    atomic_int  arp_sent;
    atomic_int  arp_recv;
    atomic_int  icmp_sent;
    atomic_int  icmp_recv;
    char        custom_target[64];
} DiscoveryContext;

HOT static uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) sum += buf[i];
    if (len & 1) sum += (uint16_t)((uint8_t*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static int get_network_config(NetworkConfig* net) {
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) < 0) return -1;

    int found = 0;
    for (struct ifaddrs* ifa = ifaddr; ifa && !found; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;

        struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
        struct sockaddr_in* mask = (struct sockaddr_in*)ifa->ifa_netmask;

        net->network = sin->sin_addr.s_addr & mask->sin_addr.s_addr;
        net->netmask = mask->sin_addr.s_addr;
        net->broadcast = net->network | ~mask->sin_addr.s_addr;
        strncpy(net->iface, ifa->ifa_name, sizeof(net->iface) - 1);
        found = 1;

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            if (ioctl(s, SIOCGIFHWADDR, &ifr) >= 0) {
                uint8_t* mac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
                snprintf(net->iface_mac, sizeof(net->iface_mac),
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                memcpy(net->iface_mac_bytes, mac, 6);
            }
            close(s);
        }

        FILE* fp = fopen("/proc/net/route", "r");
        if (fp) {
            char line[256];
            fgets(line, sizeof(line), fp);
            while (fgets(line, sizeof(line), fp)) {
                char iface_name[16];
                uint32_t dest, gw, mask_val, flags;
                sscanf(line, "%15s %x %x %x", iface_name, &dest, &gw, &flags);
                if (dest == 0 && (flags & 2)) {
                    net->gateway = gw;
                    break;
                }
            }
            fclose(fp);
        }
    }
    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

static int create_arp_socket(const char* iface) {
    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
    if (sock < 0) {
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    }
    if (sock < 0) return -1;

    struct timeval tv = { 0, ARP_TIMEOUT_MS * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

HOT static int send_arp_request(int sock, NetworkConfig* net, uint32_t target_ip) {
    struct ether_header eth;
    memset(&eth, 0, sizeof(eth));
    memset(eth.ether_dhost, 0xFF, 6);
    memcpy(eth.ether_shost, net->iface_mac_bytes, 6);
    eth.ether_type = htons(ETHERTYPE_ARP);

    struct ether_arp arp;
    memset(&arp, 0, sizeof(arp));
    arp.arp_hrd = htons(ARPHRD_ETHER);
    arp.arp_pro = htons(ETHERTYPE_IP);
    arp.arp_hln = 6;
    arp.arp_pln = 4;
    arp.arp_op = htons(ARPOP_REQUEST);
    memcpy(arp.arp_sha, net->iface_mac_bytes, 6);
    memcpy(&arp.arp_spa, &net->network, 4);
    memset(arp.arp_tha, 0, 6);
    memcpy(&arp.arp_tpa, &target_ip, 4);

    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_ARP);
    dest.sll_halen = 6;
    memset(dest.sll_addr, 0xFF, 6);

    char pkt[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    memcpy(pkt, &eth, sizeof(struct ether_header));
    memcpy(pkt + sizeof(struct ether_header), &arp, sizeof(struct ether_arp));

    return sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr*)&dest, sizeof(dest));
}

HOT static int recv_arp_response(int sock, uint32_t* ip, uint8_t* mac) {
    char buf[1024];
    struct sockaddr_ll from;
    socklen_t fl = sizeof(from);

    int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
    if (n < (int)(sizeof(struct ether_header) + sizeof(struct ether_arp))) return -1;

    struct ether_arp* arp = (struct ether_arp*)(buf + sizeof(struct ether_header));
    if (ntohs(arp->arp_op) != ARPOP_REPLY) return -1;
    if (ntohs(arp->arp_pro) != ETHERTYPE_IP) return -1;

    memcpy(ip, &arp->arp_spa, 4);
    memcpy(mac, arp->arp_sha, 6);
    return 0;
}

HOT static int send_icmp_echo(int sock, uint32_t target_ip, int id, int seq) {
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = target_ip;

    char pkt[sizeof(struct icmphdr) + 56];
    memset(pkt, 0, sizeof(pkt));
    struct icmphdr* icmp = (struct icmphdr*)pkt;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons((uint16_t)id);
    icmp->un.echo.sequence = htons((uint16_t)seq);
    icmp->checksum = checksum((uint16_t*)pkt, sizeof(pkt));

    return sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr*)&to, sizeof(to));
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

HOT static int recv_icmp_response(int sock, uint32_t* ip, int* ttl, int id, long long deadline) {
    char buf[1024];
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);

    while (now_ms() < deadline) {
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            continue;
        }
        if (n < (int)(sizeof(struct iphdr) + sizeof(struct icmphdr))) continue;

        struct iphdr* ip_hdr = (struct iphdr*)buf;
        int iphl = ip_hdr->ihl * 4;
        struct icmphdr* icmp = (struct icmphdr*)(buf + iphl);

        if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons((uint16_t)id)) {
            *ip = from.sin_addr.s_addr;
            *ttl = ip_hdr->ttl;
            return 0;
        }
        if (icmp->type == ICMP_TIME_EXCEEDED && n >= iphl + 8 + (int)sizeof(struct iphdr)) {
            struct iphdr* orig = (struct iphdr*)(buf + iphl + 8);
            uint32_t orig_dst = orig->daddr;
            struct sockaddr_in target;
            memset(&target, 0, sizeof(target));
            target.sin_family = AF_INET;
            target.sin_addr.s_addr = orig_dst;

            *ip = from.sin_addr.s_addr;
            *ttl = ip_hdr->ttl;
            return 1;
        }
    }
    return -1;
}

HOT static void guess_os_from_ttl(int ttl, char* os_guess, int sz, int* confidence) {
    if (ttl <= 0) {
        strncpy(os_guess, "unknown", sz - 1);
        *confidence = 0;
        return;
    }

    if (ttl <= 32) {
        strncpy(os_guess, "Windows 95/98/NT", sz - 1);
        *confidence = 60;
    } else if (ttl <= 64) {
        strncpy(os_guess, "Linux/Unix/Mac", sz - 1);
        *confidence = 75;
    } else if (ttl <= 128) {
        strncpy(os_guess, "Windows (NT/2000/XP/Vista/7/8/10)", sz - 1);
        *confidence = 70;
    } else if (ttl <= 255) {
        strncpy(os_guess, "Cisco/Network device", sz - 1);
        *confidence = 65;
    } else {
        strncpy(os_guess, "unknown", sz - 1);
        *confidence = 30;
    }

    if (ttl == 64) { strncpy(os_guess, "Linux", sz - 1); *confidence = 90; }
    else if (ttl == 128) { strncpy(os_guess, "Windows", sz - 1); *confidence = 90; }
    else if (ttl == 255) { strncpy(os_guess, "Cisco IOS", sz - 1); *confidence = 85; }
    else if (ttl == 60) { strncpy(os_guess, "FreeBSD", sz - 1); *confidence = 80; }
    else if (ttl == 30) { strncpy(os_guess, "Solaris", sz - 1); *confidence = 70; }
}

static void mac_to_str(uint8_t* mac, char* str, int sz) {
    snprintf(str, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool is_private_ip(uint32_t ip) {
    uint8_t* b = (uint8_t*)&ip;
    if (b[0] == 10) return true;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
    if (b[0] == 192 && b[1] == 168) return true;
    return false;
}

HOT static void* arp_scan_worker(void* arg) {
    DiscoveryContext* ctx = (DiscoveryContext*)arg;
    int sock = create_arp_socket(ctx->net.iface);
    if (sock < 0) {
        fprintf(stderr, "Failed to create ARP socket (need root?)\n");
        return NULL;
    }

    uint32_t network = ctx->net.network;
    uint32_t netmask = ctx->net.netmask;
    uint32_t host_count = ~netmask;

    while (1) {
        int idx = atomic_fetch_add(&ctx->host_count, 1);
        if (idx >= MAX_HOSTS || idx > (int)host_count) break;

        uint32_t target_ip = htonl(ntohl(network) + idx);
        if (target_ip == ctx->net.network || target_ip == ctx->net.broadcast)
            continue;

        atomic_fetch_add(&ctx->arp_sent, 1);
        send_arp_request(sock, &ctx->net, target_ip);

        usleep(1000);
    }

    usleep(ctx->arp_timeout_ms * 1000);

    for (int i = 0; i < ctx->host_count; i++) {
        uint32_t target_ip = htonl(ntohl(ctx->net.network) + i);
        uint32_t resp_ip;
        uint8_t mac[6];

        if (recv_arp_response(sock, &resp_ip, mac) == 0) {
            int host_idx = (int)(ntohl(resp_ip) - ntohl(ctx->net.network));
            if (host_idx >= 0 && host_idx < ctx->host_count) {
                DiscoveredHost* host = &ctx->hosts[host_idx];
                host->ip = resp_ip;
                memcpy(host->mac, mac, 6);
                mac_to_str(mac, host->mac_str, sizeof(host->mac_str));
                host->responding = true;
                atomic_fetch_add(&ctx->arp_recv, 1);

                if (resp_ip == ctx->net.gateway) {
                    host->is_gateway = true;
                }
            }
        }
    }

    close(sock);
    return NULL;
}

HOT static void* icmp_scan_worker(void* arg) {
    DiscoveryContext* ctx = (DiscoveryContext*)arg;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        fprintf(stderr, "Failed to create ICMP socket (need root?)\n");
        return NULL;
    }

    struct timeval tv = { 0, ICMP_TIMEOUT_MS * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int pid = (int)(getpid() & 0xFFFF);
    srand((unsigned int)(time(NULL) ^ (uintptr_t)pthread_self()));

    for (int i = 0; i < ctx->host_count; i++) {
        DiscoveredHost* host = &ctx->hosts[i];
        if (!host->ip || host->ip == 0) continue;

        int seq = i;
        atomic_fetch_add(&ctx->icmp_sent, 1);
        send_icmp_echo(sock, host->ip, pid ^ seq, seq);
        usleep(50000);
    }

    long long deadline = now_ms() + ctx->icmp_timeout_ms;

    while (now_ms() < deadline) {
        uint32_t resp_ip;
        int resp_ttl;
        int rc = recv_icmp_response(sock, &resp_ip, &resp_ttl, pid, deadline);
        if (rc < 0) continue;

        uint32_t network_n = ntohl(ctx->net.network);
        uint32_t resp_n = ntohl(resp_ip);
        int host_idx = (int)(resp_n - network_n);

        if (host_idx >= 0 && host_idx < ctx->host_count) {
            DiscoveredHost* host = &ctx->hosts[host_idx];
            host->ip = resp_ip;
            host->ttl = resp_ttl;
            host->rtt_ms = (int)(now_ms() - ctx->start_time);
            if (!host->responding) {
                host->responding = true;
            }
            if (resp_ttl > 0) {
                guess_os_from_ttl(resp_ttl, host->os_guess, sizeof(host->os_guess), &host->confidence);
            }
            atomic_fetch_add(&ctx->icmp_recv, 1);
        }
    }

    close(sock);
    return NULL;
}

static void print_host(DiscoveredHost* host) {
    char ip_str[16];
    struct in_addr addr;
    addr.s_addr = host->ip;
    strncpy(ip_str, inet_ntoa(addr), sizeof(ip_str) - 1);

    printf("{\"ip\":\"%s\",\"mac\":\"%s\",\"responding\":%s,\"ttl\":%d,\"rtt_ms\":%d,\"os_guess\":\"%s\",\"os_confidence\":%d,\"gateway\":%s,\"hostname\":\"%s\"}\n",
        ip_str,
        host->mac_str[0] ? host->mac_str : "unknown",
        host->responding ? "true" : "false",
        host->ttl, host->rtt_ms,
        host->os_guess, host->confidence,
        host->is_gateway ? "true" : "false",
        host->hostname);
}

static uint32_t resolve_ip(const char* hostname) {
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) return addr.s_addr;
    struct hostent* he = gethostbyname(hostname);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static void resolve_hostnames(DiscoveredHost* hosts, int count) {
    for (int i = 0; i < count; i++) {
        if (hosts[i].ip == 0) continue;
        struct hostent* he = gethostbyaddr(&hosts[i].ip, 4, AF_INET);
        if (he && he->h_name) {
            strncpy(hosts[i].hostname, he->h_name, sizeof(hosts[i].hostname) - 1);
        }
    }
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "  -t <target>    Single target IP for directed discovery\n");
    fprintf(stderr, "  -i <iface>     Interface to use (default: auto)\n");
    fprintf(stderr, "  --no-arp       Skip ARP scan\n");
    fprintf(stderr, "  --no-icmp      Skip ICMP scan\n");
    fprintf(stderr, "  --no-os        Skip OS fingerprinting\n");
    fprintf(stderr, "  -T <ms>        ARP/ICMP timeout (default: 1000)\n");
    fprintf(stderr, "  -j <threads>   Worker threads (default: 4)\n");
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: network discovery requires root privileges\n");
        return 1;
    }

    DiscoveryContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.arp_timeout_ms = ARP_TIMEOUT_MS;
    ctx.icmp_timeout_ms = ICMP_TIMEOUT_MS;
    ctx.thread_count = 4;
    ctx.scan_arp = true;
    ctx.scan_icmp = true;
    ctx.scan_os = true;
    ctx.custom_target[0] = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            strncpy(ctx.custom_target, argv[++i], sizeof(ctx.custom_target) - 1);
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) { }
        else if (strcmp(argv[i], "--no-arp") == 0) ctx.scan_arp = false;
        else if (strcmp(argv[i], "--no-icmp") == 0) ctx.scan_icmp = false;
        else if (strcmp(argv[i], "--no-os") == 0) ctx.scan_os = false;
        else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            ctx.arp_timeout_ms = atoi(argv[++i]);
            ctx.icmp_timeout_ms = ctx.arp_timeout_ms;
        } else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc)
            ctx.thread_count = atoi(argv[++i]);
    }

    if (get_network_config(&ctx.net) < 0) {
        fprintf(stderr, "Failed to get network configuration\n");
        return 1;
    }

    ctx.start_time = now_ms();

    char network_str[16], mask_str[16], gw_str[16];
    struct in_addr naddr, maddr, gwaddr;
    naddr.s_addr = ctx.net.network;
    maddr.s_addr = ctx.net.netmask;
    gwaddr.s_addr = ctx.net.gateway;

    fprintf(stderr, "NET_DISCOVER iface=%s network=%s netmask=%s broadcast=%s gw=%s\n",
        ctx.net.iface,
        inet_ntoa(naddr), inet_ntoa(maddr),
        inet_ntoa(gwaddr),
        ctx.net.gateway ? inet_ntoa(gwaddr) : "none");

    uint32_t host_count = ~ctx.net.netmask;
    if (host_count > MAX_HOSTS) host_count = MAX_HOSTS;

    memset(ctx.hosts, 0, sizeof(DiscoveredHost) * host_count);

    if (ctx.custom_target[0]) {
        uint32_t target = resolve_ip(ctx.custom_target);
        if (target == 0) {
            fprintf(stderr, "Failed to resolve: %s\n", ctx.custom_target);
            return 1;
        }
        DiscoveredHost* host = &ctx.hosts[0];
        host->ip = target;
        ctx.host_count = 1;
        fprintf(stderr, "Using custom target: %s\n", ctx.custom_target);
    }

    if (ctx.scan_arp && !ctx.custom_target[0]) {
        ctx.host_count = host_count;
        pthread_t arp_thread;
        pthread_create(&arp_thread, NULL, arp_scan_worker, &ctx);
        pthread_join(arp_thread, NULL);
    }

    if (ctx.scan_icmp) {
        pthread_t icmp_thread;
        pthread_create(&icmp_thread, NULL, icmp_scan_worker, &ctx);
        pthread_join(icmp_thread, NULL);
    }

    int discovered = 0;
    int max_idx = ctx.custom_target[0] ? 1 : ctx.host_count;

    resolve_hostnames(ctx.hosts, max_idx);

    for (int i = 0; i < max_idx; i++) {
        if (ctx.hosts[i].responding && ctx.hosts[i].ip != 0) {
            print_host(&ctx.hosts[i]);
            discovered++;
        }
    }

    if (discovered == 0) {
        for (int i = 0; i < max_idx; i++) {
            if (ctx.hosts[i].ip != 0 && !ctx.hosts[i].responding) {
                print_host(&ctx.hosts[i]);
            }
        }
    }

    long long elapsed = now_ms() - ctx.start_time;
    fprintf(stderr, "FINAL:{\"iface\":\"%s\",\"discovered\":%d,\"arp_sent\":%d,\"arp_recv\":%d,\"icmp_sent\":%d,\"icmp_recv\":%d,\"elapsed_ms\":%lld}\n",
        ctx.net.iface, discovered,
        (int)atomic_load(&ctx.arp_sent), (int)atomic_load(&ctx.arp_recv),
        (int)atomic_load(&ctx.icmp_sent), (int)atomic_load(&ctx.icmp_recv), elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
