#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include "optimize.h"

typedef struct {
    int count;
    char **addresses;
    char *error;
} DnsResult;

#define DNS_PORT 53
#define DNS_SERVER "8.8.8.8"
#define MAX_DNS_RR 256

#pragma pack(push, 1)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DnsHeader;

typedef struct {
    uint16_t type;
    uint16_t qclass;
} DnsQuestionFooter;

typedef struct {
    uint16_t type;
    uint16_t qclass;
    uint32_t ttl;
    uint16_t rdlength;
} DnsAnswerHeader;
#pragma pack(pop)

static pthread_mutex_t dns_cache_lock = PTHREAD_MUTEX_INITIALIZER;
#define CACHE_SIZE 64
typedef struct { char host[256]; uint32_t ips[16]; int count; time_t expiry; } DnsCacheEntry;
static DnsCacheEntry dns_cache[CACHE_SIZE];
static int dns_cache_next = 0;

static void dns_cache_store(const char *host, uint32_t *ips, int count) {
    time_t now = time(NULL);
    pthread_mutex_lock(&dns_cache_lock);
    int idx = dns_cache_next++ % CACHE_SIZE;
    strncpy(dns_cache[idx].host, host, sizeof(dns_cache[idx].host) - 1);
    dns_cache[idx].host[sizeof(dns_cache[idx].host) - 1] = 0;
    dns_cache[idx].count = count > 16 ? 16 : count;
    memcpy(dns_cache[idx].ips, ips, dns_cache[idx].count * sizeof(uint32_t));
    dns_cache[idx].expiry = now + 60;
    pthread_mutex_unlock(&dns_cache_lock);
}

static int dns_cache_lookup(const char *host, uint32_t *ips, int max) {
    time_t now = time(NULL);
    pthread_mutex_lock(&dns_cache_lock);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (dns_cache[i].host[0] && strcmp(dns_cache[i].host, host) == 0 && dns_cache[i].expiry > now) {
            int n = dns_cache[i].count < max ? dns_cache[i].count : max;
            memcpy(ips, dns_cache[i].ips, n * sizeof(uint32_t));
            pthread_mutex_unlock(&dns_cache_lock);
            return n;
        }
    }
    pthread_mutex_unlock(&dns_cache_lock);
    return -1;
}

static int dns_encode_name(unsigned char *dst, int dstlen, const char *name) {
    int pos = 0;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t labellen = dot ? (size_t)(dot - name) : strlen(name);
        if (labellen == 0 || labellen > 63) return -1;
        if (pos + (int)labellen + 1 > dstlen) return -1;
        dst[pos++] = (unsigned char)labellen;
        memcpy(dst + pos, name, labellen);
        pos += (int)labellen;
        name = dot ? dot + 1 : name + labellen;
    }
    if (pos + 1 > dstlen) return -1;
    dst[pos++] = 0;
    return pos;
}

static int dns_decode_name(const unsigned char *msg, int msglen, int offset, char *out, int outlen) {
    int pos = 0;
    int jumped = 0;
    int orig_offset = offset;
    int loops = 0;
    while (loops < 100) {
        loops++;
        if (offset >= msglen) return -1;
        unsigned char c = msg[offset];
        if ((c & 0xC0) == 0xC0) {
            if (offset + 1 >= msglen) return -1;
            int ptr = ((c & 0x3F) << 8) | msg[offset + 1];
            if (!jumped) { orig_offset = offset + 2; jumped = 1; }
            offset = ptr;
        } else if (c == 0) {
            offset++;
            break;
        } else {
            int labellen = c;
            if (offset + 1 + labellen >= msglen) return -1;
            if (pos + labellen + 1 > outlen) return -1;
            if (pos > 0) out[pos++] = '.';
            memcpy(out + pos, msg + offset + 1, labellen);
            pos += labellen;
            offset += 1 + labellen;
        }
    }
    out[pos] = 0;
    return jumped ? orig_offset : offset;
}

static int dns_raw_query(const char *hostname, int qtype, uint32_t *ips, int max_ips) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (unlikely(sock < 0)) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, DNS_SERVER, &dns_addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    unsigned char pkt[512];
    memset(pkt, 0, sizeof(pkt));
    DnsHeader *hdr = (DnsHeader *)pkt;
    hdr->id = htons((uint16_t)(rand() & 0xFFFF));
    hdr->flags = htons(0x0100);
    hdr->qdcount = htons(1);

    int pos = sizeof(DnsHeader);
    int enclen = dns_encode_name(pkt + pos, sizeof(pkt) - pos - 4, hostname);
    if (enclen < 0) { close(sock); return -1; }
    pos += enclen;
    DnsQuestionFooter *qf = (DnsQuestionFooter *)(pkt + pos);
    qf->type = htons((uint16_t)qtype);
    qf->qclass = htons(1);
    pos += 4;

    if (sendto(sock, pkt, pos, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
        close(sock);
        return -1;
    }

    struct pollfd pf = {.fd = sock, .events = POLLIN};
    pf.revents = 0;
    int n = poll(&pf, 1, 3000);
    if (n <= 0) { close(sock); return -1; }

    unsigned char reply[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int rlen = (int)recvfrom(sock, reply, sizeof(reply), 0, (struct sockaddr *)&from, &fromlen);
    close(sock);
    if (rlen < (int)sizeof(DnsHeader) + 4) return -1;

    DnsHeader *rhdr = (DnsHeader *)reply;
    if ((ntohs(rhdr->flags) & 0x800F) != 0x8000) return -1;

    int ancount = ntohs(rhdr->ancount);
    if (ancount <= 0 || ancount > MAX_DNS_RR) return -1;

    int offset = sizeof(DnsHeader);
    char namebuf[256];
    offset = dns_decode_name(reply, rlen, offset, namebuf, sizeof(namebuf));
    if (offset < 0) return -1;
    offset += 4;

    int count = 0;
    for (int i = 0; i < ancount && count < max_ips; i++) {
        offset = dns_decode_name(reply, rlen, offset, namebuf, sizeof(namebuf));
        if (offset < 0) break;
        if (offset + (int)sizeof(DnsAnswerHeader) > rlen) break;
        DnsAnswerHeader *ah = (DnsAnswerHeader *)(reply + offset);
        offset += sizeof(DnsAnswerHeader);
        uint16_t rdlength = ntohs(ah->rdlength);
        uint16_t rtype = ntohs(ah->type);
        if (rtype == 1 && rdlength == 4 && offset + (int)rdlength <= rlen) {
            uint32_t ip;
            memcpy(&ip, reply + offset, 4);
            ips[count++] = ip;
        } else if (rtype == 28 && rdlength == 16 && offset + (int)rdlength <= rlen) {
        }
        offset += rdlength;
    }
    return count;
}

DnsResult dns_resolve(const char *hostname, int timeout_ms) {
    DnsResult res = {0, NULL, NULL};
    (void)timeout_ms;
    if (!hostname || !hostname[0]) { res.error = strdup("empty hostname"); return res; }

    struct in_addr test_addr;
    if (inet_pton(AF_INET, hostname, &test_addr) == 1) {
        res.count = 1;
        res.addresses = calloc(1, sizeof(char *));
        if (res.addresses) res.addresses[0] = strdup(hostname);
        return res;
    }

    uint32_t ips[16];
    int cached = dns_cache_lookup(hostname, ips, 16);
    if (cached > 0) {
        res.count = cached;
        res.addresses = calloc(cached, sizeof(char *));
        if (res.addresses) {
            for (int i = 0; i < cached; i++) {
                struct in_addr a;
                a.s_addr = ips[i];
                res.addresses[i] = strdup(inet_ntoa(a));
            }
        }
        return res;
    }

    struct hostent *he = gethostbyname(hostname);
    if (he && he->h_addr_list[0]) {
        int count = 0;
        for (int i = 0; he->h_addr_list[i] && count < 16; i++) {
            memcpy(&ips[count], he->h_addr_list[i], 4);
            count++;
        }
        if (count > 0) {
            res.count = count;
            res.addresses = calloc(count, sizeof(char *));
            if (res.addresses) {
                for (int i = 0; i < count; i++) {
                    struct in_addr a;
                    a.s_addr = ips[i];
                    res.addresses[i] = strdup(inet_ntoa(a));
                }
            }
            dns_cache_store(hostname, ips, count);
            return res;
        }
    }

    int raw_count = dns_raw_query(hostname, 1, ips, 16);
    if (raw_count > 0) {
        res.count = raw_count;
        res.addresses = calloc(raw_count, sizeof(char *));
        if (res.addresses) {
            for (int i = 0; i < raw_count; i++) {
                struct in_addr a;
                a.s_addr = ips[i];
                res.addresses[i] = strdup(inet_ntoa(a));
            }
        }
        dns_cache_store(hostname, ips, raw_count);
        return res;
    }

    res.error = strdup("DNS resolution failed");
    return res;
}

DnsResult dns_reverse_lookup(const char *ip) {
    DnsResult res = {0, NULL, NULL};
    if (!ip || !ip[0]) { res.error = strdup("empty IP"); return res; }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        res.error = strdup("invalid IP address");
        return res;
    }

    struct hostent *he = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (he && he->h_name) {
        res.count = 1;
        res.addresses = calloc(1, sizeof(char *));
        if (res.addresses) res.addresses[0] = strdup(he->h_name);
        return res;
    }

    unsigned char *o = (unsigned char *)&addr.s_addr;
    char arpa[64];
    snprintf(arpa, sizeof(arpa), "%d.%d.%d.%d.in-addr.arpa", o[3], o[2], o[1], o[0]);

    uint32_t ips[16];
    int raw_count = dns_raw_query(arpa, 12, ips, 16);
    if (raw_count <= 0) {
        res.error = strdup("PTR lookup failed");
        return res;
    }
    res.count = raw_count;
    res.addresses = calloc(raw_count, sizeof(char *));
    if (res.addresses) {
        for (int i = 0; i < raw_count; i++) {
            struct in_addr a;
            a.s_addr = ips[i];
            res.addresses[i] = strdup(inet_ntoa(a));
        }
    }
    return res;
}

void dns_result_free(DnsResult *res) {
    if (!res) return;
    if (res->addresses) {
        for (int i = 0; i < res->count; i++) free(res->addresses[i]);
        free(res->addresses);
    }
    free(res->error);
    memset(res, 0, sizeof(DnsResult));
}
