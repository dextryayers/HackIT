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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "optimize.h"

#define MAX_QUERIES     4096
#define MAX_BURST       256
#define DNS_BUF_SIZE    4096
#define EDNS0_SIZE      4096
#define MAX_RESOLVERS   4
#define MAX_WORKERS     8
#define MAX_RETRY       3

typedef enum {
    REC_A = 1,
    REC_NS = 2,
    REC_MX = 15,
    REC_TXT = 16,
    REC_AAAA = 28,
} RecordType;

typedef struct {
    char        name[256];
    int         type;
    char        result[1024];
    char        result_extra[1024];
    bool        resolved;
    int         ttl;
    int         retries;
} QueryResult;

typedef struct {
    char        domain[256];
    int         query_type;
} QueryEntry;

typedef struct {
    QueryEntry  queries[MAX_QUERIES];
    int         query_count;
    atomic_int  next_query;
    QueryResult results[MAX_QUERIES];
    atomic_int  result_count;
    int         resolver_count;
    struct sockaddr_in resolvers[MAX_RESOLVERS];
    int         timeout_ms;
    int         retry_count;
    int         burst_size;
    int         thread_count;
    atomic_int  success_count;
    atomic_int  fail_count;
    long long   start_time;
    bool        running;
} DNSContext;

static const char* type_name(int type) {
    switch (type) {
        case REC_A: return "A";
        case REC_AAAA: return "AAAA";
        case REC_MX: return "MX";
        case REC_TXT: return "TXT";
        case REC_NS: return "NS";
        default: return "UNKNOWN";
    }
}

static ALWAYS_INLINE uint16_t dns_checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) sum += buf[i];
    if (len & 1) sum += (uint16_t)((uint8_t*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

HOT static int build_dns_query(char* buf, int id, const char* domain, int qtype, bool edns) {
    int pos = 0;
    uint16_t* hdr = (uint16_t*)buf;
    hdr[0] = htons((uint16_t)(id & 0xFFFF));
    hdr[1] = htons(0x0100);
    hdr[2] = htons(1);
    hdr[3] = htons(0);
    hdr[4] = htons(0);
    hdr[5] = htons(0);
    pos = 12;

    const char* p = domain;
    while (p && *p) {
        const char* dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len > 63) len = 63;
        buf[pos++] = (uint8_t)len;
        memcpy(buf + pos, p, len);
        pos += len;
        p = dot ? dot + 1 : NULL;
    }
    buf[pos++] = 0;

    *(uint16_t*)(buf + pos) = htons((uint16_t)qtype);
    pos += 2;
    *(uint16_t*)(buf + pos) = htons(1);
    pos += 2;

    if (edns) {
        buf[pos++] = 0;
        buf[pos++] = 0;
        buf[pos++] = 41;
        uint16_t edns_len = htons(EDNS0_SIZE);
        memcpy(buf + pos, &edns_len, 2);
        pos += 2;
        uint32_t edns_extra = 0;
        memcpy(buf + pos, &edns_extra, 4);
        pos += 4;
        uint16_t rdata_len = 0;
        memcpy(buf + pos, &rdata_len, 2);
        pos += 2;
    }
    return pos;
}

HOT static int parse_dns_response(const char* buf, int len, int query_type, char* out, int out_size, char* extra, int extra_size) {
    if (len < 12) return -1;
    const uint16_t* hdr = (const uint16_t*)buf;
    int id = ntohs(hdr[0]);
    int flags = ntohs(hdr[1]);
    if (flags & 0x000F) return -2;

    int qdcount = ntohs(hdr[2]), ancount = ntohs(hdr[3]);
    if (ancount == 0) return -3;

    int pos = 12;
    for (int i = 0; i < qdcount && pos < len; i++) {
        while (pos < len && buf[pos] != 0) {
            if ((buf[pos] & 0xC0) == 0xC0) { pos += 2; break; }
            pos += (uint8_t)buf[pos] + 1;
        }
        pos += 5;
    }

    int found = 0;
    for (int i = 0; i < ancount && pos < len && found < 2; i++) {
        uint16_t label;
        memcpy(&label, buf + pos, 2);
        if ((ntohs(label) & 0xC000) == 0xC000) pos += 2;
        else {
            while (pos < len && buf[pos] != 0) pos += (uint8_t)buf[pos] + 1;
            pos++;
        }
        if (pos + 10 > len) break;
        uint16_t rtype = ntohs(*(uint16_t*)(buf + pos));
        pos += 2;
        uint16_t rclass = ntohs(*(uint16_t*)(buf + pos));
        pos += 2;
        uint32_t rttl = ntohl(*(uint32_t*)(buf + pos));
        pos += 4;
        uint16_t rdlen = ntohs(*(uint16_t*)(buf + pos));
        pos += 2;
        if (pos + rdlen > len) break;

        if (found == 0 && extra) extra[0] = 0;

        if (rtype == REC_A && rdlen == 4) {
            struct in_addr addr;
            memcpy(&addr, buf + pos, 4);
            char* target = found == 0 ? out : extra;
            snprintf(target, found == 0 ? out_size : extra_size, "%s", inet_ntoa(addr));
            found++;
        } else if (rtype == REC_AAAA && rdlen == 16) {
            struct in6_addr addr;
            memcpy(&addr, buf + pos, 16);
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr, addr_str, sizeof(addr_str));
            char* target = found == 0 ? out : extra;
            snprintf(target, found == 0 ? out_size : extra_size, "%s", addr_str);
            found++;
        } else if (rtype == REC_MX) {
            if (rdlen >= 3) {
                uint16_t pref = ntohs(*(uint16_t*)(buf + pos));
                int mxpos = pos + 2;
                char mxname[256];
                int mxlen = 0;
                while (mxpos < len && buf[mxpos] != 0) {
                    int slen = (uint8_t)buf[mxpos];
                    if (slen == 0) break;
                    if (mxlen > 0) mxname[mxlen++] = '.';
                    mxpos++;
                    for (int s = 0; s < slen && mxpos < len; s++) {
                        mxname[mxlen++] = buf[mxpos++];
                    }
                }
                mxname[mxlen] = 0;
                snprintf(out, out_size, "%s (priority %d)", mxname, pref);
                found = 1;
            }
        } else if (rtype == REC_TXT) {
            int tpos = pos;
            int tlen = 0;
            while (tpos < pos + rdlen) {
                int slen = (uint8_t)buf[tpos++];
                for (int s = 0; s < slen && tpos < pos + rdlen && tlen < out_size - 1; s++)
                    out[tlen++] = buf[tpos++];
            }
            out[tlen] = 0;
            found = 1;
        } else if (rtype == REC_NS) {
            int npos = pos;
            char nsname[256];
            int nslen = 0;
            while (npos < len && buf[npos] != 0) {
                if ((buf[npos] & 0xC0) == 0xC0) { npos += 2; break; }
                int slen = (uint8_t)buf[npos];
                if (slen == 0) break;
                if (nslen > 0) nsname[nslen++] = '.';
                npos++;
                for (int s = 0; s < slen && npos < len; s++)
                    nsname[nslen++] = buf[npos++];
            }
            nsname[nslen] = 0;
            char* target = found == 0 ? out : extra;
            snprintf(target, found == 0 ? out_size : extra_size, "%s", nsname);
            found++;
        }
        pos += rdlen;
    }
    return found > 0 ? 0 : -4;
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

HOT static void* resolver_worker(void* arg) {
    DNSContext* ctx = (DNSContext*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (unlikely(sock < 0)) return NULL;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    struct timeval tv = { ctx->timeout_ms / 1000, (ctx->timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int buf_size = 256 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

    srand((unsigned int)(time(NULL) ^ (uintptr_t)pthread_self()));

    while (1) {
        int base = atomic_fetch_add(&ctx->next_query, ctx->burst_size);
        if (base >= ctx->query_count) break;

        int remaining = ctx->query_count - base;
        int burst = remaining > ctx->burst_size ? ctx->burst_size : remaining;

        char send_bufs[MAX_BURST][DNS_BUF_SIZE];
        int send_lens[MAX_BURST];
        int send_ids[MAX_BURST];
        int send_indices[MAX_BURST];

        int nsent = 0;
        for (int i = 0; i < burst; i++) {
            int qi = base + i;
            int id = (int)((uintptr_t)pthread_self() & 0xFFFF) ^ (qi & 0xFFFF) ^ (rand() & 0xFFFF);
            send_lens[i] = build_dns_query(send_bufs[i], id, ctx->queries[qi].domain, ctx->queries[qi].query_type, true);
            send_ids[i] = id;
            send_indices[i] = qi;

            int ri = rand() % ctx->resolver_count;
            int ret = sendto(sock, send_bufs[i], send_lens[i], 0,
                (struct sockaddr*)&ctx->resolvers[ri], sizeof(struct sockaddr_in));
            if (ret > 0) nsent++;
        }

        if (nsent == 0) continue;

        long long deadline = now_ms() + ctx->timeout_ms;
        int recvd = 0;
        while (now_ms() < deadline && recvd < burst) {
            char recv_buf[DNS_BUF_SIZE];
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int n = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from, &fl);
            if (unlikely(n <= 0)) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                continue;
            }
            int resp_id = ntohs(*(uint16_t*)recv_buf);
            for (int i = 0; i < burst; i++) {
                if (send_ids[i] == resp_id && !ctx->results[send_indices[i]].resolved) {
                    char result[1024] = {0};
                    char extra[1024] = {0};
                    int rc = parse_dns_response(recv_buf, n, ctx->queries[send_indices[i]].query_type, result, sizeof(result), extra, sizeof(extra));
                    if (rc == 0) {
                        QueryResult* qr = &ctx->results[send_indices[i]];
                        strncpy(qr->result, result, sizeof(qr->result) - 1);
                        if (extra[0]) strncpy(qr->result_extra, extra, sizeof(qr->result_extra) - 1);
                        qr->resolved = true;
                        atomic_fetch_add(&ctx->success_count, 1);
                        recvd++;
                    } else {
                        ctx->results[send_indices[i]].retries++;
                        if (ctx->results[send_indices[i]].retries >= ctx->retry_count) {
                            ctx->results[send_indices[i]].resolved = true;
                            atomic_fetch_add(&ctx->fail_count, 1);
                            recvd++;
                        }
                    }
                    break;
                }
            }
        }

        for (int i = 0; i < burst; i++) {
            if (!ctx->results[send_indices[i]].resolved) {
                ctx->results[send_indices[i]].retries++;
                if (ctx->results[send_indices[i]].retries >= ctx->retry_count) {
                    ctx->results[send_indices[i]].resolved = true;
                    atomic_fetch_add(&ctx->fail_count, 1);
                }
            }
        }
    }
    close(sock);
    return NULL;
}

static int add_resolver(DNSContext* ctx, const char* ip_str) {
    if (ctx->resolver_count >= MAX_RESOLVERS) return -1;
    struct sockaddr_in* sa = &ctx->resolvers[ctx->resolver_count];
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons(53);
    if (inet_pton(AF_INET, ip_str, &sa->sin_addr) != 1) return -1;
    ctx->resolver_count++;
    return 0;
}

static int load_default_resolvers(DNSContext* ctx) {
    const char* defaults[] = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"
    };
    int count = 0;
    for (int i = 0; i < 4 && ctx->resolver_count < MAX_RESOLVERS; i++) {
        if (add_resolver(ctx, defaults[i]) == 0) count++;
    }
    return count;
}

static int load_resolvers_from_file(DNSContext* ctx, const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char line[128];
    while (fgets(line, sizeof(line), f) && ctx->resolver_count < MAX_RESOLVERS) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char* comment = strchr(line, '#');
        if (comment) *comment = 0;
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0) continue;
        add_resolver(ctx, p);
    }
    fclose(f);
    return ctx->resolver_count;
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <domain1,domain2,...> [type] [timeout_ms] [threads] [burst_size] [resolvers]\n", prog);
    fprintf(stderr, "  type: A, AAAA, MX, TXT, NS (default: A)\n");
    fprintf(stderr, "  resolvers: comma-separated IPs or 'default' or '/etc/resolv.conf'\n");
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    DNSContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.timeout_ms = argc > 3 ? atoi(argv[3]) : 3000;
    ctx.thread_count = argc > 4 ? atoi(argv[4]) : 4;
    ctx.burst_size = argc > 5 ? atoi(argv[5]) : 64;
    ctx.retry_count = MAX_RETRY;

    if (ctx.thread_count < 1) ctx.thread_count = 1;
    if (ctx.thread_count > MAX_WORKERS) ctx.thread_count = MAX_WORKERS;
    if (ctx.burst_size < 1) ctx.burst_size = 1;
    if (ctx.burst_size > MAX_BURST) ctx.burst_size = MAX_BURST;

    int qtype = REC_A;
    if (argc > 2) {
        if (strcasecmp(argv[2], "AAAA") == 0) qtype = REC_AAAA;
        else if (strcasecmp(argv[2], "MX") == 0) qtype = REC_MX;
        else if (strcasecmp(argv[2], "TXT") == 0) qtype = REC_TXT;
        else if (strcasecmp(argv[2], "NS") == 0) qtype = REC_NS;
    }

    char domains_buf[65536];
    strncpy(domains_buf, argv[1], sizeof(domains_buf) - 1);
    domains_buf[sizeof(domains_buf) - 1] = 0;
    ctx.query_count = 0;
    char* d = strtok(domains_buf, ",");
    while (d && ctx.query_count < MAX_QUERIES) {
        while (*d == ' ' || *d == '\t') d++;
        strncpy(ctx.queries[ctx.query_count].domain, d, sizeof(ctx.queries[ctx.query_count].domain) - 1);
        ctx.queries[ctx.query_count].query_type = qtype;
        ctx.query_count++;
        d = strtok(NULL, ",");
    }

    if (ctx.query_count == 0) {
        fprintf(stderr, "No domains specified\n");
        return 1;
    }

    if (argc > 6) {
        if (strcmp(argv[6], "default") == 0) {
            load_default_resolvers(&ctx);
        } else if (strchr(argv[6], '/') || strcmp(argv[6], "/etc/resolv.conf") == 0) {
            load_resolvers_from_file(&ctx, argv[6]);
        } else {
            char resolvers_buf[1024];
            strncpy(resolvers_buf, argv[6], sizeof(resolvers_buf) - 1);
            resolvers_buf[sizeof(resolvers_buf) - 1] = 0;
            char* r = strtok(resolvers_buf, ",");
            while (r && ctx.resolver_count < MAX_RESOLVERS) {
                add_resolver(&ctx, r);
                r = strtok(NULL, ",");
            }
        }
    }
    if (ctx.resolver_count == 0) load_default_resolvers(&ctx);

    fprintf(stderr, "DNS_BURST domains=%d type=%s resolvers=%d timeout=%dms threads=%d burst=%d\n",
        ctx.query_count, type_name(qtype), ctx.resolver_count,
        ctx.timeout_ms, ctx.thread_count, ctx.burst_size);

    for (int i = 0; i < ctx.query_count; i++) {
        strncpy(ctx.results[i].name, ctx.queries[i].domain, sizeof(ctx.results[i].name) - 1);
        ctx.results[i].type = ctx.queries[i].query_type;
    }

    ctx.start_time = now_ms();
    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < ctx.thread_count; i++)
        pthread_create(&workers[i], NULL, resolver_worker, &ctx);
    for (int i = 0; i < ctx.thread_count; i++)
        pthread_join(workers[i], NULL);

    long long elapsed = now_ms() - ctx.start_time;

    for (int i = 0; i < ctx.query_count; i++) {
        QueryResult* r = &ctx.results[i];
        if (r->resolved && r->result[0]) {
            printf("{\"domain\":\"%s\",\"type\":\"%s\",\"value\":\"%s\"",
                r->name, type_name(r->type), r->result);
            if (r->result_extra[0])
                printf(",\"extra\":\"%s\"", r->result_extra);
            printf("}\n");
        } else {
            printf("{\"domain\":\"%s\",\"type\":\"%s\",\"error\":\"no_record\"}\n",
                r->name, type_name(r->type));
        }
    }

    fprintf(stderr, "FINAL:{\"total\":%d,\"success\":%d,\"failed\":%d,\"elapsed_ms\":%lld}\n",
        ctx.query_count,
        (int)atomic_load(&ctx.success_count),
        (int)atomic_load(&ctx.fail_count), elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
