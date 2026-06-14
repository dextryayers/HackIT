#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#define MAX_PORTS        131072
#define MAX_CONCURRENT   65536
#define MAX_BANNER       4096
#define BATCH_SIZE       1024
#define TIMEOUT_MS       1500
#define MAX_WORKERS      32

typedef struct {
    int  port;
    int  fd;
    bool in_use;
    long long connect_time;
} ConnSlot;

typedef struct {
    int   port;
    int   state;
    char  service[64];
    char  banner[MAX_BANNER];
    int   ttl;
    int   rtt_ms;
} ScanResult;

typedef struct {
    const char* hostname;
    uint32_t    ip;
    int*        ports;
    int         port_count;
    int         timeout_ms;
    int         workers;
    int         batch_size;
    ScanResult  results[MAX_PORTS];
    int         result_count;
    int         open_count;
    int         epfd;
    long long   start_time;
    pthread_mutex_t lock;
} MassContext;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint32_t resolve_ip(const char* host) {
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) == 1) return addr.s_addr;
    struct hostent* he = gethostbyname(host);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static int parse_ports(const char* spec, int* ports, int max) {
    int count = 0;
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    if (strcmp(buf, "all") == 0) {
        for (int p = 1; p <= 65535 && count < max; p++) ports[count++] = p;
        return count;
    }
    if (strcmp(buf, "top100") == 0 || strcmp(buf, "top:100") == 0) {
        int top[] = {21,22,23,25,53,80,110,111,135,139,143,161,179,389,443,445,465,514,587,636,873,990,992,993,995,1080,1194,1352,1433,1521,1723,2049,2375,2376,2379,3128,3306,3389,3690,4369,5432,5672,5900,5984,5985,6379,6443,8080,8443,8500,9090,9092,9200,9418,10250,11211,15672,25565,27017,32400,0};
        for (int i = 0; top[i] && count < max; i++) ports[count++] = top[i];
        return count;
    }
    char* token = strtok(buf, ",");
    while (token && count < max) {
        char* dash = strchr(token, '-');
        if (dash) {
            int s = atoi(token), e = atoi(dash + 1);
            if (s < 1) s = 1; if (e > 65535) e = 65535;
            for (int p = s; p <= e && count < max; p++) ports[count++] = p;
        } else { int p = atoi(token); if (p >= 1 && p <= 65535) ports[count++] = p; }
        token = strtok(NULL, ",");
    }
    return count;
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_block(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static int prepare_connect(int epfd, uint32_t ip, int port, int timeout_ms) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    int flag = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.data.u32 = (uint32_t)port;
    ev.events = EPOLLOUT | EPOLLERR | EPOLLONESHOT;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) { close(fd); return -1; }
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    return fd;
}

static void* worker_poll(void* arg) {
    MassContext* ctx = (MassContext*)arg;
    struct epoll_event events[4096];
    char banner_buf[MAX_BANNER];
    while (1) {
        pthread_mutex_lock(&ctx->lock);
        int remaining = ctx->port_count - ctx->result_count;
        pthread_mutex_unlock(&ctx->lock);
        if (remaining <= 0) break;
        int n = epoll_wait(ctx->epfd, events, 4096, 100);
        if (n < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            int port = (int)events[i].data.u32;
            uint32_t events_occured = events[i].events;
            bool open = false;
            if (events_occured & EPOLLOUT) {
                int so_err = 0;
                socklen_t err_len = sizeof(so_err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
                if (so_err == 0) open = true;
            }
            if (open) {
                set_block(fd);
                struct timeval tv = {0, 500000};
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                memset(banner_buf, 0, sizeof(banner_buf));
                int total = 0;
                for (int a = 0; a < 3 && total < MAX_BANNER - 1; a++) {
                    int r = (int)read(fd, banner_buf + total, MAX_BANNER - 1 - total);
                    if (r > 0) total += r; else break;
                }
                if (total == 0 && (port == 80 || port == 8080 || port == 443 || port == 8443)) {
                    const char* req = "GET / HTTP/1.0\r\nHost: hackit\r\n\r\n";
                    write(fd, req, strlen(req));
                    usleep(80000);
                    total = (int)read(fd, banner_buf, MAX_BANNER - 1);
                    if (total < 0) total = 0;
                }
                banner_buf[total] = 0;
                pthread_mutex_lock(&ctx->lock);
                if (ctx->result_count < MAX_PORTS) {
                    ScanResult* r = &ctx->results[ctx->result_count++];
                    r->port = port;
                    r->state = 1;
                    ctx->open_count++;
                    int out = 0;
                    for (int si = 0; si < total && out < MAX_BANNER - 1; si++) {
                        char c = banner_buf[si];
                        if (c == '\r') continue;
                        if (c == '\n') { banner_buf[out++] = ' '; continue; }
                        if (c >= 32 && c < 127) banner_buf[out++] = c;
                    }
                    banner_buf[out] = 0;
                    strncpy(r->banner, banner_buf, sizeof(r->banner) - 1);
                }
                pthread_mutex_unlock(&ctx->lock);
                printf("RESULT:{\"port\":%d,\"state\":1,\"open\":true,\"banner\":\"%s\"}\n", port, banner_buf);
                fflush(stdout);
            }
            epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, fd, NULL);
            close(fd);
        }
    }
    return NULL;
}

static void* worker_connect(void* arg) {
    MassContext* ctx = (MassContext*)arg;
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) return NULL;
    struct epoll_event ev;
    ev.data.fd = pipe_fds[0];
    ev.events = EPOLLIN;
    epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, pipe_fds[0], &ev);
    while (1) {
        pthread_mutex_lock(&ctx->lock);
        int start = ctx->result_count;
        if (start >= ctx->port_count) {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }
        int batch = ctx->batch_size;
        if (start + batch > ctx->port_count) batch = ctx->port_count - start;
        pthread_mutex_unlock(&ctx->lock);
        if (batch <= 0) break;
        for (int i = 0; i < batch; i++) {
            int idx = start + i;
            if (idx >= ctx->port_count) break;
            int fd = prepare_connect(ctx->epfd, ctx->ip, ctx->ports[idx], ctx->timeout_ms);
            if (fd < 0) continue;
        }
        usleep(ctx->timeout_ms * 1000 + 100000);
    }
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return NULL;
}

static void run_mass_scan(MassContext* ctx) {
    ctx->epfd = epoll_create1(0);
    if (ctx->epfd < 0) { perror("epoll_create"); return; }
    pthread_t workers[MAX_WORKERS + 1];
    int n_workers = ctx->workers;
    if (n_workers > MAX_WORKERS) n_workers = MAX_WORKERS;
    pthread_create(&workers[0], NULL, worker_connect, ctx);
    for (int i = 0; i < n_workers; i++)
        pthread_create(&workers[1 + i], NULL, worker_poll, ctx);
    pthread_join(workers[0], NULL);
    for (int i = 0; i < n_workers; i++)
        pthread_join(workers[1 + i], NULL);
    close(ctx->epfd);
}

typedef struct { int port; const char* name; } SvcEntry;

static const SvcEntry SVC_DB[] = {
    {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},{80,"HTTP"},{110,"POP3"},{111,"RPC"},{135,"MSRPC"},{139,"NetBIOS"},{143,"IMAP"},{161,"SNMP"},{179,"BGP"},{389,"LDAP"},{443,"HTTPS"},{445,"SMB"},{465,"SMTPS"},{587,"SMTP-MSA"},{636,"LDAPS"},{873,"RSYNC"},{993,"IMAPS"},{995,"POP3S"},{1080,"SOCKS"},{1194,"OpenVPN"},{1433,"MSSQL"},{1521,"Oracle"},{1723,"PPTP"},{2049,"NFS"},{2375,"Docker"},{2376,"Docker-TLS"},{2379,"etcd"},{3128,"Squid"},{3306,"MySQL"},{3389,"RDP"},{3690,"SVN"},{4369,"EPMD"},{5432,"PostgreSQL"},{5672,"AMQP"},{5900,"VNC"},{5984,"CouchDB"},{5985,"WinRM"},{6379,"Redis"},{6443,"K8s-API"},{8080,"HTTP-Proxy"},{8443,"HTTPS-Alt"},{8500,"Consul"},{9090,"Prometheus"},{9092,"Kafka"},{9200,"Elasticsearch"},{10250,"Kubelet"},{11211,"Memcached"},{27017,"MongoDB"},{32400,"Plex"},{0,NULL}
};

static const char* get_service(int port) {
    for (int i = 0; SVC_DB[i].name; i++)
        if (SVC_DB[i].port == port) return SVC_DB[i].name;
    return "unknown";
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <ports> [timeout_ms] [workers] [batch_size]\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.1 1-65535 1000 16 1024\n", argv[0]);
        return 1;
    }
    MassContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.hostname = argv[1];
    ctx.ip = resolve_ip(ctx.hostname);
    if (ctx.ip == 0) { fprintf(stderr, "Failed to resolve\n"); return 1; }
    int ports[MAX_PORTS];
    int port_count = parse_ports(argv[2], ports, MAX_PORTS);
    if (port_count <= 0) { fprintf(stderr, "No valid ports\n"); return 1; }
    ctx.ports = ports;
    ctx.port_count = port_count;
    ctx.timeout_ms = argc > 3 ? atoi(argv[3]) : TIMEOUT_MS;
    ctx.workers = argc > 4 ? atoi(argv[4]) : 8;
    ctx.batch_size = argc > 5 ? atoi(argv[5]) : BATCH_SIZE;
    if (ctx.workers < 1) ctx.workers = 1;
    if (ctx.workers > MAX_WORKERS) ctx.workers = MAX_WORKERS;
    if (ctx.batch_size < 64) ctx.batch_size = 64;
    pthread_mutex_init(&ctx.lock, NULL);
    struct in_addr ia; ia.s_addr = ctx.ip;
    fprintf(stderr, "MASS_SCANNER target=%s ip=%s ports=%d timeout=%dms workers=%d batch=%d\n",
        ctx.hostname, inet_ntoa(ia), port_count, ctx.timeout_ms, ctx.workers, ctx.batch_size);
    ctx.start_time = now_ms();
    run_mass_scan(&ctx);
    long long elapsed = now_ms() - ctx.start_time;
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"open\":%d,\"elapsed_ms\":%lld}\n",
        ctx.hostname, port_count, ctx.open_count, elapsed);
    return 0;
}
