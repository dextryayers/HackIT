#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <math.h>

#include "optimize.h"

#define MAX_SAMPLES 1000
#define MAX_CONCURRENT 64
#define PACKET_SIZES {64, 256, 1024, 4096, 8192, 16384, 32768, 65536}
#define TIMEOUT_MS 10000

typedef struct {
    double start_time;
    double end_time;
    int success;
    size_t bytes_sent;
    size_t bytes_recv;
    int packet_size;
} BenchSample;

typedef struct {
    char target[256];
    int port;
    BenchSample samples[MAX_SAMPLES];
    int sample_count;
    double latencies[MAX_SAMPLES];
    int latency_count;
    double bandwidth_bytes;
    double total_time;
    pthread_mutex_t lock;
    volatile int running;
} BenchContext;

static BenchContext ctx;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static int connect_with_timeout(const char *ip, int port, int timeout_ms, double *conn_time) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    double t1 = now_ms();
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    struct epoll_event ev, events[1];
    int epfd = epoll_create1(0);
    ev.events = EPOLLOUT | EPOLLERR;
    ev.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    int nfds = epoll_wait(epfd, events, 1, timeout_ms);
    double t2 = now_ms();
    int ok = 0;
    if (nfds > 0 && (events[0].events & EPOLLOUT)) {
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err == 0) ok = 1;
    }
    close(epfd);
    if (ok) *conn_time = t2 - t1;
    close(fd);
    return ok ? 0 : -1;
}

static int measure_latency(const char *ip, int port, int pkt_size, double *latency) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    char *send_buf = malloc(pkt_size);
    if (!send_buf) { close(fd); return -1; }
    memset(send_buf, 'A', pkt_size);
    double t1 = now_ms();
    int sent = send(fd, send_buf, pkt_size, 0);
    char recv_buf[4096];
    int total_recv = 0;
    while (total_recv < sent && (now_ms() - t1) < 5000) {
        int n = recv(fd, recv_buf, sizeof(recv_buf), 0);
        if (n <= 0) break;
        total_recv += n;
    }
    double t2 = now_ms();
    free(send_buf);
    close(fd);
    if (sent > 0) {
        *latency = t2 - t1;
        return 1;
    }
    return 0;
}

static int measure_bandwidth(const char *ip, int port, int duration_ms, double *bw_bps, double *total_bytes) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    struct timeval tv = {duration_ms / 1000 + 1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    char buf[32768];
    memset(buf, 'B', sizeof(buf));
    double t1 = now_ms();
    unsigned long total = 0;
    while ((now_ms() - t1) < duration_ms) {
        int n = send(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        total += n;
    }
    double t2 = now_ms();
    double elapsed = (t2 - t1) / 1000.0;
    if (elapsed > 0) {
        *bw_bps = (total * 8.0) / elapsed;
        *total_bytes = total;
    }
    close(fd);
    return 0;
}

static void *latency_test_thread(void *arg) {
    (void)arg;
    int sizes[] = PACKET_SIZES;
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    for (int s = 0; s < num_sizes; s++) {
        for (int i = 0; i < 10; ++i) {
            double lat = 0;
            if (measure_latency(ctx.target, ctx.port, sizes[s], &lat) > 0) {
                pthread_mutex_lock(&ctx.lock);
                if (ctx.latency_count < MAX_SAMPLES) {
                    ctx.latencies[ctx.latency_count++] = lat;
                }
                pthread_mutex_unlock(&ctx.lock);
                printf("RESULT:{\"type\":\"latency\",\"packet_size\":%d,\"latency_ms\":%.3f}\n",
                       sizes[s], lat);
            }
            usleep(50000);
        }
    }
    return NULL;
}

static void *bandwidth_thread(void *arg) {
    (void)arg;
    double bw_bps = 0, total_bytes = 0;
    if (measure_bandwidth(ctx.target, ctx.port, 5000, &bw_bps, &total_bytes) == 0) {
        printf("RESULT:{\"type\":\"bandwidth\",\"bps\":%.0f,\"mbps\":%.2f,\"bytes\":%.0f}\n",
               bw_bps, bw_bps / 1000000.0, total_bytes);
        pthread_mutex_lock(&ctx.lock);
        ctx.bandwidth_bytes = total_bytes;
        ctx.total_time = 5.0;
        pthread_mutex_unlock(&ctx.lock);
    }
    return NULL;
}

static void *conn_test_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 50; ++i) {
        double conn_time = 0;
        if (connect_with_timeout(ctx.target, ctx.port, TIMEOUT_MS, &conn_time) == 0) {
            pthread_mutex_lock(&ctx.lock);
            if (ctx.sample_count < MAX_SAMPLES) {
                ctx.samples[ctx.sample_count].start_time = now_ms();
                ctx.samples[ctx.sample_count].end_time = ctx.samples[ctx.sample_count].start_time + conn_time;
                ctx.samples[ctx.sample_count].success = 1;
                ctx.sample_count++;
            }
            pthread_mutex_unlock(&ctx.lock);
            printf("RESULT:{\"type\":\"connection\",\"attempt\":%d,\"time_ms\":%.3f}\n", i, conn_time);
        }
        usleep(10000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    memset(&ctx, 0, sizeof(ctx));
    ctx.running = 1;
    pthread_mutex_init(&ctx.lock, NULL);
    char *target = NULL;
    ctx.port = 80;
    int opt;
    while ((opt = getopt(argc, argv, "t:p:")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'p': ctx.port = atoi(optarg); break;
        }
    }
    if (!target) { fprintf(stderr, "Usage: %s -t target [-p port]\n", argv[0]); return 1; }
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
    pthread_t conn_thr, lat_thr, bw_thr;
    pthread_create(&conn_thr, NULL, conn_test_thread, NULL);
    pthread_create(&lat_thr, NULL, latency_test_thread, NULL);
    pthread_create(&bw_thr, NULL, bandwidth_thread, NULL);
    pthread_join(conn_thr, NULL);
    pthread_join(lat_thr, NULL);
    pthread_join(bw_thr, NULL);
    double min_lat = 999999, max_lat = 0, sum_lat = 0;
    double jitter_sum = 0;
    int lat_samples = 0;
    pthread_mutex_lock(&ctx.lock);
    for (int i = 0; i < ctx.latency_count; ++i) {
        if (ctx.latencies[i] < min_lat) min_lat = ctx.latencies[i];
        if (ctx.latencies[i] > max_lat) max_lat = ctx.latencies[i];
        sum_lat += ctx.latencies[i];
        lat_samples++;
    }
    double avg_lat = lat_samples > 0 ? sum_lat / lat_samples : 0;
    for (int i = 1; i < ctx.latency_count; i++)
        jitter_sum += fabs(ctx.latencies[i] - ctx.latencies[i - 1]);
    double jitter = ctx.latency_count > 1 ? jitter_sum / (ctx.latency_count - 1) : 0;
    double conn_avg = 0;
    int conn_samples = 0;
    for (int i = 0; i < ctx.sample_count; ++i) {
        if (ctx.samples[i].success) {
            conn_avg += (ctx.samples[i].end_time - ctx.samples[i].start_time);
            conn_samples++;
        }
    }
    if (conn_samples > 0) conn_avg /= conn_samples;
    pthread_mutex_unlock(&ctx.lock);
    printf("RESULT:{\"type\":\"summary\",\"latency_ms\":{\"min\":%.3f,\"max\":%.3f,\"avg\":%.3f,\"samples\":%d},"
           "\"jitter_ms\":%.3f,\"connection_time_avg_ms\":%.3f,\"connection_samples\":%d}\n",
           min_lat, max_lat, avg_lat, lat_samples, jitter, conn_avg, conn_samples);
    printf("FINAL:{\"target\":\"%s\",\"port\":%d,\"latency_min_ms\":%.3f,\"latency_max_ms\":%.3f,"
           "\"latency_avg_ms\":%.3f,\"jitter_ms\":%.3f,\"estimated_bandwidth_mbps\":%.2f}\n",
           ctx.target, ctx.port, min_lat, max_lat, avg_lat, jitter,
           ctx.bandwidth_bytes > 0 ? (ctx.bandwidth_bytes * 8.0 / ctx.total_time / 1000000.0) : 0);
    pthread_mutex_destroy(&ctx.lock);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
