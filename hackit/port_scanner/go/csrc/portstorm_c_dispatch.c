#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int advanced_scanner_main(int argc, char **argv);
extern int banner_grabber_main(int argc, char **argv);
extern int c_evasion_main(int argc, char **argv);
extern int credential_harvester_main(int argc, char **argv);
extern int cve_matcher_main(int argc, char **argv);
extern int database_scanner_main(int argc, char **argv);
extern int deep_packet_analysis_main(int argc, char **argv);
extern int dns_burst_resolver_main(int argc, char **argv);
extern int epoll_scanner_main(int argc, char **argv);
extern int full_system_scanner_main(int argc, char **argv);
extern int icmp_discovery_main(int argc, char **argv);
extern int iot_scanner_main(int argc, char **argv);
extern int mass_port_scanner_main(int argc, char **argv);
extern int mass_tcp_scanner_main(int argc, char **argv);
extern int network_discovery_main(int argc, char **argv);
extern int network_oracle_main(int argc, char **argv);
extern int network_path_main(int argc, char **argv);
extern int network_topology_main(int argc, char **argv);
extern int os_fingerprint_main(int argc, char **argv);
extern int os_fingerprint_v2_main(int argc, char **argv);
extern int packet_crafter_main(int argc, char **argv);
extern int packet_inspector_main(int argc, char **argv);
extern int performance_bench_main(int argc, char **argv);
extern int scanner_main(int argc, char *argv[]);
extern int service_exploiter_main(int argc, char **argv);
extern int service_fingerprinter_main(int argc, char **argv);
extern int service_prober_main(int argc, char **argv);
extern int ssl_deep_scan_main(int argc, char **argv);
extern int stealth_evasion_main(int argc, char *argv[]);
extern int syn_flood_optimized_main(int argc, char **argv);
extern int syn_scanner_main(int argc, char **argv);
extern int syn_scanner_v2_main(int argc, char **argv);
extern int tcp_prober_main(int argc, char **argv);
extern int tls_prober_main(int argc, char **argv);
extern int udp_prober_main(int argc, char **argv);
extern int udp_scanner_main(int argc, char **argv);
extern int web_app_fingerprint_main(int argc, char **argv);

typedef int (*scanner_fn)(int, char **);

typedef struct {
    const char *name;
    scanner_fn fn;
} ScannerEntry;

static const ScannerEntry SCANNERS[] = {
    {"advanced_scanner",    advanced_scanner_main},
    {"banner_grabber",      banner_grabber_main},
    {"c_evasion",           c_evasion_main},
    {"credential_harvester", credential_harvester_main},
    {"cve_matcher",         cve_matcher_main},
    {"database_scanner",    database_scanner_main},
    {"deep_packet_analysis", deep_packet_analysis_main},
    {"dns_burst_resolver",  dns_burst_resolver_main},
    {"epoll_scanner",       epoll_scanner_main},
    {"full_system_scanner", full_system_scanner_main},
    {"icmp_discovery",      icmp_discovery_main},
    {"iot_scanner",         iot_scanner_main},
    {"mass_port_scanner",   mass_port_scanner_main},
    {"mass_tcp_scanner",    mass_tcp_scanner_main},
    {"network_discovery",   network_discovery_main},
    {"network_oracle",      network_oracle_main},
    {"network_path",        network_path_main},
    {"network_topology",    network_topology_main},
    {"os_fingerprint",      os_fingerprint_main},
    {"os_fingerprint_v2",   os_fingerprint_v2_main},
    {"packet_crafter",      packet_crafter_main},
    {"packet_inspector",    packet_inspector_main},
    {"performance_bench",   performance_bench_main},
    {"scanner",             scanner_main},
    {"service_exploiter",   service_exploiter_main},
    {"service_fingerprinter", service_fingerprinter_main},
    {"service_prober",      service_prober_main},
    {"ssl_deep_scan",       ssl_deep_scan_main},
    {"stealth_evasion",     stealth_evasion_main},
    {"syn_flood_optimized", syn_flood_optimized_main},
    {"syn_scanner",         syn_scanner_main},
    {"syn_scanner_v2",      syn_scanner_v2_main},
    {"tcp_prober",          tcp_prober_main},
    {"tls_prober",          tls_prober_main},
    {"udp_prober",          udp_prober_main},
    {"udp_scanner",         udp_scanner_main},
    {"web_app_fingerprint", web_app_fingerprint_main},
    {NULL, NULL}
};

__attribute__((visibility("default")))
int portstorm_c_dispatch(const char *scanner_name, int argc, char **argv) {
    if (!scanner_name) return -1;
    for (const ScannerEntry *e = SCANNERS; e->name; e++) {
        if (strcmp(e->name, scanner_name) == 0) {
            return e->fn(argc, argv);
        }
    }
    fprintf(stderr, "Unknown scanner: %s\n", scanner_name);
    return -1;
}

__attribute__((visibility("default")))
const char **portstorm_c_list_scanners(void) {
    static const char *names[40];
    int i = 0;
    for (const ScannerEntry *e = SCANNERS; e->name; e++) {
        names[i++] = e->name;
    }
    names[i] = NULL;
    return names;
}

__attribute__((visibility("default")))
int portstorm_c_scanner_count(void) {
    int count = 0;
    for (const ScannerEntry *e = SCANNERS; e->name; e++) count++;
    return count;
}
