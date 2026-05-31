#ifndef HACKIT_PACKET_CAPTURE_H
#define HACKIT_PACKET_CAPTURE_H

#include <stdbool.h>
#include <stdint.h>

// MOCK PCAP STRUCTURES FOR WINDOWS NATIVE COMPILATION
#define PCAP_ERRBUF_SIZE 256
#define PCAP_ERROR_BREAK -2

// Opaque stub for pcap_t
typedef void pcap_t;

// Stub for pcap_pkthdr
struct pcap_pkthdr {
    long ts_sec;
    long ts_usec;
    uint32_t caplen;
    uint32_t len;
};

// Packet handler callback matching pcap signature
typedef void (*packet_handler_cb)(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet);

typedef struct {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    packet_handler_cb callback;
} pcap_session_t;

pcap_session_t* hackit_pcap_open(const char* interface_name, bool monitor_mode);
int hackit_pcap_start(pcap_session_t* session, packet_handler_cb callback);
void hackit_pcap_stop(pcap_session_t* session);
void hackit_pcap_close(pcap_session_t* session);
const char* hackit_pcap_get_error(pcap_session_t* session);

#endif // HACKIT_PACKET_CAPTURE_H
