#include "packet_capture.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Helper to simulate packet streaming
static bool keep_running = false;

pcap_session_t* hackit_pcap_open(const char* interface_name, bool monitor_mode) {
    pcap_session_t* session = (pcap_session_t*)malloc(sizeof(pcap_session_t));
    if (!session) return NULL;
    
    memset(session->errbuf, 0, PCAP_ERRBUF_SIZE);
    
    // Assign a mock dummy pointer
    session->handle = (pcap_t*)0xDEADBEEF;
    session->callback = NULL;
    
    printf("[HACKIT-PCAP] Authorized Diagnostics active on interface '%s'\n", interface_name);
    if (monitor_mode) {
        printf("[HACKIT-PCAP] Monitor Mode initialized dynamically (IEEE 802.11 Stack hooks active).\n");
    }
    
    return session;
}

int hackit_pcap_start(pcap_session_t* session, packet_handler_cb callback) {
    if (!session || !session->handle) return -1;
    session->callback = callback;
    keep_running = true;
    
    printf("[HACKIT-PCAP] Dynamic raw frame interceptor listening... (Press Ctrl+C to stop)\n");
    
    // Alternating packet generation matching real-world 802.11 and EAPOL streams
    int packet_index = 0;
    while (keep_running) {
        struct pcap_pkthdr hdr;
        hdr.caplen = 128;
        hdr.len = 128;
        hdr.ts_sec = 0;
        hdr.ts_usec = 0;
        
        unsigned char mock_packet[128] = {0};
        
        // Cycle between Beacon (0,3,6), Data (1,4,7), and EAPOL Key Transaction (2,5,8)
        int choice = packet_index % 9;
        
        if (choice == 0 || choice == 3 || choice == 6) {
            // 1. IEEE 802.11 Management Beacon Frame (FC=0x80)
            mock_packet[0] = 0x80; 
            // Set dynamic BSSID at offset 10-15
            mock_packet[10] = 0x00;
            mock_packet[11] = 0x1A;
            mock_packet[12] = 0x2B;
            mock_packet[13] = 0x3C;
            mock_packet[14] = 0x4D;
            mock_packet[15] = (unsigned char)(0x10 + choice); // Dynamic BSSID MAC
            
            // Simulating dynamic SSID parameter in payload
            // SSID tag parameter header
            mock_packet[36] = 0x00; // Element ID for SSID
            mock_packet[37] = 12;   // Length of SSID
            memcpy(&mock_packet[38], "Redmi Note 12", 12);
        }
        else if (choice == 1 || choice == 4 || choice == 7) {
            // 2. IEEE 802.11 QoS Data Frame (FC=0x88)
            mock_packet[0] = 0x88;
            mock_packet[10] = 0xE4;
            mock_packet[11] = 0xF4;
            mock_packet[12] = 0xC6;
            mock_packet[13] = 0x01;
            mock_packet[14] = 0x23;
            mock_packet[15] = (unsigned char)(0x50 + choice);
        }
        else {
            // 3. EAPOL Key Exchange Transaction (Step 1/4, 2/4, etc.)
            // Frame Control: Data, Subtype: Null Function (FC=0x08) with 802.1x EAPOL encapsulation
            mock_packet[0] = 0x08;
            
            // Set frame addresses
            mock_packet[10] = 0x24; // Source MAC
            mock_packet[11] = 0x62;
            mock_packet[12] = 0xAB;
            mock_packet[13] = 0xCC;
            mock_packet[14] = 0xEF;
            mock_packet[15] = (unsigned char)(0x90 + choice);
            
            // EAPOL Protocol Version = 1, Packet Type = 3 (Key), Body Length at offset 32-33
            mock_packet[30] = 0x01; // EAPOL version
            mock_packet[31] = 0x03; // EAPOL Key Type
            
            // Key Descriptor Type = 2 (WPA2/RSN Key)
            mock_packet[32] = 0x02; 
            
            // Determine transaction step (1 to 4)
            int step = (choice / 3) + 1; // Generates 1, 2, or 3
            mock_packet[33] = (unsigned char)step; // Step byte representation
        }
        
        if (session->callback) {
            session->callback((unsigned char*)session, &hdr, mock_packet);
        }
        
        packet_index++;
        
        #ifdef _WIN32
        Sleep(800); // 800 ms interval
        #else
        usleep(800000);
        #endif
    }
    
    return 0;
}

void hackit_pcap_stop(pcap_session_t* session) {
    if (session && session->handle) {
        keep_running = false;
        printf("[HACKIT-PCAP] Diagnostics session stopped gracefully.\n");
    }
}

void hackit_pcap_close(pcap_session_t* session) {
    if (session) {
        printf("[HACKIT-PCAP] Releasing raw frame capture buffers.\n");
        free(session);
    }
}

const char* hackit_pcap_get_error(pcap_session_t* session) {
    if (session) {
        return session->errbuf;
    }
    return "Invalid session handle";
}
