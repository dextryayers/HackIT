#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <regex>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

/**
 * C++ Expert Service & Version Discovery Engine
 * Designed for high-accuracy banner grabbing and protocol analysis
 */

class ServiceScanner {
public:
    static string analyze_banner(int port, const string& banner) {
        if (banner.empty()) return "unknown";

        // Advanced Regex-based Version Extraction
        if (port == 80 || port == 443 || port == 8080) {
            regex http_regex("Server: ([^\\r\\n]+)");
            smatch match;
            if (regex_search(banner, match, http_regex)) return match[1];
        } else if (port == 22) {
            regex ssh_regex("SSH-([^-]+)-([^\\s\\r\\n]+)");
            smatch match;
            if (regex_search(banner, match, ssh_regex)) return "SSH " + match[1].str() + " (" + match[2].str() + ")";
        } else if (port == 21) {
            if (banner.find("vsFTPd") != string::npos) return "vsFTPd";
            if (banner.find("ProFTPD") != string::npos) return "ProFTPD";
        } else if (port == 3306) {
            if (banner.length() > 5) return "MySQL " + banner.substr(5, 10);
        } else if (port == 445) {
            return "Microsoft-DS (SMB)";
        } else if (port == 3389) {
            return "RDP (Remote Desktop)";
        } else if (port == 23) {
            if (banner.find("\xff\xfd") != string::npos) return "Telnet (Negotiation)";
            return "Telnet";
        } else if (port == 5900) {
            if (banner.find("RFB") != string::npos) return "VNC (" + banner.substr(0, 11) + ")";
            return "VNC";
        } else if (port == 5432) {
            return "PostgreSQL";
        } else if (port == 1433) {
            return "MSSQL Server";
        } else if (port == 1521) {
            return "Oracle DB";
        } else if (port == 161) {
            return "SNMP Service";
        } else if (port == 6379) {
            if (banner.find("redis_version") != string::npos) {
                regex redis_regex("redis_version:([0-9.]+)");
                smatch match;
                if (regex_search(banner, match, redis_regex)) return "Redis " + match[1].str();
            }
            return "Redis";
        } else if (port == 27017) {
            return "MongoDB";
        } else if (port == 25 || port == 587) {
            if (banner.find("Postfix") != string::npos) return "Postfix SMTP";
            if (banner.find("Exim") != string::npos) return "Exim SMTP";
            return "SMTP";
        } else if (port == 110) {
            return "POP3";
        } else if (port == 143) {
            return "IMAP";
        }
        
        return banner.substr(0, 50); // Fallback to first 50 chars of banner
    }

    static string grab_deep_banner(const char* host, int port, int timeout_ms) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return "";

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host, &addr.sin_addr);

        // Set timeout
        DWORD timeout = timeout_ms;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(s);
            return "";
        }

        // For some protocols, we need to send a probe first (like Nmap)
        if (port == 80 || port == 8080) {
            string probe = "HEAD / HTTP/1.0\r\n\r\n";
            send(s, probe.c_str(), probe.length(), 0);
        } else if (port == 3306) {
            // MySQL probe is usually not needed as it sends a handshake, 
            // but we can send a small packet if needed.
        } else if (port == 445) {
            // SMB Negotiate Protocol Request
            unsigned char smb_probe[] = {
                0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x02,
                0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
            };
            send(s, (const char*)smb_probe, sizeof(smb_probe), 0);
        } else if (port == 3389) {
            // RDP Connection Request
            unsigned char rdp_probe[] = {
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
                0x00, 0x00, 0x00
            };
            send(s, (const char*)rdp_probe, sizeof(rdp_probe), 0);
        } else if (port == 23) {
            // Telnet options negotiation
            unsigned char telnet_probe[] = { 0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03 };
            send(s, (const char*)telnet_probe, sizeof(telnet_probe), 0);
        } else if (port == 5900) {
            // VNC Security Handshake request (Passive, but we can send version)
            string vnc_probe = "RFB 003.008\n";
            send(s, vnc_probe.c_str(), vnc_probe.length(), 0);
        } else if (port == 5432) {
            // PostgreSQL Startup Message
            unsigned char pg_probe[] = { 0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f };
            send(s, (const char*)pg_probe, sizeof(pg_probe), 0);
        } else if (port == 6379) {
            // Redis INFO command
            string redis_probe = "INFO\r\n";
            send(s, redis_probe.c_str(), redis_probe.length(), 0);
        } else if (port == 27017) {
            // MongoDB is-master probe
            unsigned char mongo_probe[] = { 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13, 0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
            send(s, (const char*)mongo_probe, sizeof(mongo_probe), 0);
        } else if (port == 25 || port == 587) {
            string smtp_probe = "HELO hackit.local\r\n";
            send(s, smtp_probe.c_str(), smtp_probe.length(), 0);
        } else if (port == 110) {
            string pop3_probe = "CAPA\r\n";
            send(s, pop3_probe.c_str(), pop3_probe.length(), 0);
        } else if (port == 143) {
            string imap_probe = "A001 CAPABILITY\r\n";
            send(s, imap_probe.c_str(), imap_probe.length(), 0);
        }

        char buffer[2048] = {0};
        int bytes = recv(s, buffer, sizeof(buffer) - 1, 0);
        closesocket(s);

        if (bytes > 0) return string(buffer, bytes);
        return "";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: service_scanner.exe <host> <port> [timeout]" << endl;
        return 1;
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    const char* host = argv[1];
    int port = stoi(argv[2]);
    int timeout = (argc > 3) ? stoi(argv[3]) : 1000;

    string banner = ServiceScanner::grab_deep_banner(host, port, timeout);
    string version = ServiceScanner::analyze_banner(port, banner);

    // Clean banner for JSON
    for (auto &c : banner) if (c == '\n' || c == '\r' || c == '\"') c = ' ';

    cout << "{\"port\": " << port 
         << ", \"banner\": \"" << banner 
         << "\", \"version\": \"" << version << "\"}" << endl;

    WSACleanup();
    return 0;
}
