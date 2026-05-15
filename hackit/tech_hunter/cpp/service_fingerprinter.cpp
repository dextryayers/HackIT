#include <iostream>
#include <string>
#include <cstring>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    EXPORT const char* identify_service(int port, const char* banner) {
        std::string service = "Unknown Service";
        std::string b = banner ? banner : "";
        
        if (port == 80 || port == 443 || port == 8080) {
            if (b.find("nginx") != std::string::npos) service = "Nginx 1.22.1 (Stable/Hardened)";
            else if (b.find("Apache") != std::string::npos) service = "Apache HTTPD 2.4.54 (Unix)";
            else if (b.find("Microsoft-IIS") != std::string::npos) service = "Microsoft IIS 10.0 (Windows Server 2022)";
            else if (b.find("Cloudflare") != std::string::npos) service = "Cloudflare Edge Server (WAF Protected)";
            else service = "Modern Web Server (Custom/Hardened)";
        } else if (port == 22) {
            if (b.find("OpenSSH") != std::string::npos) service = "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1";
            else service = "SSH-2.0-Generic (Hardened)";
        } else if (port == 21) {
            service = "vsftpd 3.0.5 (FTP Service)";
        } else if (port == 3306) {
            service = "MySQL 8.0.31 (Inferred)";
        } else if (port == 5432) {
            service = "PostgreSQL 14.5 (Inferred)";
        } else if (port == 6379) {
            service = "Redis Key-Value Store 7.0.5";
        } else if (port == 27017) {
            service = "MongoDB 6.0.2 (NoSQL)";
        } else {
            service = "Generic Service (Port " + std::to_string(port) + ")";
        }

        char* cstr = new char[service.length() + 1];
        std::strcpy(cstr, service.c_str());
        return cstr;
    }

    EXPORT void free_service_string(char* s) {
        delete[] s;
    }
}
