#ifndef NETWORK_CORE_H
#define NETWORK_CORE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

class NetworkCore {
public:
    NetworkCore();
    ~NetworkCore();
    std::string send_request(const std::string& url, long& status_code);
private:
    void init_ws();
    void cleanup_ws();
};

#endif
