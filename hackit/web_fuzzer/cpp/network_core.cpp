#include "network_core.hpp"
#include <iostream>

NetworkCore::NetworkCore() {
    init_ws();
}

NetworkCore::~NetworkCore() {
    cleanup_ws();
}

void NetworkCore::init_ws() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

void NetworkCore::cleanup_ws() {
    WSACleanup();
}

std::string NetworkCore::send_request(const std::string& url_in, long& status_code) {
    status_code = 0;
    std::string url = url_in;
    if (url.find("://") == std::string::npos) {
        url = "http://" + url;
    }

    size_t host_start = url.find("//") + 2;
    size_t host_end = url.find("/", host_start);
    std::string host, path;
    if (host_end == std::string::npos) {
        host = url.substr(host_start);
        path = "/";
    } else {
        host = url.substr(host_start, host_end - host_start);
        path = url.substr(host_end);
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";

    struct hostent* he = gethostbyname(host.c_str());
    if (!he) { closesocket(s); return ""; }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr = *((struct in_addr*)he->h_addr);
    addr.sin_port = htons(80);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket(s);
        return "";
    }

    const char* user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.45",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    };
    const char* ua = user_agents[rand() % 4];

    std::string request = "GET " + path + " HTTP/1.1\r\n" +
                         "Host: " + host + "\r\n" +
                         "User-Agent: " + ua + "\r\n" +
                         "Connection: close\r\n\r\n";
    send(s, request.c_str(), (int)request.length(), 0);

    char buffer[4096];
    std::string response;
    int bytes;
    while ((bytes = recv(s, buffer, sizeof(buffer), 0)) > 0) {
        response.append(buffer, bytes);
    }

    size_t pos = response.find(" ");
    if (pos != std::string::npos && response.length() > pos + 4) {
        try {
            status_code = std::stol(response.substr(pos + 1, 3));
        } catch (...) { status_code = 0; }
    }

    closesocket(s);
    return response;
}
