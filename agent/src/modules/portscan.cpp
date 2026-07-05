// portscan module (B6).
//
// arguments[0] = host (e.g. "192.168.1.1")
// arguments[1] = ports: comma-separated, ranges allowed (e.g. "22,80,8000-8100")
// arguments[2] = optional timeout_ms (default 200)

#include "../json.hpp"
#include "../protocol.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
#define NAT_INVALID_SOCKET INVALID_SOCKET
#define NAT_SOCKET_ERROR SOCKET_ERROR
#define NAT_CLOSE_SOCKET closesocket
#define NAT_GETERR WSAGetLastError
#define NAT_EINPROGRESS WSAEWOULDBLOCK
using socklen_t_native = int;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <cerrno>
using socket_t = int;
#define NAT_INVALID_SOCKET (-1)
#define NAT_SOCKET_ERROR (-1)
#define NAT_CLOSE_SOCKET ::close
#define NAT_GETERR() (errno)
#define NAT_EINPROGRESS EINPROGRESS
using socklen_t_native = socklen_t;
#endif

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

std::vector<int> parse_ports(const std::string& s) {
    std::vector<int> out;
    size_t i = 0;
    while (i < s.size()) {
        size_t j = i;
        while (j < s.size() && s[j] != ',') ++j;
        std::string tok = s.substr(i, j - i);
        size_t dash = tok.find('-');
        if (dash != std::string::npos) {
            int a = std::atoi(tok.substr(0, dash).c_str());
            int b = std::atoi(tok.substr(dash + 1).c_str());
            for (int p = a; p <= b && p < 65536; ++p) out.push_back(p);
        } else {
            int p = std::atoi(tok.c_str());
            if (p > 0 && p < 65536) out.push_back(p);
        }
        i = j + 1;
    }
    return out;
}

// RAII wrapper so a single WSAStartup is performed for the module's lifetime.
#ifdef _WIN32
struct WsaInit {
    WsaInit() {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    }
    ~WsaInit() { WSACleanup(); }
};
WsaInit g_wsa;
#endif

bool try_connect(const std::string& host, int port, int timeout_ms) {
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) return false;
    bool open = false;
    for (auto* r = res; r; r = r->ai_next) {
        socket_t fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd == NAT_INVALID_SOCKET) continue;
        // Non-blocking connect
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(fd, FIONBIO, &mode);
#else
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
        int rc = connect(fd, r->ai_addr, (socklen_t)r->ai_addrlen);
        if (rc == 0) {
            open = true;
            NAT_CLOSE_SOCKET(fd);
            break;
        }
        if (NAT_GETERR() != NAT_EINPROGRESS) {
            NAT_CLOSE_SOCKET(fd);
            continue;
        }
        // Poll-based wait for the connection to complete (or time out).
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        rc = select(fd + 1, nullptr, &wset, nullptr, &tv);
        if (rc > 0) {
            int err = 0;
            socklen_t_native len = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
            if (err == 0) open = true;
        }
        NAT_CLOSE_SOCKET(fd);
        if (open) break;
    }
    if (res) freeaddrinfo(res);
    return open;
}

} // namespace

namespace nagomio_modules {

std::string handle_portscan(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return std::string(R"({"error":"host and ports required"})");
    }
    std::string host = args[0];
    std::vector<int> ports = parse_ports(args[1]);
    int timeout = args.size() > 2 ? std::atoi(args[2].c_str()) : 200;
    if (timeout <= 0) timeout = 200;
    nlohmann::json arr = nlohmann::json::array();
    for (int p : ports) {
        nlohmann::json entry = {{"port", p}};
        bool open = try_connect(host, p, timeout);
        entry["state"] = open ? "open" : "closed";
        arr.push_back(entry);
    }
    nlohmann::json j = {
        {"host", host},
        {"results", arr},
    };
    return j.dump();
}

} // namespace nagomio_modules