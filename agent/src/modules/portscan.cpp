// portscan module (B6).
//
// arguments[0] = host (e.g. "192.168.1.1")
// arguments[1] = ports: comma-separated, ranges allowed (e.g. "22,80,8000-8100")
// arguments[2] = optional timeout_ms (default 200)

#include "../json.hpp"
#include "../protocol.h"

#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

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
        int fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        // Non-blocking connect
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, r->ai_addr, r->ai_addrlen);
        if (rc == 0) {
            open = true;
            close(fd);
            break;
        }
        if (errno != EINPROGRESS) {
            close(fd);
            continue;
        }
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) open = true;
        }
        close(fd);
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