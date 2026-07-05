// whoami module (B6).
//
// Returns JSON with username, group memberships, integrity level, and
// elevation status.

#include "../json.hpp"
#include "../protocol.h"

#include <array>
#include <cstdio>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#else
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef _WIN32
namespace {

std::string get_username() {
    char buf[256] = {};
    DWORD size = sizeof(buf);
    if (GetUserNameA(buf, &size)) return std::string(buf);
    return std::string("unknown");
}

std::vector<std::string> get_groups() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD needed = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &needed);
    std::vector<unsigned char> buf(needed);
    if (!GetTokenInformation(token, TokenGroups, buf.data(), needed, &needed)) {
        CloseHandle(token);
        return {};
    }
    auto* groups = reinterpret_cast<TOKEN_GROUPS*>(buf.data());
    std::vector<std::string> out;
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        SID_NAME_USE use = SidTypeUnknown;
        char name[256] = {};
        char domain[256] = {};
        DWORD name_size = sizeof(name);
        DWORD domain_size = sizeof(domain);
        if (LookupAccountSidA(nullptr, groups->Groups[i].Sid,
                              name, &name_size, domain, &domain_size, &use)) {
            out.push_back(std::string(name));
        }
    }
    CloseHandle(token);
    return out;
}

std::string get_integrity() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return "";
    DWORD needed = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &needed);
    std::vector<unsigned char> buf(needed);
    TOKEN_MANDATORY_LABEL* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    if (!GetTokenInformation(token, TokenIntegrityLevel, buf.data(), needed, &needed)) {
        CloseHandle(token);
        return "";
    }
    DWORD rid = *GetSidSubAuthority(label->Label.Sid, 0);
    CloseHandle(token);
    if (rid < SECURITY_MANDATORY_LOW_RID) return "Untrusted";
    if (rid < SECURITY_MANDATORY_MEDIUM_RID) return "Low";
    if (rid < SECURITY_MANDATORY_HIGH_RID) return "Medium";
    if (rid < SECURITY_MANDATORY_SYSTEM_RID) return "High";
    return "System";
}

bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD needed = 0;
    bool out = false;
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &needed)) {
        out = elev.TokenIsElevated != 0;
    }
    CloseHandle(token);
    return out;
}

} // namespace
#else
namespace {

std::string get_username() {
    if (const char* u = getenv("USER")) return u;
    struct passwd* p = getpwuid(getuid());
    return p ? std::string(p->pw_name) : std::string("unknown");
}

std::vector<std::string> get_groups() {
    std::vector<std::string> out;
    gid_t gids[NGROUPS_MAX];
    int n = getgroups(NGROUPS_MAX, gids);
    for (int i = 0; i < n; ++i) {
        struct group* gr = getgrgid(gids[i]);
        if (gr && gr->gr_name) out.push_back(gr->gr_name);
    }
    return out;
}

std::string get_integrity() {
    return geteuid() == 0 ? "root" : "user";
}

bool is_elevated() {
    return geteuid() == 0;
}

} // namespace
#endif

namespace nagomio_modules {

std::string handle_whoami(const std::vector<std::string>&) {
    nlohmann::json j = {
        {"username", get_username()},
        {"groups", get_groups()},
        {"integrity", get_integrity()},
        {"is_elevated", is_elevated()},
    };
    return j.dump();
}

} // namespace nagomio_modules