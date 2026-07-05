// uninstall module (B6).
//
// arguments[0] = "now" or "reboot"
// For "now":  spawn a child process to delete the binary and exit; the child
//             waits until the parent is gone then calls unlink / MoveFileEx
//             with MOVEFILE_DELAY_UNTIL_REBOOT.
// For "reboot": just schedule the file for deletion on next boot.

#include "../json.hpp"
#include "../protocol.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#endif

namespace {

std::string get_self_path() {
#ifdef _WIN32
    char buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(nullptr, buf, sizeof(buf));
    return n ? std::string(buf, n) : std::string();
#else
    char buf[4096] = {};
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) buf[n] = '\0';
    return n > 0 ? std::string(buf) : std::string();
#endif
}

} // namespace

#ifdef _WIN32

namespace nagomio_modules {

std::string handle_uninstall(const std::vector<std::string>& args) {
    std::string mode = args.empty() ? "now" : args[0];
    std::string self = get_self_path();
    if (mode == "reboot") {
        if (!MoveFileExA(self.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            return std::string(R"({"error":"MoveFileEx failed"})");
        }
        return R"({"status":"scheduled_reboot_delete"})";
    }
    // "now": launch a detached process that waits for the parent to die then
    // deletes the binary.
    std::string cmd = "cmd.exe /C timeout /T 1 /NOBREAK >NUL & del /F /Q \"" + self + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return std::string(R"({"error":"CreateProcessA failed"})");
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    nlohmann::json j = {{"status", "scheduled"}, {"path", self}};
    return j.dump();
}

} // namespace nagomio_modules

#else

namespace nagomio_modules {

std::string handle_uninstall(const std::vector<std::string>& args) {
    std::string mode = args.empty() ? "now" : args[0];
    std::string self = get_self_path();
    if (mode == "reboot") {
        // POSIX: no equivalent of MoveFileEx. The best we can do is delete
        // the binary now via a detached process.
        mode = "now";
    }
    if (mode == "now") {
        // Spawn a detached shell that waits for the parent to die then
        // unlinks the binary. The child re-execs `sh -c "sleep 1; rm -f ..."`.
        std::string cmd = "nohup sh -c 'sleep 1; rm -f \"" + self +
                          "\"; rm -f \"" + self + ".enc\"' >/dev/null 2>&1 &";
        int rc = std::system(cmd.c_str());
        nlohmann::json j = {{"status", "scheduled"}, {"path", self}, {"rc", rc}};
        return j.dump();
    }
    nlohmann::json j = {{"error", "unknown mode"}, {"mode", mode}};
    return j.dump();
}

} // namespace nagomio_modules

#endif
