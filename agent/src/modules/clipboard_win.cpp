// clipboard module (B6, Windows only).
//
// Reads the current Windows clipboard text and returns it as JSON. Uses
// OpenClipboard / GetClipboardData / GlobalLock.

#include "../json.hpp"
#include "../protocol.h"

#include <windows.h>
#include <string>

namespace nagomio_modules {

std::string handle_clipboard(const std::vector<std::string>&) {
    if (!OpenClipboard(nullptr)) {
        return std::string(R"({"error":"OpenClipboard failed"})");
    }
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    std::string out;
    if (h) {
        const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h));
        if (p) {
            // Convert wchar_t -> UTF-8.
            int len = WideCharToMultiByte(CP_UTF8, 0, p, -1, nullptr, 0, nullptr, nullptr);
            if (len > 1) {
                std::string buf(static_cast<size_t>(len - 1), '\0');
                WideCharToMultiByte(CP_UTF8, 0, p, -1, buf.data(), len, nullptr, nullptr);
                out = std::move(buf);
            }
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    nlohmann::json j = {
        {"text", out},
        {"size", out.size()},
    };
    return j.dump();
}

} // namespace nagomio_modules