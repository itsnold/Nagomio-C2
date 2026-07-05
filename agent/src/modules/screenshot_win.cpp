// screenshot module (B6, Windows only).
//
// Captures the primary display using GDI. The bitmap is base64-encoded as a
// raw 32bpp DIB inside the JSON output. The Tauri client renders the DIB.
//
// We avoid the WIC dependency to keep the agent small. The result is a
// `.bmp`-style base64 blob; the client turns it into a PNG with canvas.

#include "../../json.hpp"
#include "../../protocol.h"

#include <windows.h>
#include <string>
#include <vector>

namespace nagomio_modules {

std::string handle_screenshot(const std::vector<std::string>&) {
    HDC hdc_screen = GetDC(nullptr);
    int width = GetDeviceCaps(hdc_screen, HORZRES);
    int height = GetDeviceCaps(hdc_screen, VERTRES);
    if (width <= 0 || height <= 0) {
        ReleaseDC(nullptr, hdc_screen);
        return std::string(R"({"error":"could not determine display size"})");
    }
    HDC hdc = CreateCompatibleDC(hdc_screen);
    HBITMAP hbm = CreateCompatibleBitmap(hdc_screen, width, height);
    HGDIOBJ prev = SelectObject(hdc, hbm);
    BitBlt(hdc, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);

    BITMAPINFOHEADER bih{};
    bih.biSize = sizeof(bih);
    bih.biWidth = width;
    bih.biHeight = -height; // top-down
    bih.biPlanes = 1;
    bih.biBitCount = 32;
    bih.biCompression = BI_RGB;
    std::vector<unsigned char> pixels(width * height * 4);
    if (!GetDIBits(hdc, hbm, 0, height, pixels.data(),
                   reinterpret_cast<BITMAPINFO*>(&bih), DIB_RGB_COLORS)) {
        SelectObject(hdc, prev);
        DeleteObject(hbm);
        DeleteDC(hdc);
        ReleaseDC(nullptr, hdc_screen);
        return std::string(R"({"error":"GetDIBits failed"})");
    }
    SelectObject(hdc, prev);
    DeleteObject(hbm);
    DeleteDC(hdc);
    ReleaseDC(nullptr, hdc_screen);

    // Build a minimal BMP file (no file header; just DIB + file header). The
    // client parses it as a BMP. The upside is no PNG dependency.
    BITMAPFILEHEADER bfh{};
    bfh.bfType = 0x4D42; // 'BM'
    bfh.bfSize = (DWORD)(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pixels.size());
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    std::vector<unsigned char> bmp;
    bmp.resize(sizeof(BITMAPFILEHEADER));
    std::memcpy(bmp.data(), &bfh, sizeof(bfh));
    bmp.resize(bmp.size() + sizeof(BITMAPINFOHEADER));
    std::memcpy(bmp.data() + sizeof(BITMAPFILEHEADER), &bih, sizeof(bih));
    bmp.insert(bmp.end(), pixels.begin(), pixels.end());

    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    int val = 0, bits = -6;
    for (auto c : bmp) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            b64.push_back(alpha[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) b64.push_back(alpha[((val << 8) >> (bits + 8)) & 0x3F]);
    while (b64.size() % 4) b64.push_back('=');

    nlohmann::json j = {
        {"type", "screenshot_bmp"},
        {"width", width},
        {"height", height},
        {"content_base64", b64},
    };
    return j.dump();
}

} // namespace nagomio_modules