// Shared live-stream state.
//
// The agent runs modules in response to a single task at a time inside the
// main beacon loop. A "live stream" module (stream_display / stream_camera /
// stream_mic) holds the task thread for the entire capture duration and
// posts chunks of frames to the teamserver. To end a stream, the operator
// queues a `stream_stop` task. That task needs to signal the live-stream
// module to exit its capture loop.
//
// We use a process-global atomic flag for that signal so any module can set
// it without going through the task dispatcher.

#pragma once

#include <atomic>

namespace nagomio_modules {

inline std::atomic<bool>& stream_stop_flag() {
    static std::atomic<bool> flag{false};
    return flag;
}

inline void request_stream_stop() {
    stream_stop_flag().store(true, std::memory_order_release);
}

inline bool stream_stop_requested() {
    return stream_stop_flag().load(std::memory_order_acquire);
}

inline void clear_stream_stop() {
    stream_stop_flag().store(false, std::memory_order_release);
}

} // namespace nagomio_modules
