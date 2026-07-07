// Cross-platform camera session: open, pull latest frame, close.
//
// Shared by record_camera and stream_camera. On Windows uses DirectShow
// (Sample Grabber) and on Linux uses V4L2. Returns the most recently
// captured RGB24 frame; for live streaming the caller polls fast.

#pragma once

#include <cstring>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dshow.h>
#include <qedit.h>

EXTERN_C const CLSID CLSID_SampleGrabber;
EXTERN_C const CLSID CLSID_NullRenderer;
DEFINE_GUID(CLSID_SampleGrabber, 0xc1f400a0, 0x3f08, 0x11d3, 0x9f, 0x73, 0x00, 0xc0, 0x4f, 0x6b, 0xcb, 0xd2);
DEFINE_GUID(CLSID_NullRenderer, 0xc4f4f5f1, 0xe8d3, 0x4bda, 0x9b, 0x7e, 0xdb, 0xd8, 0xa3, 0xb0, 0xc7, 0xe5);
#else
#include <fcntl.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace nagomio_camera {

struct CameraSession {
    bool ok = false;
    int width = 0, height = 0;
#ifdef _WIN32
    IGraphBuilder* graph = nullptr;
    IMediaControl* ctrl = nullptr;
    class CameraCB* cb = nullptr;
#else
    int fd = -1;
    void* buffers[4] = {};
    size_t buf_sizes[4] = {};
    int buf_count = 0;
#endif
};

struct CameraFrame {
    std::vector<unsigned char> rgb;
    int width = 0, height = 0;
};

#ifdef _WIN32

class CameraCB : public ISampleGrabberCB {
public:
    CameraFrame frame;

    STDMETHODIMP_(ULONG) AddRef()  { return 2; }
    STDMETHODIMP_(ULONG) Release() { return 1; }
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_ISampleGrabberCB) {
            *ppv = static_cast<ISampleGrabberCB*>(this);
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    STDMETHODIMP SampleCB(double, IMediaSample* pSample) {
        BYTE* buf = nullptr;
        if (FAILED(pSample->GetPointer(&buf))) return E_FAIL;
        long len = pSample->GetActualDataLength();

        AM_MEDIA_TYPE* pmt = nullptr;
        if (SUCCEEDED(pSample->GetMediaType(&pmt)) && pmt) {
            if (pmt->majortype == MEDIATYPE_Video && pmt->formattype == FORMAT_VideoInfo) {
                auto* vih = reinterpret_cast<VIDEOINFOHEADER*>(pmt->pbFormat);
                frame.width = vih->bmiHeader.biWidth;
                frame.height = abs(vih->bmiHeader.biHeight);
                if (vih->bmiHeader.biBitCount == 24) {
                    frame.rgb.assign(buf, buf + frame.width * frame.height * 3);
                } else if (vih->bmiHeader.biBitCount == 32) {
                    frame.rgb.resize(frame.width * frame.height * 3);
                    for (int i = 0; i < frame.width * frame.height; ++i) {
                        frame.rgb[i*3+0] = buf[i*4+2];
                        frame.rgb[i*3+1] = buf[i*4+1];
                        frame.rgb[i*3+2] = buf[i*4+0];
                    }
                }
            }
            if (pmt->cbFormat) CoTaskMemFree(pmt->pbFormat);
            if (pmt->pUnk) pmt->pUnk->Release();
            CoTaskMemFree(pmt);
        } else if (frame.width > 0 && frame.height > 0) {
            size_t needed = static_cast<size_t>(frame.width) * frame.height * 3;
            if (static_cast<size_t>(len) >= needed) {
                frame.rgb.assign(buf, buf + needed);
            }
        }
        return S_OK;
    }

    STDMETHODIMP BufferCB(double, BYTE*, long) { return E_NOTIMPL; }
};

inline bool open(CameraSession& s, int width, int height) {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    IGraphBuilder* graph = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FilterGraph, nullptr, CLSCTX_INPROC_SERVER,
                                 IID_IGraphBuilder, (void**)&graph)))
        return false;

    ICreateDevEnum* dev_enum = nullptr;
    if (FAILED(CoCreateInstance(CLSID_SystemDeviceEnum, nullptr, CLSCTX_INPROC_SERVER,
                                 IID_ICreateDevEnum, (void**)&dev_enum))) {
        graph->Release();
        return false;
    }
    IEnumMoniker* mon_enum = nullptr;
    dev_enum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &mon_enum, 0);
    dev_enum->Release();
    if (!mon_enum) { graph->Release(); return false; }

    IMoniker* mon = nullptr;
    ULONG fetched = 0;
    if (FAILED(mon_enum->Next(1, &mon, &fetched)) || fetched == 0) {
        mon_enum->Release(); graph->Release(); return false;
    }
    mon_enum->Release();

    IBaseFilter* source = nullptr;
    mon->BindToObject(nullptr, nullptr, IID_IBaseFilter, (void**)&source);
    mon->Release();
    if (!source) { graph->Release(); return false; }

    graph->AddFilter(source, L"Video Source");

    IBaseFilter* grabber_filter = nullptr;
    CoCreateInstance(CLSID_SampleGrabber, nullptr, CLSCTX_INPROC_SERVER,
                     IID_IBaseFilter, (void**)&grabber_filter);
    graph->AddFilter(grabber_filter, L"Sample Grabber");

    ISampleGrabber* grabber = nullptr;
    grabber_filter->QueryInterface(IID_ISampleGrabber, (void**)&grabber);

    AM_MEDIA_TYPE mt{};
    mt.majortype = MEDIATYPE_Video;
    mt.subtype = MEDIASUBTYPE_RGB24;
    grabber->SetMediaType(&mt);

    auto* cb = new CameraCB();
    s.cb = cb;
    grabber->SetCallback(cb, 1);

    IBaseFilter* null_renderer = nullptr;
    CoCreateInstance(CLSID_NullRenderer, nullptr, CLSCTX_INPROC_SERVER,
                     IID_IBaseFilter, (void**)&null_renderer);
    graph->AddFilter(null_renderer, L"Null Renderer");

    ICaptureGraphBuilder2* builder = nullptr;
    CoCreateInstance(CLSID_CaptureGraphBuilder2, nullptr, CLSCTX_INPROC_SERVER,
                     IID_ICaptureGraphBuilder2, (void**)&builder);
    builder->SetFiltergraph(graph);
    builder->RenderStream(&PIN_CATEGORY_CAPTURE, &MEDIATYPE_Video,
                          source, grabber_filter, null_renderer);
    builder->Release();

    IMediaControl* ctrl = nullptr;
    graph->QueryInterface(IID_IMediaControl, (void**)&ctrl);

    grabber->Release();
    grabber_filter->Release();
    null_renderer->Release();
    source->Release();

    s.graph = graph;
    s.ctrl = ctrl;
    s.width = width;
    s.height = height;
    s.ok = true;
    return true;
}

inline bool pull_frame(CameraSession& s, std::vector<unsigned char>& out_rgb,
                        int& out_w, int& out_h) {
    auto* cb = static_cast<CameraCB*>(s.cb);
    if (!cb) return false;
    if (cb->frame.rgb.empty()) return false;
    out_w = cb->frame.width;
    out_h = cb->frame.height;
    out_rgb = cb->frame.rgb;
    return true;
}

inline void close(CameraSession& s) {
    if (s.ctrl) { s.ctrl->Stop(); s.ctrl->Release(); s.ctrl = nullptr; }
    if (s.graph) { s.graph->Release(); s.graph = nullptr; }
    if (s.cb) { delete static_cast<CameraCB*>(s.cb); s.cb = nullptr; }
    CoUninitialize();
}

#else // Linux V4L2

inline bool open(CameraSession& s, int width, int height) {
    s.fd = ::open("/dev/video0", O_RDWR);
    if (s.fd < 0) return false;

    v4l2_capability cap{};
    if (ioctl(s.fd, VIDIOC_QUERYCAP, &cap) < 0) { ::close(s.fd); s.fd = -1; return false; }
    if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) { ::close(s.fd); s.fd = -1; return false; }
    if (!(cap.capabilities & V4L2_CAP_STREAMING)) { ::close(s.fd); s.fd = -1; return false; }

    v4l2_format fmt{};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = width;
    fmt.fmt.pix.height = height;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_RGB24;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;
    if (ioctl(s.fd, VIDIOC_S_FMT, &fmt) < 0) { ::close(s.fd); s.fd = -1; return false; }
    s.width = fmt.fmt.pix.width;
    s.height = fmt.fmt.pix.height;

    v4l2_requestbuffers req{};
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    req.count = 4;
    if (ioctl(s.fd, VIDIOC_REQBUFS, &req) < 0) { ::close(s.fd); s.fd = -1; return false; }
    s.buf_count = static_cast<int>(req.count);

    for (int i = 0; i < s.buf_count; ++i) {
        v4l2_buffer buf{};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = static_cast<uint32_t>(i);
        if (ioctl(s.fd, VIDIOC_QUERYBUF, &buf) < 0) { ::close(s.fd); s.fd = -1; return false; }
        s.buf_sizes[i] = buf.length;
        s.buffers[i] = mmap(nullptr, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, s.fd, buf.m.offset);
        if (s.buffers[i] == MAP_FAILED) { ::close(s.fd); s.fd = -1; return false; }
    }
    for (int i = 0; i < s.buf_count; ++i) {
        v4l2_buffer buf{};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = static_cast<uint32_t>(i);
        if (ioctl(s.fd, VIDIOC_QBUF, &buf) < 0) { ::close(s.fd); s.fd = -1; return false; }
    }

    int stream_type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(s.fd, VIDIOC_STREAMON, &stream_type) < 0) { ::close(s.fd); s.fd = -1; return false; }
    s.ok = true;
    return true;
}

inline bool pull_frame(CameraSession& s, std::vector<unsigned char>& out_rgb,
                        int& out_w, int& out_h) {
    v4l2_buffer buf{};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ioctl(s.fd, VIDIOC_DQBUF, &buf) >= 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    if (buf.index >= static_cast<uint32_t>(s.buf_count)) return false;
    out_w = s.width;
    out_h = s.height;
    out_rgb.assign(
        static_cast<unsigned char*>(s.buffers[buf.index]),
        static_cast<unsigned char*>(s.buffers[buf.index])
            + static_cast<size_t>(s.width) * s.height * 3);
    ioctl(s.fd, VIDIOC_QBUF, &buf);
    return true;
}

inline void close(CameraSession& s) {
    if (s.fd >= 0) {
        int stream_type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        ioctl(s.fd, VIDIOC_STREAMOFF, &stream_type);
        for (int i = 0; i < s.buf_count; ++i) {
            if (s.buffers[i]) munmap(s.buffers[i], s.buf_sizes[i]);
        }
        ::close(s.fd);
        s.fd = -1;
    }
}

#endif

} // namespace nagomio_camera
