#pragma once

namespace nagomio_evade {
// Apply all startup-time Windows-specific evasions: AMSI + ETW patching.
// Defined in evade_win.cpp behind NAGOMIO_STEALTH on _WIN32.
void apply_all();
} // namespace nagomio_evade
