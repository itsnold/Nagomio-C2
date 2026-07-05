#pragma once

#include "../json.hpp"
#include "../protocol.h"

#include <string>

namespace nagomio_modules {

// Dispatch a task to the matching module. Returns the JSON to put in
// `AgentResponse.output`.
std::string dispatch(const Nagomio::Task& task, const std::string& agent_id);

// Returns true when `cmd` is a known module name (e.g. "whoami", "mem_exec").
bool is_known_module(const std::string& cmd);

} // namespace nagomio_modules