#pragma once
#include <string>
#include <vector>

namespace Nagomio {
    
    struct AgentRegistration {
        std::string agent_id;
        std::string hostname;
        std::string os;
        std::string architecture;
    };

    struct BeaconRequest {
        AgentRegistration registration;
    };

    struct Task {
        std::string task_id;
        std::string command;
        std::vector<std::string> arguments;
    };

    struct BeaconReply {
        std::string status;
        int sleep_seconds;
        bool has_task;
        Task task;
    };

    struct AgentResponse {
        std::string agent_id;
        std::string task_id;
        std::string output;
        std::string status;
    };

} // namespace Nagomio
