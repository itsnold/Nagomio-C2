// stream_stop: signal the live-stream capture loop to exit.
//
// Sets the shared atomic stop flag. The next iteration of any active
// `stream_*` module checks the flag and exits its loop. After that the
// streaming task sends its final chunk and the task completes.
//
// Args: none.

#include "../json.hpp"
#include "../protocol.h"
#include "registry.h"
#include "stream_state.h"

namespace nagomio_modules {

std::string handle_stream_stop(const std::vector<std::string>&) {
    request_stream_stop();
    nlohmann::json j = {
        {"type",  "stream_stop"},
        {"flag",  true},
    };
    return j.dump();
}

} // namespace nagomio_modules
