//! Append-only persistence.
//!
//! In the original design every beacon / response triggered a
//! `DELETE FROM ...; INSERT INTO ...` full-store rewrite. That thrashes SQLite
//! and serializes every request behind the write lock at any non-trivial
//! agent count.
//!
//! This module replaces it with an event channel feeding a single background
//! worker that applies point `INSERT` / `UPDATE` / `DELETE` operations. The
//! in-memory `Store` remains the read path; SQLite becomes a write-ahead log
//! plus the cold-start replay source.
//!
//! The legacy JSON state-file fallback (used when no `--db` is configured) is
//! preserved via a debounced periodic checkpoint emitted by the same worker.

use rusqlite::{params, Connection};
use shared::AgentResponse;
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, oneshot};

use crate::SharedState;
use crate::Store;

/// Events emitted by request handlers. Sent over an `mpsc::Sender`; the
/// worker applies each to SQLite and (debounced) the JSON state file.
#[derive(Debug)]
pub enum PersistEvent {
    AgentUpsert {
        agent_id: String,
        registration_json: String,
        first_seen_unix: u64,
        last_seen_unix: u64,
        /// When false, the agent exists; we UPDATE last_seen + registration only.
        is_new: bool,
    },
    TaskQueued {
        task_id: String,
        agent_id: String,
        command: String,
        arguments_json: String,
        created_at_unix: u64,
        position: usize,
    },
    TaskDispatched {
        task_id: String,
        dispatched_at_unix: u64,
    },
    TaskCompleted {
        task_id: String,
        status: String,
        completed_at_unix: u64,
    },
    TaskReQueued {
        task_id: String,
    },
    ResponseAppended {
        agent_id: String,
        response: AgentResponse,
    },
    AgentRemoved {
        agent_id: String,
    },
    AgentPskSet {
        agent_id: String,
        psk: String,
    },
    PayloadUpserted {
        build_id: String,
        artifact_json: String,
    },
    PayloadsCleared,
    PayloadRemoved {
        build_id: String,
    },
    Audit {
        timestamp_unix: u64,
        source_ip: String,
        action: String,
        agent_id: Option<String>,
        task_id: Option<String>,
    },
    /// Force a JSON state-file checkpoint immediately.
    Checkpoint,
}

/// A persistence request and the result channel for its durable write.
pub struct PersistRequest {
    event: PersistEvent,
    ack: oneshot::Sender<Result<(), String>>,
}

pub type PersistSender = mpsc::Sender<PersistRequest>;
pub const PERSIST_CHANNEL_CAPACITY: usize = 256;

/// Wait for the worker to durably apply an event. A full queue applies
/// backpressure instead of silently accumulating unbounded mutations.
pub async fn persist(tx: &PersistSender, event: PersistEvent) -> Result<(), String> {
    let (ack_tx, ack_rx) = oneshot::channel();
    tx.send(PersistRequest { event, ack: ack_tx })
        .await
        .map_err(|_| "persistence worker is unavailable".to_owned())?;
    ack_rx
        .await
        .map_err(|_| "persistence worker stopped before acknowledging write".to_owned())?
}

/// Queue a non-request mutation without blocking its caller. Use [`persist`]
/// for API mutations that must report durability to their caller.
pub fn enqueue(tx: &PersistSender, event: PersistEvent) -> Result<(), String> {
    let (ack, _ignored) = oneshot::channel();
    tx.try_send(PersistRequest { event, ack })
        .map_err(|err| format!("persistence queue unavailable: {err}"))
}

/// Spawns the persistence worker that drains `rx`. The caller must create a
/// single channel and share its sender with `AppState`, `AuditState`, and the
/// requeue worker so every event reaches this same receiver.
pub fn spawn(
    state: Option<SharedState>,
    db_path: Option<PathBuf>,
    state_file: Option<PathBuf>,
    mut rx: mpsc::Receiver<PersistRequest>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Open a private SQLite connection for the worker. If no db_path is
        // configured (legacy JSON-only mode) the worker keeps running but only
        // performs the debounced checkpoint writes.
        let mut conn = match db_path.as_ref() {
            Some(path) => match open_db_with_wal(path) {
                Ok(c) => Some(c),
                Err(err) => {
                    eprintln!("[-] persistence worker: cannot open db {}: {}", path.display(), err);
                    None
                }
            },
            None => None,
        };

        let mut last_checkpoint = std::time::Instant::now();
        const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

        while let Some(request) = rx.recv().await {
            let event = request.event;
            let result = if let Some(conn) = conn.as_mut() {
                apply_event(conn, &event)
            } else if state_file.is_some() {
                // The legacy JSON path snapshots the current in-memory store.
                // It is retained for compatibility but is not used by the DB mode.
                Ok(())
            } else {
                Err("no persistence backend is configured".to_owned())
            };
            if let Err(err) = &result {
                eprintln!("[-] persistence worker: event failed: {err} (event={event:?})");
            }

            // Debounced JSON checkpoint (only used in legacy state-file mode).
            if last_checkpoint.elapsed() >= CHECKPOINT_INTERVAL {
                last_checkpoint = std::time::Instant::now();
                if let Some(path) = state_file.as_ref() {
                    let snapshot = {
                        let s = state
                            .as_ref()
                            .expect("state file requires application state")
                            .lock()
                            .await;
                        s.store.clone()
                    };
                    save_store_json(&path.clone(), &snapshot).await;
                }
            }

            if matches!(&event, PersistEvent::Checkpoint) {
                last_checkpoint = std::time::Instant::now();
                if let Some(path) = state_file.as_ref() {
                    let snapshot = {
                        let s = state
                            .as_ref()
                            .expect("state file requires application state")
                            .lock()
                            .await;
                        s.store.clone()
                    };
                    save_store_json(&path.clone(), &snapshot).await;
                }
            }
            let _ = request.ack.send(result);
        }
    })
}

fn open_db_with_wal(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            registration_json TEXT NOT NULL,
            first_seen_unix INTEGER NOT NULL,
            last_seen_unix INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agent_psks (
            agent_id TEXT PRIMARY KEY,
            psk TEXT NOT NULL
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
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_unix INTEGER NOT NULL,
            source_ip TEXT NOT NULL,
            action TEXT NOT NULL,
            agent_id TEXT,
            task_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp_unix);
        CREATE INDEX IF NOT EXISTS idx_responses_agent ON responses(agent_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
        CREATE INDEX IF NOT EXISTS idx_tasks_dispatched ON tasks(dispatched_at_unix);
        ",
    )?;
    Ok(conn)
}

fn apply_event(conn: &mut Connection, event: &PersistEvent) -> Result<(), String> {
    match event {
        PersistEvent::AgentUpsert { agent_id, registration_json, first_seen_unix, last_seen_unix, is_new } => {
            if *is_new {
                conn.execute(
                    "INSERT INTO agents (agent_id, registration_json, first_seen_unix, last_seen_unix) VALUES (?1, ?2, ?3, ?4)",
                    params![agent_id, registration_json, *first_seen_unix as i64, *last_seen_unix as i64],
                ).map_err(|e| e.to_string())?;
            } else {
                conn.execute(
                    "UPDATE agents SET registration_json = ?2, last_seen_unix = ?3 WHERE agent_id = ?1",
                    params![agent_id, registration_json, *last_seen_unix as i64],
                ).map_err(|e| e.to_string())?;
            }
        }
        PersistEvent::TaskQueued { task_id, agent_id, command, arguments_json, created_at_unix, position } => {
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO tasks (task_id, agent_id, command, arguments_json, status, created_at_unix, dispatched_at_unix, completed_at_unix)
                 VALUES (?1, ?2, ?3, ?4, 'queued', ?5, NULL, NULL)
                 ON CONFLICT(task_id) DO UPDATE SET
                    agent_id = excluded.agent_id,
                    command = excluded.command,
                    arguments_json = excluded.arguments_json,
                    status = 'queued',
                    created_at_unix = excluded.created_at_unix,
                    dispatched_at_unix = NULL,
                    completed_at_unix = NULL",
                params![task_id, agent_id, command, arguments_json, *created_at_unix as i64],
            ).map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO pending_tasks (agent_id, position, task_id) VALUES (?1, ?2, ?3)",
                params![agent_id, *position as i64, task_id],
            ).map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        }
        PersistEvent::TaskDispatched { task_id, dispatched_at_unix } => {
            conn.execute(
                "UPDATE tasks SET status = 'dispatched', dispatched_at_unix = ?2 WHERE task_id = ?1",
                params![task_id, *dispatched_at_unix as i64],
            ).map_err(|e| e.to_string())?;
            // Drop the pending_tasks row (already popped from in-memory queue).
            conn.execute(
                "DELETE FROM pending_tasks WHERE task_id = ?1",
                params![task_id],
            ).map_err(|e| e.to_string())?;
        }
        PersistEvent::TaskCompleted { task_id, status, completed_at_unix } => {
            conn.execute(
                "UPDATE tasks SET status = ?2, completed_at_unix = ?3 WHERE task_id = ?1",
                params![task_id, status, *completed_at_unix as i64],
            ).map_err(|e| e.to_string())?;
            // A late response or terminal transition must not leave a pending row.
            conn.execute(
                "DELETE FROM pending_tasks WHERE task_id = ?1",
                params![task_id],
            ).map_err(|e| e.to_string())?;
        }
        PersistEvent::TaskReQueued { task_id } => {
            let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
            // Need to re-add to pending_tasks at the tail of this agent's queue.
            let agent_id: String = tx
                .query_row("SELECT agent_id FROM tasks WHERE task_id = ?1", params![task_id], |r| r.get(0))
                .map_err(|e| e.to_string())?;
            let next_pos: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM pending_tasks WHERE agent_id = ?1",
                    params![agent_id],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO pending_tasks (agent_id, position, task_id) VALUES (?1, ?2, ?3)",
                params![agent_id, next_pos, task_id],
            ).map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE tasks SET status = 're_queued', dispatched_at_unix = NULL, completed_at_unix = NULL WHERE task_id = ?1",
                params![task_id],
            ).map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        }
        PersistEvent::ResponseAppended { agent_id, response } => {
            conn.execute(
                "INSERT INTO responses (agent_id, task_id, output, status) VALUES (?1, ?2, ?3, ?4)",
                params![agent_id, response.task_id, response.output, response.status],
            ).map_err(|e| e.to_string())?;
        }
        PersistEvent::AgentRemoved { agent_id } => {
            conn.execute("DELETE FROM pending_tasks WHERE agent_id = ?1", params![agent_id]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM responses WHERE agent_id = ?1", params![agent_id]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM tasks WHERE agent_id = ?1", params![agent_id]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM agents WHERE agent_id = ?1", params![agent_id]).map_err(|e| e.to_string())?;
            conn.execute("DELETE FROM agent_psks WHERE agent_id = ?1", params![agent_id]).map_err(|e| e.to_string())?;
        }
        PersistEvent::AgentPskSet { agent_id, psk } => {
            conn.execute(
                "INSERT INTO agent_psks (agent_id, psk) VALUES (?1, ?2) ON CONFLICT(agent_id) DO UPDATE SET psk = excluded.psk",
                params![agent_id, psk],
            ).map_err(|e| e.to_string())?;
        }
        PersistEvent::PayloadUpserted { build_id, artifact_json } => {
            conn.execute(
                "INSERT INTO payloads (build_id, artifact_json) VALUES (?1, ?2)
                 ON CONFLICT(build_id) DO UPDATE SET artifact_json = excluded.artifact_json",
                params![build_id, artifact_json],
            ).map_err(|e| e.to_string())?;
        }
        PersistEvent::PayloadsCleared => {
            conn.execute("DELETE FROM payloads", []).map_err(|e| e.to_string())?;
        }
        PersistEvent::PayloadRemoved { build_id } => {
            conn.execute("DELETE FROM payloads WHERE build_id = ?1", params![build_id]).map_err(|e| e.to_string())?;
        }
        PersistEvent::Audit { timestamp_unix, source_ip, action, agent_id, task_id } => {
            conn.execute(
                "INSERT INTO audit_log (timestamp_unix, source_ip, action, agent_id, task_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![*timestamp_unix as i64, source_ip, action, agent_id, task_id],
            ).map_err(|e| e.to_string())?;
        }
        PersistEvent::Checkpoint => {
            // No-op here; the worker loop handles the JSON file checkpoint.
        }
    }
    Ok(())
}

/// Write the entire store to JSON. Used as a debounced checkpoint in the
/// legacy state-file mode (`NAGOMIO_STATE_FILE` set, no `db_path`).
async fn save_store_json(path: &Path, store: &Store) {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(store) {
        if let Err(err) = tokio::fs::write(path, bytes).await {
            eprintln!("[-] could not write state file {}: {}", path.display(), err);
        }
    }
}

/// Convenience wrapper used by the legacy cold-start path. Kept here so the
/// main module's `main` can bootstrap the in-memory store before the worker
/// starts. The [`spawn`] worker maintains its own connection afterwards.
pub fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    open_db_with_wal(path)
}
