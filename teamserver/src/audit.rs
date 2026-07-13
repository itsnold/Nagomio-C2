//! Operator audit log (B10).
//!
//! Every authenticated operator API call produces an `Audit` event into the
//! persistence worker. The `audit_log` SQLite table is queried by the
//! read endpoint `/api/audit` for display in the operator UI.

use crate::auth::require_api_auth;
use crate::persistence::{open_db, PersistEvent};
use crate::{internal_error, ApiState};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rusqlite::params;
use serde::Deserialize;
use shared::AuditEntry;

#[derive(Clone)]
pub struct AuditState {
    pub tx: crate::persistence::PersistSender,
}

/// Record an operator action. Caller passes the empty string for `source_ip`
/// when the requestor's IP cannot be determined.
pub async fn record(
    tx: &crate::persistence::PersistSender,
    source_ip: &str,
    action: &str,
    agent_id: Option<&str>,
    task_id: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    crate::persistence::persist(tx, PersistEvent::Audit {
        timestamp_unix: unix_now(),
        source_ip: source_ip.to_owned(),
        action: action.to_owned(),
        agent_id: agent_id.map(|s| s.to_owned()),
        task_id: task_id.map(|s| s.to_owned()),
    })
    .await
    .map_err(|err| (StatusCode::SERVICE_UNAVAILABLE, format!("persistence failed: {err}")))
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    pub limit: Option<usize>,
    pub since: Option<u64>,
}

pub async fn api_get_audit(
    State(api): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, (StatusCode, String)> {
    require_api_auth(&headers, &api.shared, &api.auth).await?;
    record(&api.audit.tx, "", "list_audit", None, None).await?;
    let limit = query.limit.unwrap_or(200).min(1000);
    let since = query.since.unwrap_or(0) as i64;
    let db_path = {
        let s = api.shared.lock().await;
        s.db_path.clone()
    };
    let Some(db_path) = db_path else {
        return Ok(Json(Vec::new()));
    };
    let conn = open_db(&db_path).map_err(internal_error)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, timestamp_unix, source_ip, action, agent_id, task_id
             FROM audit_log WHERE timestamp_unix >= ?1 ORDER BY id DESC LIMIT ?2",
        )
        .map_err(internal_error)?;
    let rows = stmt
        .query_map(params![since, limit as i64], |row| {
            Ok(AuditEntry {
                id: row.get(0)?,
                timestamp_unix: row.get::<_, i64>(1)? as u64,
                source_ip: row.get(2)?,
                action: row.get(3)?,
                agent_id: row.get(4)?,
                task_id: row.get(5)?,
            })
        })
        .map_err(internal_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(internal_error)?);
    }
    Ok(Json(out))
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
