//! Replay-resistant HMAC authentication for both agents and operators.
//!
//! Per-request HMAC-SHA256 over a canonical request string keyed by a shared
//! PSK. The signed material binds method, path, query, principal, timestamp,
//! nonce, and a SHA-256 of the body so headers cannot be moved across routes
//! and bodies cannot be swapped without invalidating the MAC.
//!
//! Canonical message (v1):
//! ```text
//! v1\n{METHOD}\n{PATH}\n{QUERY}\n{PRINCIPAL}\n{TS}\n{NONCE}\n{BODY_SHA256_HEX}
//! ```

use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Allowed clock skew (in seconds) for the HMAC timestamp.
pub const HMAC_WINDOW_SECONDS: i64 = 60;
/// Maximum entries kept per principal for replay detection.
const REPLAY_LRU_CAP: usize = 64;
/// Maximum number of distinct principals tracked in the replay cache.
const REPLAY_PRINCIPAL_CAP: usize = 4096;
/// Drop replay entries older than this many seconds past the HMAC window.
const REPLAY_TTL_SECONDS: i64 = HMAC_WINDOW_SECONDS * 2;

/// Headers
pub const HDR_TS: &str = "x-nagomio-ts";
pub const HDR_MAC: &str = "x-nagomio-mac";
pub const HDR_NONCE: &str = "x-nagomio-nonce";
/// Legacy bearer header kept for backwards compatibility in localhost mode.
pub const HDR_LEGACY_OPERATOR: &str = "x-nagomio-token";
pub const HDR_LEGACY_AGENT: &str = "x-nagomio-agent-token";

#[derive(Default)]
struct ReplayCache {
    /// Ring buffer of recently-seen (timestamp, mac) tuples per principal.
    seen: std::collections::HashMap<String, VecDeque<(i64, String)>>,
}

#[derive(Clone, Default)]
pub struct AuthState {
    replay: Arc<Mutex<ReplayCache>>,
}

/// Outcome of an auth attempt. `Ok(())` on success; on failure a tuple
/// suitable for axum's error response.
pub type AuthResult = Result<(), (StatusCode, String)>;

/// Build the canonical HMAC message for a request.
pub fn canonical_message(
    method: &str,
    path: &str,
    query: &str,
    principal: &str,
    ts: &str,
    nonce: &str,
    body: &[u8],
) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "v1\n{method}\n{path}\n{query}\n{principal}\n{ts}\n{nonce}\n{body_hash}"
    )
}

/// Verify an operator request. The principal in the HMAC payload is the
/// literal string `"operator"`. Falls back to the legacy
/// `x-nagomio-token` / `Authorization: Bearer` header when no PSK is
/// configured. When a PSK is configured, the legacy header is also
/// accepted for backwards compatibility (the Tauri UI currently uses
/// that path); HMAC is a strict upgrade.
pub async fn require_api_auth(
    headers: &HeaderMap,
    state: &crate::SharedState,
    auth: &AuthState,
) -> AuthResult {
    require_api_auth_ex(headers, state, auth, "GET", "/api", "", &[]).await
}

/// Operator auth with request binding (method/path/query/body).
pub async fn require_api_auth_ex(
    headers: &HeaderMap,
    state: &crate::SharedState,
    auth: &AuthState,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> AuthResult {
    let (psk, allow_unauth) = {
        let s = state.lock().await;
        (
            s.config.api_psk.clone(),
            s.config.allow_unauthenticated,
        )
    };

    if let Some(psk) = psk {
        // Legacy static token remains accepted for the operator UI, but uses
        // constant-time comparison so timing does not leak the secret.
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let legacy = headers
            .get(HDR_LEGACY_OPERATOR)
            .and_then(|v| v.to_str().ok());
        if bearer.is_some_and(|b| constant_time_eq(b.as_bytes(), psk.as_bytes()))
            || legacy.is_some_and(|t| constant_time_eq(t.as_bytes(), psk.as_bytes()))
        {
            return Ok(());
        }
        return verify_hmac(headers, auth, "operator", psk.as_bytes(), method, path, query, body)
            .await;
    }

    if allow_unauth {
        return Ok(());
    }

    Err((
        StatusCode::UNAUTHORIZED,
        "operator PSK is not configured".to_owned(),
    ))
}

/// Verify an agent request. Identity is taken from the already-authenticated
/// principal argument (agent_id), not re-read from an untrusted field after
/// verification.
pub async fn require_agent_auth(
    headers: &HeaderMap,
    state: &crate::SharedState,
    auth: &AuthState,
    principal: &str,
) -> AuthResult {
    // Legacy entry point: no request binding (tests / gradual migration).
    require_agent_auth_ex(headers, state, auth, principal, "POST", "/", "", &[]).await
}

/// Agent auth with full request binding.
pub async fn require_agent_auth_ex(
    headers: &HeaderMap,
    state: &crate::SharedState,
    auth: &AuthState,
    principal: &str,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> AuthResult {
    let (psk, allow_unauth) = {
        let s = state.lock().await;
        (
            s.config.agent_psk.clone(),
            s.config.allow_unauthenticated,
        )
    };

    if let Some(psk) = psk {
        return verify_hmac(
            headers,
            auth,
            principal,
            psk.as_bytes(),
            method,
            path,
            query,
            body,
        )
        .await;
    }

    if allow_unauth {
        return Ok(());
    }

    Err((
        StatusCode::UNAUTHORIZED,
        "agent PSK is not configured".to_owned(),
    ))
}

async fn verify_hmac(
    headers: &HeaderMap,
    auth: &AuthState,
    principal: &str,
    psk: &[u8],
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> AuthResult {
    let ts = headers
        .get(HDR_TS)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing timestamp header".into()))?;
    let mac = headers
        .get(HDR_MAC)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing mac header".into()))?;
    let nonce = headers
        .get(HDR_NONCE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing nonce header".into()))?;

    if nonce.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "empty nonce".into()));
    }
    // Require a cryptographically useful nonce (at least 8 hex chars / 32 bits).
    if nonce.len() < 8 {
        return Err((StatusCode::UNAUTHORIZED, "nonce too short".into()));
    }

    let ts_i: i64 = ts
        .parse()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid timestamp".into()))?;
    let now = unix_now();
    // Checked distance avoids overflow on extreme timestamps.
    let skew = now.abs_diff(ts_i) as i64;
    if skew > HMAC_WINDOW_SECONDS {
        return Err((StatusCode::UNAUTHORIZED, "timestamp out of window".into()));
    }

    let msg = canonical_message(method, path, query, principal, ts, nonce, body);
    let expected = hmac_sha256(psk, msg.as_bytes());
    let expected_hex = hex::encode(expected);

    if !constant_time_eq(mac.as_bytes(), expected_hex.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, "bad mac".into()));
    }

    // Replay: check (ts, mac) has not been seen for this principal.
    let mut cache = auth.replay.lock().await;
    // Bound the number of principals tracked.
    if !cache.seen.contains_key(principal) && cache.seen.len() >= REPLAY_PRINCIPAL_CAP {
        // Evict the first principal with an empty or fully-stale bucket.
        let stale_keys: Vec<String> = cache
            .seen
            .iter()
            .filter(|(_, bucket)| {
                bucket.is_empty()
                    || bucket
                        .iter()
                        .all(|(t, _)| now.abs_diff(*t) as i64 > REPLAY_TTL_SECONDS)
            })
            .map(|(k, _)| k.clone())
            .take(16)
            .collect();
        for k in stale_keys {
            cache.seen.remove(&k);
        }
        if cache.seen.len() >= REPLAY_PRINCIPAL_CAP {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "replay cache capacity exceeded".into(),
            ));
        }
    }

    let bucket = cache.seen.entry(principal.to_owned()).or_default();
    // Time-based eviction before capacity trim.
    while let Some(&(t, _)) = bucket.front() {
        if now.abs_diff(t) as i64 > REPLAY_TTL_SECONDS {
            bucket.pop_front();
        } else {
            break;
        }
    }
    if bucket.iter().any(|(t, m)| *t == ts_i && m == mac) {
        return Err((StatusCode::UNAUTHORIZED, "replay detected".into()));
    }
    bucket.push_back((ts_i, mac.to_owned()));
    while bucket.len() > REPLAY_LRU_CAP {
        bucket.pop_front();
    }

    Ok(())
}

/// Constant-time compare. Wraps `subtle::ConstantTimeEq` so callers do not
/// need to deal with `[u8]::ct_eq` returning a `Choice`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[doc(hidden)]
pub fn auth_hmac_for_test(key: &[u8], msg: &[u8]) -> String {
    hex::encode(hmac_sha256(key, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_binds_body() {
        let a = canonical_message("POST", "/beacon", "", "agent-1", "1", "deadbeef", b"{}");
        let b = canonical_message("POST", "/beacon", "", "agent-1", "1", "deadbeef", b"{ }");
        assert_ne!(a, b);
    }

    #[test]
    fn canonical_message_binds_route() {
        let a = canonical_message("POST", "/beacon", "", "agent-1", "1", "deadbeef", b"");
        let b = canonical_message("POST", "/response", "", "agent-1", "1", "deadbeef", b"");
        assert_ne!(a, b);
    }
}
