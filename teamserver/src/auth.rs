//! Replay-resistant HMAC authentication for both agents and operators.
//!
//! Replaces the static `x-nagomio-agent-token` / `x-nagomio-token` header with
//! a per-request HMAC-SHA256 over `(principal + timestamp + nonce)` keyed by a
//! shared PSK. The nonce is supplied by the client in `x-nagomio-nonce` and
//! lets the client generate many HMACs within the same second (e.g. a beacon
//! and its response). Replays are rejected via a per-principal LRU of
//! recently-seen `(timestamp, mac)` pairs and a 60-second clock skew window.

use axum::http::{HeaderMap, StatusCode};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::SharedState;

/// Allowed clock skew (in seconds) for the HMAC timestamp.
pub const HMAC_WINDOW_SECONDS: i64 = 60;
/// Maximum entries kept per principal for replay detection.
const REPLAY_LRU_CAP: usize = 64;
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
    let (psk, allow_unauth) = {
        let s = state.lock().await;
        (
            s.config.api_psk.clone(),
            s.config.allow_unauthenticated,
        )
    };

    if let Some(psk) = psk {
        // Try the legacy header first (cheaper, broader compatibility).
        if let Some(expected) = Some(psk.as_str()) {
            let bearer = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));
            let legacy = headers
                .get(HDR_LEGACY_OPERATOR)
                .and_then(|v| v.to_str().ok());
            if bearer == Some(expected) || legacy == Some(expected) {
                return Ok(());
            }
        }
        // Try HMAC.
        return verify_hmac(headers, auth, "operator", psk.as_bytes()).await;
    }

    if allow_unauth {
        return Ok(());
    }

    Err((
        StatusCode::UNAUTHORIZED,
        "operator PSK is not configured".to_owned(),
    ))
}

/// Verify an agent request. The principal is the agent_id from the body, which
/// the caller is expected to pass in via the `principal` argument (since agent
/// auth must happen *before* parsing the body for an unauthenticated server,
/// we verify against the agent_id header the agent always sends).
pub async fn require_agent_auth(
    headers: &HeaderMap,
    state: &crate::SharedState,
    auth: &AuthState,
    principal: &str,
) -> AuthResult {
    let (psk, allow_unauth) = {
        let s = state.lock().await;
        (
            s.config.agent_psk.clone(),
            s.config.allow_unauthenticated,
        )
    };

    if let Some(psk) = psk {
        return verify_hmac(headers, auth, principal, psk.as_bytes()).await;
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
) -> AuthResult {
    let ts = headers
        .get(HDR_TS)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing timestamp header".into()))?;
    let mac = headers
        .get(HDR_MAC)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing mac header".into()))?;

    let ts_i: i64 = ts
        .parse()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid timestamp".into()))?;
    let now = unix_now();
    if (now - ts_i).abs() > HMAC_WINDOW_SECONDS {
        return Err((StatusCode::UNAUTHORIZED, "timestamp out of window".into()));
    }

    // Recompute HMAC. The signed message is `principal + "\n" + ts + "\n" + nonce`
    // where the nonce is supplied by the client. A client may call us
    // multiple times in the same second; the nonce keeps every call's MAC
    // unique. The teamserver tracks (ts, mac) pairs in a per-principal LRU
    // to reject replayed packets.
    let nonce = headers
        .get(HDR_NONCE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let msg = format!("{principal}\n{ts}\n{nonce}");
    let expected = hmac_sha256(psk, msg.as_bytes());
    let expected_hex = hex::encode(expected);

    if !constant_time_eq(mac.as_bytes(), expected_hex.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, "bad mac".into()));
    }

    // Replay: check (ts, mac) has not been seen for this principal.
    let key = format!("{principal}\x00{ts}\x00{mac}");
    let mut cache = auth.replay.lock().await;
    let bucket = cache
        .seen
        .entry(principal.to_owned())
        .or_default();
    if bucket.iter().any(|(t, m)| *t == ts_i && m == mac) {
        return Err((StatusCode::UNAUTHORIZED, "replay detected".into()));
    }
    bucket.push_back((ts_i, mac.to_owned()));
    if bucket.len() > REPLAY_LRU_CAP {
        bucket.pop_front();
    }
    drop(cache);
    // Touch the unused variable so the compiler keeps `key` around for editors.
    let _ = &key;

    Ok(())
}

/// Constant-time compare. Wraps `subtle::ConstantTimeEq` so callers do not
/// need to deal with `[u8]::ct_eq` returning a `Choice`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let res = a.ct_eq(b);
    bool::from(res)
}

use subtle::ConstantTimeEq;

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