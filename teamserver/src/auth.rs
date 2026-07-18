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
pub(crate) const REPLAY_LRU_CAP: usize = 64;
/// Maximum number of distinct principals tracked in the replay cache.
pub(crate) const REPLAY_PRINCIPAL_CAP: usize = 4096;
/// Drop replay entries older than this many seconds past the HMAC window.
pub(crate) const REPLAY_TTL_SECONDS: i64 = HMAC_WINDOW_SECONDS * 2;

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
        let resolved = crate::resolve_agent_psk(&s.store, principal, s.config.agent_psk.as_deref());
        (resolved, s.config.allow_unauthenticated)
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
    verify_hmac_at(headers, auth, principal, psk, method, path, query, body, unix_now()).await
}

async fn verify_hmac_at(
    headers: &HeaderMap,
    auth: &AuthState,
    principal: &str,
    psk: &[u8],
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    now: i64,
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
    use axum::http::HeaderValue;

    fn signed_headers(
        psk: &[u8],
        method: &str,
        path: &str,
        query: &str,
        principal: &str,
        ts: i64,
        nonce: &str,
        body: &[u8],
    ) -> HeaderMap {
        let ts_s = ts.to_string();
        let msg = canonical_message(method, path, query, principal, &ts_s, nonce, body);
        let mac = auth_hmac_for_test(psk, msg.as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(HDR_TS, HeaderValue::from_str(&ts_s).unwrap());
        headers.insert(HDR_NONCE, HeaderValue::from_str(nonce).unwrap());
        headers.insert(HDR_MAC, HeaderValue::from_str(&mac).unwrap());
        headers
    }

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

    #[test]
    fn canonical_message_binds_method() {
        let a = canonical_message("POST", "/beacon", "", "agent-1", "1", "deadbeef", b"");
        let b = canonical_message("GET", "/beacon", "", "agent-1", "1", "deadbeef", b"");
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn modified_body_is_rejected() {
        let auth = AuthState::default();
        let psk = b"test-psk-for-hmac-body";
        let now = 1_700_000_000i64;
        let body = br#"{"agent_id":"agent-1"}"#;
        let headers = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "agent-1",
            now,
            "deadbeef",
            body,
        );
        assert!(
            verify_hmac_at(
                &headers,
                &auth,
                "agent-1",
                psk,
                "POST",
                "/beacon",
                "",
                body,
                now,
            )
            .await
            .is_ok()
        );
        let tampered = br#"{"agent_id":"agent-2"}"#;
        let err = verify_hmac_at(
            &headers,
            &auth,
            "agent-1",
            psk,
            "POST",
            "/beacon",
            "",
            tampered,
            now,
        )
        .await;
        assert!(matches!(err, Err((StatusCode::UNAUTHORIZED, _))));
    }

    #[tokio::test]
    async fn changed_route_is_rejected() {
        let auth = AuthState::default();
        let psk = b"test-psk-for-hmac-route";
        let now = 1_700_000_000i64;
        let body = b"{}";
        let headers = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "agent-1",
            now,
            "cafebabe",
            body,
        );
        let err = verify_hmac_at(
            &headers,
            &auth,
            "agent-1",
            psk,
            "POST",
            "/response",
            "",
            body,
            now,
        )
        .await;
        assert!(matches!(err, Err((StatusCode::UNAUTHORIZED, _))));
    }

    #[tokio::test]
    async fn changed_method_is_rejected() {
        let auth = AuthState::default();
        let psk = b"test-psk-for-hmac-method";
        let now = 1_700_000_000i64;
        let body = b"{}";
        let headers = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "agent-1",
            now,
            "feedface",
            body,
        );
        let err = verify_hmac_at(
            &headers,
            &auth,
            "agent-1",
            psk,
            "GET",
            "/beacon",
            "",
            body,
            now,
        )
        .await;
        assert!(matches!(err, Err((StatusCode::UNAUTHORIZED, _))));
    }

    #[tokio::test]
    async fn replay_is_rejected_within_ttl() {
        let auth = AuthState::default();
        let psk = b"test-psk-for-hmac-replay";
        let now = 1_700_000_000i64;
        let body = b"{}";
        let headers = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "agent-1",
            now,
            "aabbccdd",
            body,
        );
        assert!(
            verify_hmac_at(
                &headers,
                &auth,
                "agent-1",
                psk,
                "POST",
                "/beacon",
                "",
                body,
                now,
            )
            .await
            .is_ok()
        );
        let err = verify_hmac_at(
            &headers,
            &auth,
            "agent-1",
            psk,
            "POST",
            "/beacon",
            "",
            body,
            now + 1,
        )
        .await;
        assert!(matches!(err, Err((StatusCode::UNAUTHORIZED, _))));
    }

    #[tokio::test]
    async fn replay_entry_expires_after_ttl() {
        let auth = AuthState::default();
        let psk = b"test-psk-for-hmac-ttl";
        let t0 = 1_700_000_000i64;
        let body = b"{}";
        let headers = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "agent-1",
            t0,
            "11223344",
            body,
        );
        assert!(
            verify_hmac_at(
                &headers,
                &auth,
                "agent-1",
                psk,
                "POST",
                "/beacon",
                "",
                body,
                t0,
            )
            .await
            .is_ok()
        );
        // Immediate replay rejected.
        assert!(
            verify_hmac_at(
                &headers,
                &auth,
                "agent-1",
                psk,
                "POST",
                "/beacon",
                "",
                body,
                t0 + 1,
            )
            .await
            .is_err()
        );
        // After TTL the same (ts, mac) may be accepted again because the
        // replay entry has been evicted. The timestamp itself must still be
        // within the HMAC window relative to `now`, so re-sign at the new time.
        let t1 = t0 + REPLAY_TTL_SECONDS + 1;
        let headers2 = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "agent-1",
            t1,
            "11223344",
            body,
        );
        // Fresh request at t1 succeeds (different ts => different mac).
        assert!(
            verify_hmac_at(
                &headers2,
                &auth,
                "agent-1",
                psk,
                "POST",
                "/beacon",
                "",
                body,
                t1,
            )
            .await
            .is_ok()
        );
        // Seed an expired entry directly and confirm eviction allows a new
        // request for the same principal after TTL.
        {
            let mut cache = auth.replay.lock().await;
            let bucket = cache.seen.entry("agent-ttl".to_owned()).or_default();
            bucket.clear();
            bucket.push_back((t0, "expired-mac".to_owned()));
        }
        let headers3 = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "agent-ttl",
            t1,
            "55667788",
            body,
        );
        assert!(
            verify_hmac_at(
                &headers3,
                &auth,
                "agent-ttl",
                psk,
                "POST",
                "/beacon",
                "",
                body,
                t1,
            )
            .await
            .is_ok()
        );
        let cache = auth.replay.lock().await;
        let bucket = cache.seen.get("agent-ttl").expect("principal bucket");
        assert!(
            !bucket.iter().any(|(t, m)| *t == t0 && m == "expired-mac"),
            "stale replay entry must be evicted after TTL"
        );
    }

    #[tokio::test]
    async fn replay_principal_capacity_rejects_when_full() {
        let auth = AuthState::default();
        let psk = b"test-psk-for-hmac-cap";
        let now = 1_700_000_000i64;
        let body = b"{}";
        // Fill the principal cache to capacity with fresh entries.
        {
            let mut cache = auth.replay.lock().await;
            for i in 0..REPLAY_PRINCIPAL_CAP {
                let mut bucket = VecDeque::new();
                bucket.push_back((now, format!("mac-{i}")));
                cache.seen.insert(format!("principal-{i}"), bucket);
            }
        }
        let headers = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "new-principal",
            now,
            "99aabbcc",
            body,
        );
        let err = verify_hmac_at(
            &headers,
            &auth,
            "new-principal",
            psk,
            "POST",
            "/beacon",
            "",
            body,
            now,
        )
        .await;
        assert!(matches!(err, Err((StatusCode::SERVICE_UNAVAILABLE, _))));
    }

    #[tokio::test]
    async fn replay_principal_capacity_frees_stale_slots() {
        let auth = AuthState::default();
        let psk = b"test-psk-for-hmac-cap-free";
        let now = 1_700_000_000i64;
        let body = b"{}";
        {
            let mut cache = auth.replay.lock().await;
            for i in 0..REPLAY_PRINCIPAL_CAP {
                let mut bucket = VecDeque::new();
                // All entries older than TTL so they are eligible for eviction.
                bucket.push_back((now - REPLAY_TTL_SECONDS - 10, format!("mac-{i}")));
                cache.seen.insert(format!("stale-{i}"), bucket);
            }
        }
        let headers = signed_headers(
            psk,
            "POST",
            "/beacon",
            "",
            "fresh-principal",
            now,
            "ddeeff00",
            body,
        );
        assert!(
            verify_hmac_at(
                &headers,
                &auth,
                "fresh-principal",
                psk,
                "POST",
                "/beacon",
                "",
                body,
                now,
            )
            .await
            .is_ok(),
            "stale principals must be evicted to free capacity"
        );
    }
}
