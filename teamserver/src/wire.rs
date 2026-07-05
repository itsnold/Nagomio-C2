//! End-to-end encryption of agent/server wire bodies using ChaCha20-Poly1305.
//!
//! Both endpoints derive the same 256-bit key from a PSK via HKDF-SHA256 with a
//! per-direction `info` string. The wire body becomes a `WireEnvelope` JSON
//! object (see `shared::WireEnvelope`); everything *around* it (HTTP headers,
//! routing) stays in cleartext. This defeats the JSON beacon signature even
//! when a blue-team proxy intercepts TLS.

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::Arc;

use crate::SharedState;
use shared::WireEnvelope;

/// HKDF `info` for keys used to seal agent -> server bodies.
pub const CTX_AGENT: &str = "nagomio/agent/v1";
/// HKDF `info` for keys used to seal server -> agent bodies.
pub const CTX_SERVER: &str = "nagomio/server/v1";

/// Derive a 256-bit ChaCha20-Poly1305 key from a PSK and a context string.
pub fn derive_key(psk: &[u8], ctx: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, psk);
    let mut okm = [0u8; 32];
    hk.expand(ctx.as_bytes(), &mut okm)
        .expect("HKDF accepts a 32-byte output");
    okm
}

fn b64e(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn b64d(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}

/// Seal a plaintext JSON body. `ctx` selects the directional key
/// (CTX_AGENT or CTX_SERVER).
pub fn seal(psk: &[u8], ctx: &str, plaintext: &[u8]) -> Result<String, String> {
    let key = derive_key(psk, ctx);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: ctx.as_bytes() })
        .map_err(|e| format!("encrypt: {e}"))?;
    // chacha20poly1305 appends the 16-byte tag to the ciphertext.
    let (ciphertext, tag) = ct.split_at(ct.len() - 16);
    let envelope = WireEnvelope {
        nonce: b64e(nonce_bytes.as_slice()),
        ct: b64e(ciphertext),
        tag: b64e(tag),
        ctx: ctx.to_owned(),
    };
    serde_json::to_string(&envelope).map_err(|e| format!("serialize envelope: {e}"))
}

/// Open a sealed envelope. `ctx` must match the context the sealer used.
pub fn open(psk: &[u8], envelope: &WireEnvelope) -> Result<Vec<u8>, String> {
    if envelope.ctx.is_empty() {
        return Err("envelope is missing ctx".into());
    }
    let key = derive_key(psk, &envelope.ctx);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce_bytes = b64d(&envelope.nonce).map_err(|e| format!("nonce b64: {e}"))?;
    if nonce_bytes.len() != 12 {
        return Err("nonce must be 12 bytes".into());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = b64d(&envelope.ct).map_err(|e| format!("ct b64: {e}"))?;
    let tag = b64d(&envelope.tag).map_err(|e| format!("tag b64: {e}"))?;
    if tag.len() != 16 {
        return Err("tag must be 16 bytes".into());
    }
    let mut combined = ciphertext;
    combined.extend_from_slice(&tag);
    cipher
        .decrypt(nonce, Payload { msg: &combined, aad: envelope.ctx.as_bytes() })
        .map_err(|e| format!("decrypt: {e}"))
}

/// Try to parse a body as a WireEnvelope. If `wire_encryption` is disabled on
/// the server, returns `None`.
pub fn maybe_unwrap_envelope(body: &str) -> Option<WireEnvelope> {
    if body.trim_start().starts_with('{') {
        // Distinguish a WireEnvelope from other JSON bodies by required fields.
        if let Ok(env) = serde_json::from_str::<WireEnvelope>(body) {
            if !env.nonce.is_empty() && !env.ct.is_empty() && !env.tag.is_empty() {
                return Some(env);
            }
        }
    }
    None
}

/// Helper used by handlers: returns the PSK + wire-encryption flag from the
/// shared state.
pub async fn server_agent_psk(state: &SharedState) -> (Option<Arc<[u8]>>, bool) {
    let s = state.lock().await;
    (
        s.config.agent_psk.as_ref().map(|p| Arc::from(p.as_bytes())),
        s.config.wire_encryption,
    )
}

pub async fn server_operator_psk(state: &SharedState) -> Option<Arc<[u8]>> {
    let s = state.lock().await;
    s.config.api_psk.as_ref().map(|p| Arc::from(p.as_bytes()))
}