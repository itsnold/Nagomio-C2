//! End-to-end encryption of agent/server wire bodies using ChaCha20-Poly1305.
//!
//! Both endpoints derive the same 256-bit key from a PSK via HKDF-SHA256 with a
//! per-direction `info` string. The wire body becomes a `WireEnvelope` JSON
//! object (see `shared::WireEnvelope`); everything *around* it (HTTP headers,
//! routing) stays in cleartext. This defeats the JSON beacon signature even
//! when a blue-team proxy intercepts TLS.
//!
//! Key derivation is RFC 5869 HKDF-SHA256:
//! - salt = empty / HashLen zero bytes (equivalent for SHA-256)
//! - IKM  = PSK bytes
//! - info = directional context (`CTX_AGENT` / `CTX_SERVER`)
//! - L    = 32
//!
//! C++ agent (OpenSSL on Linux, BCrypt HMAC+HKDF on Windows) must match these
//! vectors bit-for-bit. See `wire::tests` known-answer constants and
//! `agent/tests/wire_kat.cpp`.

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
    // `None` salt == HashLen zeros per RFC 5869; matches OpenSSL salt=[0;32]
    // and the Windows BCrypt HKDF path.
    let hk = Hkdf::<Sha256>::new(None, psk);
    let mut okm = [0u8; 32];
    hk.expand(ctx.as_bytes(), &mut okm)
        .expect("HKDF accepts a 32-byte output");
    okm
}

/// Seal with a fixed 12-byte nonce (interop / known-answer tests only).
pub fn seal_with_nonce(
    psk: &[u8],
    ctx: &str,
    plaintext: &[u8],
    nonce_bytes: &[u8; 12],
) -> Result<String, String> {
    let key = derive_key(psk, ctx);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: ctx.as_bytes(),
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;
    let (ciphertext, tag) = ct.split_at(ct.len() - 16);
    let envelope = WireEnvelope {
        nonce: b64e(nonce_bytes.as_slice()),
        ct: b64e(ciphertext),
        tag: b64e(tag),
        ctx: ctx.to_owned(),
    };
    serde_json::to_string(&envelope).map_err(|e| format!("serialize envelope: {e}"))
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

/// Open a sealed envelope. When `expected_ctx` is `Some`, the envelope's
/// claimed context must match exactly (prevents direction-context swaps).
pub fn open(psk: &[u8], envelope: &WireEnvelope) -> Result<Vec<u8>, String> {
    open_with_ctx(psk, envelope, None)
}

/// Open a sealed envelope requiring a specific directional context.
pub fn open_with_ctx(
    psk: &[u8],
    envelope: &WireEnvelope,
    expected_ctx: Option<&str>,
) -> Result<Vec<u8>, String> {
    if envelope.ctx.is_empty() {
        return Err("envelope is missing ctx".into());
    }
    if let Some(expected) = expected_ctx {
        if envelope.ctx != expected {
            return Err(format!(
                "unexpected wire context: got {:?}, expected {:?}",
                envelope.ctx, expected
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with `agent/tests/wire_kat.cpp` — do not change without updating both.
    const KAT_PSK: &[u8] = b"test-psk-for-wire-vectors";
    const KAT_PLAIN: &[u8] = br#"{"agent_id":"agent-1","hostname":"box"}"#;
    const KAT_NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    // HKDF-SHA256(ikm=KAT_PSK, salt=empty/HashLen zeros, info=ctx)[..32]
    const KAT_KEY_AGENT: &str =
        "f49485c7a72f33d166b1f56639f35232d3b6c51d36c7f39b79a29436b8f54220";
    const KAT_KEY_SERVER: &str =
        "de251781fcdaeb2f54088836e77124f6edbe802c19e7bf126c9551ae8c4b7db2";

    // ChaCha20-Poly1305 with KAT_NONCE, AAD=ctx
    const KAT_CT_AGENT: &str =
        "a2e08a54a6c8f4c349bb143123855a7b421f6d2e696bca889af377179d43b02b4a7eb1a65a7253";
    const KAT_TAG_AGENT: &str = "dfdaebf57cdb20a24e950a9d5fdc0327";
    const KAT_CT_SERVER: &str =
        "189fd8125d10dd6d75902b7cafb5911f0ff8c3f8115bcfa9840031e88d9ed3be025dd8a0231f8d";
    const KAT_TAG_SERVER: &str = "1a2d70a9df0445c5e8d80ff556e3dce4";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn derive_key_matches_shared_kat_agent() {
        assert_eq!(hex(&derive_key(KAT_PSK, CTX_AGENT)), KAT_KEY_AGENT);
    }

    #[test]
    fn derive_key_matches_shared_kat_server() {
        assert_eq!(hex(&derive_key(KAT_PSK, CTX_SERVER)), KAT_KEY_SERVER);
    }

    #[test]
    fn seal_with_nonce_matches_shared_kat_agent() {
        let sealed =
            seal_with_nonce(KAT_PSK, CTX_AGENT, KAT_PLAIN, &KAT_NONCE).expect("seal");
        let env: WireEnvelope = serde_json::from_str(&sealed).expect("json");
        assert_eq!(env.ctx, CTX_AGENT);
        assert_eq!(hex(&b64d(&env.nonce).unwrap()), hex(&KAT_NONCE));
        assert_eq!(hex(&b64d(&env.ct).unwrap()), KAT_CT_AGENT);
        assert_eq!(hex(&b64d(&env.tag).unwrap()), KAT_TAG_AGENT);
    }

    #[test]
    fn seal_with_nonce_matches_shared_kat_server() {
        let sealed =
            seal_with_nonce(KAT_PSK, CTX_SERVER, KAT_PLAIN, &KAT_NONCE).expect("seal");
        let env: WireEnvelope = serde_json::from_str(&sealed).expect("json");
        assert_eq!(hex(&b64d(&env.ct).unwrap()), KAT_CT_SERVER);
        assert_eq!(hex(&b64d(&env.tag).unwrap()), KAT_TAG_SERVER);
    }

    #[test]
    fn open_shared_kat_agent_envelope() {
        let env = WireEnvelope {
            nonce: b64e(&KAT_NONCE),
            ct: b64e(&unhex(KAT_CT_AGENT)),
            tag: b64e(&unhex(KAT_TAG_AGENT)),
            ctx: CTX_AGENT.to_owned(),
        };
        let plain = open_with_ctx(KAT_PSK, &env, Some(CTX_AGENT)).expect("open");
        assert_eq!(plain, KAT_PLAIN);
    }

    #[test]
    fn open_rejects_wrong_direction_ctx() {
        let env = WireEnvelope {
            nonce: b64e(&KAT_NONCE),
            ct: b64e(&unhex(KAT_CT_AGENT)),
            tag: b64e(&unhex(KAT_TAG_AGENT)),
            ctx: CTX_AGENT.to_owned(),
        };
        assert!(open_with_ctx(KAT_PSK, &env, Some(CTX_SERVER)).is_err());
    }

    #[test]
    fn open_rejects_mutated_ciphertext() {
        let mut ct = unhex(KAT_CT_AGENT);
        ct[0] ^= 0x01;
        let env = WireEnvelope {
            nonce: b64e(&KAT_NONCE),
            ct: b64e(&ct),
            tag: b64e(&unhex(KAT_TAG_AGENT)),
            ctx: CTX_AGENT.to_owned(),
        };
        assert!(open(KAT_PSK, &env).is_err());
    }
}