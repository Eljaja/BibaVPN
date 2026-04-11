//! `biba://` invite links: ChaCha20-Poly1305 encrypted JSON (key from BLAKE3 KDF on a passphrase).

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blake3::derive_key;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const BLOB_VERSION: u8 = 1;
const KDF_CONTEXT: &str = "bibavpn.invite.uri.v1";
const NONCE_LEN: usize = 12;
const PREFIX: &str = "biba://";

/// Wire payload after decryption (JSON).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteV1 {
    /// Always `1` for this struct layout.
    pub v: u8,
    /// Client `--server host:port` (reachable address).
    pub server: String,
    /// TLS SNI and default WS trust name.
    pub sni: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    pub decoy_max: u8,
    pub max_pad: u8,
    pub max_ws_binary: usize,
    pub ws_ping_secs: u64,
    #[serde(default)]
    pub ws_ping_jitter_percent: u8,
    #[serde(default)]
    pub ws_binary_send_jitter_ms: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_max_pad: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_max_ws_binary: Option<usize>,
    #[serde(default = "default_udp_mux_reply_timeout_secs")]
    pub udp_mux_reply_timeout_secs: u64,
    /// Set when the server uses demo self-signed TLS; client should use `--insecure` or pin.
    pub insecure: bool,
    #[serde(default = "default_tls_profile")]
    pub tls_profile: String,
    /// WebSocket HTTP path (default `/ws`). Omit in JSON for backward compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
    /// `random` or `http-buckets` (padding mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad_mode: Option<String>,
    /// Idle dummy WSS frames interval seconds (`0` = off).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dummy_interval_secs: Option<u64>,
}

fn default_tls_profile() -> String {
    "default".to_string()
}

fn default_udp_mux_reply_timeout_secs() -> u64 {
    130
}

fn cipher_from_passphrase(passphrase: &[u8]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new_from_slice(&derive_key(KDF_CONTEXT, passphrase))
        .expect("ChaCha20Poly1305 key length")
}

/// `biba://` + URL-safe base64 of `version || nonce(12) || ciphertext`.
pub fn encode_invite_v1(invite: &InviteV1, passphrase: &str) -> anyhow::Result<String> {
    let plain = serde_json::to_vec(invite).context("invite json")?;
    let cipher = cipher_from_passphrase(passphrase.as_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|e| anyhow::anyhow!("encrypt invite: {e}"))?;

    let mut wire = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    wire.push(BLOB_VERSION);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct);

    Ok(format!("{}{}", PREFIX, URL_SAFE_NO_PAD.encode(wire)))
}

/// Decode `biba://...` or raw base64 payload.
pub fn decode_invite_v1(uri: &str, passphrase: &str) -> anyhow::Result<InviteV1> {
    let s = uri.trim();
    let b64 = s
        .strip_prefix(PREFIX)
        .or_else(|| s.strip_prefix("biba:"))
        .unwrap_or(s);
    let wire = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .context("invite: invalid base64url")?;
    if wire.is_empty() || wire[0] != BLOB_VERSION {
        anyhow::bail!("invite: unsupported blob version");
    }
    if wire.len() < 1 + NONCE_LEN + 16 {
        anyhow::bail!("invite: blob too short");
    }
    let nonce = &wire[1..1 + NONCE_LEN];
    let ct = &wire[1 + NONCE_LEN..];
    let cipher = cipher_from_passphrase(passphrase.as_bytes());
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("invite: bad passphrase or corrupted blob"))?;
    let invite: InviteV1 = serde_json::from_slice(&plain).context("invite: bad json")?;
    if invite.v != BLOB_VERSION {
        anyhow::bail!("invite: inner v mismatch");
    }
    Ok(invite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let i = InviteV1 {
            v: 1,
            server: "203.0.113.7:8443".into(),
            sni: "vpn.example.com".into(),
            token: "tok".into(),
            psk: Some("sec".into()),
            decoy_max: 8,
            max_pad: 64,
            max_ws_binary: 1400,
            ws_ping_secs: 25,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            udp_max_pad: None,
            udp_max_ws_binary: None,
            udp_mux_reply_timeout_secs: 130,
            insecure: true,
            tls_profile: "default".into(),
            ws_path: None,
            pad_mode: None,
            dummy_interval_secs: None,
        };
        let u = encode_invite_v1(&i, "pass").unwrap();
        assert!(u.starts_with(PREFIX));
        let j = decode_invite_v1(&u, "pass").unwrap();
        assert_eq!(i, j);
    }
}
