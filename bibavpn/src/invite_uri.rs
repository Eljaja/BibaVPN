//! `biba://` invite links: ChaCha20-Poly1305 encrypted JSON (key from BLAKE3 KDF on a passphrase).

use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake3::derive_key;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const BLOB_VERSION: u8 = 1;
const KDF_CONTEXT: &str = "bibavpn.invite.uri.v1";
const NONCE_LEN: usize = 12;
const PREFIX: &str = "biba://";

// --- serde default helpers (backward compatible: old JSON omits these) ---

fn default_u32_0() -> u32 {
    0
}
fn default_u8_0() -> u8 {
    0
}
fn default_bool_false() -> bool {
    false
}
fn default_use_tcp_mux() -> bool {
    true
}
fn default_decoy_gets_interval() -> u64 {
    30
}
fn default_ws_parallel() -> u8 {
    1
}
fn default_tls_stack_str() -> String {
    "rustls".to_string()
}

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
    /// Wire protocol: only `3` (opaque PSK hello + sealed control).
    #[serde(default = "default_invite_proto")]
    pub proto: u8,
    /// Domain label for v3 PSK KDF (omit to let client default to SNI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto_domain: Option<String>,
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
    /// Outbound WS send delay: random ms in `min..=max` when both set; else `ws_binary_send_jitter_ms` only.
    #[serde(default)]
    pub ws_jitter_min_ms: u8,
    #[serde(default)]
    pub ws_jitter_max_ms: u8,
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
    /// `adaptive` / `random` / `http-buckets` (padding mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad_mode: Option<String>,
    /// Idle dummy WSS frames interval seconds (`0` = off).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dummy_interval_secs: Option<u64>,

    // ---- Extended (optional in old invites; JSON omits) ----
    /// Local HTTP CONNECT bind (e.g. `127.0.0.1:8080`); omit to let client use its default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_proxy: Option<String>,
    /// Local SOCKS5 bind; omit to use client default (e.g. `127.0.0.1:1080`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_bind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_auth_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_auth_password: Option<String>,

    #[serde(default = "default_u32_0")]
    pub junk_frames: u32,
    #[serde(default = "default_u8_0")]
    pub early_ws_frames: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_accept_language: Option<String>,
    /// Each entry `Name: value` (BibaV2.1), same as `--ws-header`.
    #[serde(default)]
    pub ws_headers: Vec<String>,

    #[serde(default = "default_use_tcp_mux")]
    pub use_tcp_mux: bool,

    #[serde(default = "default_bool_false")]
    pub decoy_gets: bool,
    #[serde(default = "default_decoy_gets_interval")]
    pub decoy_gets_interval_secs: u64,
    /// Comma-separated paths, same as `--decoy-gets-paths`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_gets_paths: Option<String>,

    /// Same names as `--fingerprint` (e.g. `chrome-132`). If set, preferred over `tls_profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// `default` | `balanced` | `aggressive`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stealth_profile: Option<String>,
    /// `simple` | `browser`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desync_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fooling: Option<String>,
    #[serde(default = "default_bool_false")]
    pub tls_fragment: bool,
    #[serde(default = "default_ws_parallel")]
    pub ws_parallel: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_decoy_secs: Option<u64>,
    /// `rustls` or `boring` (Boring build required).
    #[serde(default = "default_tls_stack_str")]
    pub tls_stack: String,

    /// REALITY: front host for SNI (e.g. `vk.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_target: Option<String>,
    /// X25519 server public key, **standard** base64, 32 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_public_key: Option<String>,
    /// 16 hex digits (8 bytes) or omit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_short_id: Option<String>,

    /// Optional PEM of pinned leaf/chain (encrypted inside blob with passphrase).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_cert_pem: Option<String>,

    /// Hints to match the server (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ack_delay_min_ms: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ack_delay_max_ms: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_mask_jitter_ms: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_profile: Option<String>,
}

impl InviteV1 {
    /// X25519 public key from `reality_public_key` (Standard base64, 32 bytes), if present.
    pub fn reality_public_key_parsed(
        &self,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let Some(s) = self
            .reality_public_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let bytes = STANDARD
            .decode(s)
            .context("reality_public_key: invalid base64")?;
        if bytes.len() != 32 {
            anyhow::bail!("reality_public_key: expected 32 bytes, got {}", bytes.len());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    /// Short ID: 16 hex digits (8 bytes) or None.
    pub fn reality_short_id_parsed(&self) -> anyhow::Result<Option<[u8; 8]>> {
        let Some(s) = self
            .reality_short_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let bytes = hex::decode(s).context("reality_short_id: invalid hex")?;
        if bytes.len() != 8 {
            anyhow::bail!("reality_short_id: need 8 bytes (16 hex digits)");
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }
}

fn default_invite_proto() -> u8 {
    3
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
            proto: 3,
            proto_domain: None,
            psk: Some("sec".into()),
            decoy_max: 8,
            max_pad: 64,
            max_ws_binary: 1400,
            ws_ping_secs: 25,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            udp_max_pad: None,
            udp_max_ws_binary: None,
            udp_mux_reply_timeout_secs: 130,
            insecure: true,
            tls_profile: "default".into(),
            ws_path: None,
            pad_mode: None,
            dummy_interval_secs: None,
            http_proxy: None,
            socks_bind: None,
            socks_auth_user: None,
            socks_auth_password: None,
            junk_frames: 0,
            early_ws_frames: 0,
            ws_host: None,
            ws_origin: None,
            ws_user_agent: None,
            ws_accept_language: None,
            ws_headers: vec![],
            use_tcp_mux: true,
            decoy_gets: false,
            decoy_gets_interval_secs: 30,
            decoy_gets_paths: None,
            fingerprint: None,
            stealth_profile: None,
            decoy_mode: None,
            desync_mode: None,
            tcp_fooling: None,
            tls_fragment: false,
            ws_parallel: 1,
            idle_decoy_secs: None,
            tls_stack: "rustls".into(),
            reality_target: None,
            reality_public_key: None,
            reality_short_id: None,
            pin_cert_pem: None,
            server_ack_delay_min_ms: None,
            server_ack_delay_max_ms: None,
            rtt_mask_jitter_ms: None,
            ack_profile: None,
        };
        let u = encode_invite_v1(&i, "pass").unwrap();
        assert!(u.starts_with(PREFIX));
        let j = decode_invite_v1(&u, "pass").unwrap();
        assert_eq!(i, j);
    }

    #[test]
    fn old_minimal_json_still_parses() {
        let json = br#"{"v":1,"server":"h:1","sni":"h","token":"t","proto":3,"psk":"p","decoy_max":0,"max_pad":64,"max_ws_binary":1400,"ws_ping_secs":25,"udp_mux_reply_timeout_secs":130,"insecure":true,"tls_profile":"default"}"#;
        let invite: InviteV1 = serde_json::from_slice(json).unwrap();
        assert_eq!(invite.junk_frames, 0);
        assert_eq!(invite.tls_stack, "rustls");
        assert!(invite.use_tcp_mux);
    }
}
