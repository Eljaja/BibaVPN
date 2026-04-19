//! Print one `biba://` invite (same crypto as bibavpn-server --print-invite-uri).
//! Usage:
//!   export BIBA_VPN_TOKEN=... BIBA_VPN_PSK=... BIBA_INVITE_PASSPHRASE=...
//!   export INVITE_PUBLIC=host:port
//!   # optional: INVITE_SNI MAX_WS_BINARY DECOY_MAX MAX_PAD WS_PING_SECS
//!   cargo run -p bibavpn --bin bibavpn-mint-invite --release

use anyhow::Context;
use bibavpn::invite_uri::{encode_invite_v1, InviteV1};
use bibavpn::local_client::{normalize_ws_path, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u8(name: &str, default: u8) -> u8 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() -> anyhow::Result<()> {
    let public =
        std::env::var("INVITE_PUBLIC").context("set INVITE_PUBLIC=host:port")?;
    let sni = std::env::var("INVITE_SNI").unwrap_or_else(|_| {
        public
            .split_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| public.clone())
    });
    let token = std::env::var("BIBA_VPN_TOKEN").context("set BIBA_VPN_TOKEN")?;
    let psk = std::env::var("BIBA_VPN_PSK").context("set BIBA_VPN_PSK")?;
    let passphrase =
        std::env::var("BIBA_INVITE_PASSPHRASE").context("set BIBA_INVITE_PASSPHRASE")?;

    let ws_path =
        normalize_ws_path(&std::env::var("WS_PATH").unwrap_or_else(|_| "/ws".to_string()));

    let proto: u8 = std::env::var("INVITE_PROTO")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let proto_domain = std::env::var("INVITE_PROTO_DOMAIN").ok();

    let invite = InviteV1 {
        v: 1,
        server: public,
        sni,
        token,
        proto,
        proto_domain,
        psk: Some(psk),
        decoy_max: env_u8("DECOY_MAX", 32),
        max_pad: env_u8("MAX_PAD", 64),
        max_ws_binary: env_usize("MAX_WS_BINARY", 262_144),
        ws_ping_secs: env_u64("WS_PING_SECS", 25),
        ws_ping_jitter_percent: env_u8("WS_PING_JITTER_PERCENT", 0),
        ws_binary_send_jitter_ms: env_u8("WS_BINARY_SEND_JITTER_MS", 0),
        udp_max_pad: None,
        udp_max_ws_binary: None,
        udp_mux_reply_timeout_secs: DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
        insecure: true,
        tls_profile: "default".into(),
        ws_path: Some(ws_path),
        pad_mode: Some("random".into()),
        dummy_interval_secs: None,
    };

    println!("{}", encode_invite_v1(&invite, &passphrase)?);
    Ok(())
}
