//! Print one `biba://` invite (same crypto as bibavpn-server --print-invite-uri).
//! Usage:
//!   export BIBA_VPN_TOKEN=... BIBA_VPN_PSK=... BIBA_INVITE_PASSPHRASE=...
//!   export INVITE_PUBLIC=host:port
//!   # optional: INVITE_SNI MAX_WS_BINARY DECOY_MAX MAX_PAD WS_PING_SECS
//!   cargo run -p bibavpn --bin bibavpn-mint-invite --release

use anyhow::Context;
use bibavpn::invite_uri::{encode_invite_v1, InviteV1};
use bibavpn::local_client::{
    normalize_ws_path, parse_host_port, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use bibavpn::startup_secrets::{resolve_cli_token, validate_psk};

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

/// Strict bool parsing for env flags: only `1`/`true` and `0`/`false`
/// (ASCII case-insensitive, surrounding whitespace ignored). Anything else is `None`.
fn parse_bool_strict(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

/// `BIBA_INVITE_INSECURE` is opt-in: only an explicit `1`/`true` disables TLS
/// verification. Unset, empty, or malformed values keep verification enabled.
fn invite_insecure_from_env(raw: Option<&str>) -> bool {
    raw.and_then(parse_bool_strict).unwrap_or(false)
}

/// Default SNI for an invite: the host part of `host:port` (IPv6-safe), or the
/// raw value when it cannot be parsed (the caller validates the public address).
fn default_sni(public: &str) -> String {
    parse_host_port(public.trim())
        .map(|(host, _)| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string()
        })
        .unwrap_or_else(|_| public.to_string())
}

fn main() -> anyhow::Result<()> {
    let public = std::env::var("INVITE_PUBLIC").context("set INVITE_PUBLIC=host:port")?;
    parse_host_port(public.trim()).context("INVITE_PUBLIC must be host:port")?;
    let sni = std::env::var("INVITE_SNI").unwrap_or_else(|_| default_sni(&public));
    let token = std::env::var("BIBA_VPN_TOKEN").context("set BIBA_VPN_TOKEN")?;
    let token = resolve_cli_token(Some(token.as_str()), false).context("BIBA_VPN_TOKEN")?;
    let psk = std::env::var("BIBA_VPN_PSK").context("set BIBA_VPN_PSK")?;
    validate_psk(&psk).context("BIBA_VPN_PSK")?;
    let passphrase =
        std::env::var("BIBA_INVITE_PASSPHRASE").context("set BIBA_INVITE_PASSPHRASE")?;
    anyhow::ensure!(
        passphrase.trim().chars().count() >= 8,
        "BIBA_INVITE_PASSPHRASE must be at least 8 characters"
    );

    let ws_path =
        normalize_ws_path(&std::env::var("WS_PATH").unwrap_or_else(|_| "/ws".to_string()));

    let proto: u8 = std::env::var("INVITE_PROTO")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    anyhow::ensure!(
        proto == 3,
        "only Biba protocol v3 is supported (set INVITE_PROTO=3)"
    );
    let proto_domain = std::env::var("INVITE_PROTO_DOMAIN")
        .ok()
        .or_else(|| Some("default".to_string()));

    let pin_cert_pem = std::env::var_os("INVITE_PIN_CERT_FILE")
        .map(|path| std::fs::read_to_string(path).context("read INVITE_PIN_CERT_FILE"))
        .transpose()?;
    if pin_cert_pem.as_ref().is_some_and(|pem| pem.trim().is_empty()) {
        anyhow::bail!("INVITE_PIN_CERT_FILE is empty");
    }

    let invite = InviteV1 {
        v: 1,
        server: public,
        yb_mesh: std::env::var("BIBA_YB_MESH_ENDPOINT").ok().filter(|s| !s.trim().is_empty()).map(|endpoint| {
            bibavpn::yb_mesh::parse_endpoint(&endpoint)?;
            Ok::<_, anyhow::Error>(bibavpn::invite_uri::YbMeshInvite { endpoint })
        }).transpose()?,
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
        ws_jitter_min_ms: env_u8("WS_JITTER_MIN_MS", 0),
        ws_jitter_max_ms: env_u8("WS_JITTER_MAX_MS", 0),
        udp_max_pad: None,
        udp_max_ws_binary: None,
        udp_mux_reply_timeout_secs: DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
        // Pinned invites verify the pin; only unpinned invites may opt into insecure TLS.
        insecure: pin_cert_pem.is_none()
            && invite_insecure_from_env(std::env::var("BIBA_INVITE_INSECURE").ok().as_deref()),
        tls_profile: "default".into(),
        ws_path: Some(ws_path),
        pad_mode: Some("random".into()),
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
        tls_stack: "rustls".to_string(),
        reality_target: std::env::var("INVITE_REALITY_TARGET").ok().filter(|s| !s.trim().is_empty()),
        reality_public_key: std::env::var("INVITE_REALITY_PUBLIC_KEY").ok().filter(|s| !s.trim().is_empty()),
        reality_short_id: std::env::var("INVITE_REALITY_SHORT_ID").ok().filter(|s| !s.trim().is_empty()),
        pin_cert_pem,
        server_ack_delay_min_ms: None,
        server_ack_delay_max_ms: None,
        rtt_mask_jitter_ms: None,
        ack_profile: None,
    };

    if invite.reality_target.is_some() || invite.reality_public_key.is_some() || invite.reality_short_id.is_some() {
        anyhow::ensure!(invite.reality_target.is_some() && invite.reality_public_key.is_some(), "REALITY invites require INVITE_REALITY_TARGET and INVITE_REALITY_PUBLIC_KEY");
        invite.reality_public_key_parsed()?;
        invite.reality_short_id_parsed()?;
    }
    println!("{}", encode_invite_v1(&invite, &passphrase)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sni_handles_ipv4_and_ipv6() {
        assert_eq!(default_sni("vpn.example:443"), "vpn.example");
        assert_eq!(default_sni("203.0.113.7:8443"), "203.0.113.7");
        assert_eq!(default_sni("[2001:db8::1]:8443"), "2001:db8::1");
        assert_eq!(default_sni("vpn.example"), "vpn.example");
    }

    #[test]
    fn strict_bool_parse_only_accepts_explicit_values() {
        assert_eq!(parse_bool_strict("1"), Some(true));
        assert_eq!(parse_bool_strict("true"), Some(true));
        assert_eq!(parse_bool_strict("TRUE"), Some(true));
        assert_eq!(parse_bool_strict(" true "), Some(true));
        assert_eq!(parse_bool_strict("0"), Some(false));
        assert_eq!(parse_bool_strict("false"), Some(false));
        for raw in ["", " ", "yes", "on", "2", "true-ish", "no"] {
            assert_eq!(parse_bool_strict(raw), None, "raw={raw:?}");
        }
    }

    #[test]
    fn invite_insecure_is_fail_closed() {
        assert!(!invite_insecure_from_env(None));
        assert!(!invite_insecure_from_env(Some("")));
        assert!(!invite_insecure_from_env(Some("false")));
        assert!(!invite_insecure_from_env(Some("yes")));
        assert!(invite_insecure_from_env(Some("1")));
        assert!(invite_insecure_from_env(Some("true")));
    }
}
