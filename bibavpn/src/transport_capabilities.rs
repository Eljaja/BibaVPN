//! Summarize which client-side stealth knobs actually apply in this build.

use tracing::warn;

use crate::local_client::LocalClientOptions;
use crate::startup_secrets::client_reality_configured;
use crate::stealth_v12::DesyncMode;
use crate::tcp_mux::MuxWindow;
use crate::tls_util::TlsStack;

/// Whether a desync mode is enforced in-process or advisory-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesyncApplied {
    Advisory,
}

pub fn effective_desync_mode(mode: DesyncMode) -> DesyncApplied {
    let _ = mode;
    DesyncApplied::Advisory
}

/// Effective client configuration fields (no secrets) for logging and unit tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EffectiveConfigSnapshot {
    pub mux_window_bytes: u32,
    pub ws_parallel: u8,
    pub use_tcp_mux: bool,
    pub psk: bool,
    pub reality: bool,
    pub max_ws_binary: usize,
    pub max_pad: u8,
    pub dummy_interval_secs: u64,
    pub version: &'static str,
}

pub(crate) fn client_effective_config_snapshot(
    opts: &LocalClientOptions,
    ws_parallel: u8,
) -> EffectiveConfigSnapshot {
    EffectiveConfigSnapshot {
        mux_window_bytes: opts.mux_window_mib.bytes(),
        ws_parallel,
        use_tcp_mux: opts.use_tcp_mux,
        psk: opts
            .psk
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false),
        reality: client_reality_configured(
            opts.reality_target.as_deref(),
            opts.reality_public_key.as_ref(),
        ),
        max_ws_binary: opts.max_ws_binary,
        max_pad: opts.max_pad,
        dummy_interval_secs: opts.dummy_interval_secs,
        version: env!("CARGO_PKG_VERSION"),
    }
}

/// Effective server listen configuration fields (no secrets) for logging and unit tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerEffectiveConfigSnapshot {
    pub mux_window_bytes: u32,
    pub max_ws_binary: usize,
    pub max_pad: u8,
    pub dummy_interval_secs: u64,
    pub psk: bool,
    pub reality: bool,
    pub version: &'static str,
}

pub(crate) fn server_effective_config_snapshot(
    mux_window_mib: MuxWindow,
    max_pad: u8,
    max_ws_binary: usize,
    dummy_interval_secs: u64,
    psk_present: bool,
    reality_present: bool,
) -> ServerEffectiveConfigSnapshot {
    ServerEffectiveConfigSnapshot {
        mux_window_bytes: mux_window_mib.bytes(),
        max_ws_binary,
        max_pad,
        dummy_interval_secs,
        psk: psk_present,
        reality: reality_present,
        version: env!("CARGO_PKG_VERSION"),
    }
}

const EFFECTIVE_CONFIG_NOTE: &str =
    "effective config: download throughput is limited by the client advertised receive window; upload by the server advertised receive window";

/// One-line summary when the entry server starts accepting connections.
pub fn log_server_listen_caps(
    legacy_path_auth: bool,
    auth_rate_limit_enabled: bool,
    max_concurrent_sessions: usize,
    udp_socket_pool_size: usize,
    mux_window_mib: MuxWindow,
    max_pad: u8,
    max_ws_binary: usize,
    dummy_interval_secs: u64,
    psk_present: bool,
    reality_present: bool,
) {
    let cap = if max_concurrent_sessions == 0 {
        "unlimited".to_string()
    } else {
        max_concurrent_sessions.to_string()
    };
    tracing::info!(
        target: "bibavpn_server",
        legacy_path_auth,
        auth_rate_limit = auth_rate_limit_enabled,
        max_concurrent_sessions = %cap,
        udp_socket_pool_size,
        "listen: session hardening (see --max-concurrent-sessions / --udp-socket-pool-size)"
    );
    let snap = server_effective_config_snapshot(
        mux_window_mib,
        max_pad,
        max_ws_binary,
        dummy_interval_secs,
        psk_present,
        reality_present,
    );
    tracing::info!(
        target: "bibavpn_server",
        mux_window_bytes = snap.mux_window_bytes,
        max_ws_binary = snap.max_ws_binary,
        max_pad = snap.max_pad,
        dummy_interval_secs = snap.dummy_interval_secs,
        psk = snap.psk,
        reality = snap.reality,
        version = snap.version,
        "{EFFECTIVE_CONFIG_NOTE}"
    );
    if legacy_path_auth {
        warn!(
            target: "bibavpn_security",
            "legacy path auth is enabled; use AUTH frame + standard path for production"
        );
    }
}

fn tls_stack_str(stack: TlsStack) -> &'static str {
    match stack {
        TlsStack::Rustls => "rustls",
        TlsStack::Boring => "boring",
    }
}

/// Log after `LocalClientOptions` is fully resolved (CLI / invite / JSON).
pub fn log_client_transport_caps(opts: &LocalClientOptions, ws_parallel: u8) {
    let snap = client_effective_config_snapshot(opts, ws_parallel);
    tracing::info!(
        target: "bibavpn_client",
        mux_window_bytes = snap.mux_window_bytes,
        ws_parallel = snap.ws_parallel,
        use_tcp_mux = snap.use_tcp_mux,
        psk = snap.psk,
        reality = snap.reality,
        max_ws_binary = snap.max_ws_binary,
        max_pad = snap.max_pad,
        dummy_interval_secs = snap.dummy_interval_secs,
        version = snap.version,
        "{EFFECTIVE_CONFIG_NOTE}"
    );

    let stack = tls_stack_str(opts.tls_stack);
    let pin = opts
        .pinned_certs_pem
        .as_ref()
        .map(|b| !b.is_empty())
        .unwrap_or(false);

    tracing::info!(
        target: "bibavpn_client",
        tls_stack = stack,
        desync_mode = ?opts.desync_mode,
        tcp_fooling = ?opts.tcp_fooling,
        tls_fragment_requested = opts.tls_fragment,
        pin_cert_configured = pin,
        "transport: desync/tcp-fooling are advisory; tls-fragment applies on boring stack; pin-cert works on rustls and boring"
    );

    if opts.desync_mode != DesyncMode::Off {
        warn!(
            target: "bibavpn_stealth",
            desync_mode = ?opts.desync_mode,
            "desync modes are not applied in-process; use an external helper (e.g. zapret) if needed"
        );
    }
    if opts.tls_fragment && matches!(opts.tls_stack, TlsStack::Rustls) {
        warn!(
            target: "bibavpn_stealth",
            "tls-fragment is not implemented for rustls; boring stack may enable record sizing when built with boring-tls"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::frame::PadMode;
    use crate::stealth_v12::{DecoyMode, DesyncMode, TcpFooling};
    use crate::tcp_mux::MuxWindow;
    use crate::tls_util::TlsClientProfile;

    use super::*;

    fn test_client_opts(
        mux_window_mib: MuxWindow,
        ws_parallel: u8,
        use_tcp_mux: bool,
        psk: Option<&str>,
        reality_target: Option<&str>,
        reality_public_key: Option<[u8; 32]>,
    ) -> LocalClientOptions {
        LocalClientOptions {
            server_host: "example.com".into(),
            server_port: 8443,
            sni: "example.com".into(),
            token: "super-secret-token".into(),
            socks_bind: "127.0.0.1:1080".into(),
            socks_auth: None,
            http_proxy_bind: None,
            insecure_tls: false,
            max_pad: 64,
            junk_frames: 0,
            early_ws_frames: 0,
            psk: psk.map(str::to_string),
            decoy_max: 32,
            ws_host: None,
            ws_origin: None,
            ws_user_agent: None,
            ws_accept_language: None,
            ws_extra_headers: Arc::new(Vec::new()),
            max_ws_binary: 1400,
            ws_ping_secs: 25,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            udp_max_pad: None,
            udp_max_ws_binary: None,
            udp_mux_reply_timeout_secs: 0,
            tls_profile: TlsClientProfile::Default,
            pinned_certs_pem: None,
            ws_path: "/ws".into(),
            use_tcp_mux,
            pad_mode: PadMode::Adaptive,
            dummy_interval_secs: 30,
            decoy_gets: false,
            decoy_gets_interval_secs: 0,
            decoy_gets_paths: Vec::new(),
            proto: 3,
            proto_domain: String::new(),
            reality_target: reality_target.map(str::to_string),
            reality_public_key,
            reality_short_id: None,
            decoy_mode: DecoyMode::default(),
            desync_mode: DesyncMode::default(),
            tcp_fooling: TcpFooling::default(),
            tls_fragment: false,
            ws_parallel,
            mux_window_mib,
            idle_decoy_secs: 0,
            stealth_profile: None,
            tls_stack: TlsStack::Rustls,
        }
    }

    #[test]
    fn client_effective_config_snapshot_psk_mux_fields() {
        let opts = test_client_opts(
            MuxWindow::try_from(4).unwrap(),
            3,
            true,
            Some("secret-psk-material"),
            None,
            None,
        );
        let snap = client_effective_config_snapshot(&opts, 3);
        assert_eq!(snap.mux_window_bytes, 4 * 1024 * 1024);
        assert_eq!(snap.ws_parallel, 3);
        assert!(snap.use_tcp_mux);
        assert!(snap.psk);
        assert!(!snap.reality);
        assert_eq!(snap.max_ws_binary, 1400);
        assert_eq!(snap.max_pad, 64);
        assert_eq!(snap.dummy_interval_secs, 30);
        assert!(!snap.version.is_empty());
        assert!(!EFFECTIVE_CONFIG_NOTE.contains("token"));
        assert!(!EFFECTIVE_CONFIG_NOTE.contains("psk"));
        assert!(!EFFECTIVE_CONFIG_NOTE.contains("secret"));
    }

    #[test]
    fn client_effective_config_snapshot_reality_without_psk() {
        let pk = [7u8; 32];
        let opts = test_client_opts(
            MuxWindow::default(),
            1,
            true,
            None,
            Some("vk.com:443"),
            Some(pk),
        );
        let snap = client_effective_config_snapshot(&opts, 1);
        assert!(!snap.psk);
        assert!(snap.reality);
        assert_eq!(snap.mux_window_bytes, 1024 * 1024);
    }

    #[test]
    fn server_effective_config_snapshot_fields() {
        let snap = server_effective_config_snapshot(
            MuxWindow::try_from(2).unwrap(),
            64,
            1400,
            0,
            true,
            false,
        );
        assert_eq!(snap.mux_window_bytes, 2 * 1024 * 1024);
        assert_eq!(snap.max_pad, 64);
        assert_eq!(snap.max_ws_binary, 1400);
        assert!(snap.psk);
        assert!(!snap.reality);
        assert!(!EFFECTIVE_CONFIG_NOTE.contains("token"));
    }
}
