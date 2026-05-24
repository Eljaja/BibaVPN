//! Summarize which client-side stealth knobs actually apply in this build.

use tracing::warn;

use crate::local_client::LocalClientOptions;
use crate::stealth_v12::DesyncMode;
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

/// One-line summary when the entry server starts accepting connections.
pub fn log_server_listen_caps(
    legacy_path_auth: bool,
    auth_rate_limit_enabled: bool,
    max_concurrent_sessions: usize,
    udp_socket_pool_size: usize,
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
pub fn log_client_transport_caps(opts: &LocalClientOptions) {
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
