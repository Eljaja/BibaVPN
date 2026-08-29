use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Context;
use bibavpn::crypto_layer::{self, SessionCrypto};
use bibavpn::frame::{AdaptivePadState, PadMode, DEFAULT_MAX_WS_BINARY};
use bibavpn::incoming::{accept_websocket_or_camouflage, CamouflageServeConfig, WsHandshakeKind};
use bibavpn::log_ratelimit::LogEvery;
use bibavpn::logging::{self, LogConfig, LogFormat};
use bibavpn::server_limits::{
    account_pre_hello_binary, AuthRateLimiter, AuthRateLimiterConfig, PreAuthBudget,
    PreHelloJunkTracker, ServerStats, MAX_PRE_HELLO_BYTES, MAX_PRE_HELLO_FRAMES,
};
use bibavpn::server_metrics::{spawn_metrics_listener, MetricsAuth};
use bibavpn::transport_capabilities::log_server_listen_caps;
use bibavpn::startup_secrets::{
    log_lab_mode_enabled, log_reality_without_psk, require_psk, resolve_cli_token,
    server_reality_configured,
};
use bibavpn::udp_mux::UdpSocketPool;
use bibavpn::invite_uri::{encode_invite_v1, InviteV1};
use bibavpn::local_client::{
    normalize_ws_path, parse_host_port, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use bibavpn::protocol::{
    classify_v3_first_channel, decode_v3_auth, encode_v3_open_err, encode_v3_open_ok,
    is_v3_mux_open, V3FirstChannelKind, OPEN_FLAG_STATUS,
};
use bibavpn::ServerWsOutTiming;
use bibavpn::{read_padded_frame_into, write_padded_frame_with_mode_state};
use bibavpn::tls_util::{install_ring_crypto, server_config_from_pem, server_self_signed};
use bibavpn::ws_bridge::TunnelEnd;
use bibavpn::reality::{extract_sni, server_handshake_reality, RealityServerConfig};
use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustls::ServerConfig;
use std::str::FromStr;
use bibavpn::stealth_v12::StealthProfile;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
struct ServerConnParams {
    peer: SocketAddr,
    session_id: u64,
    auth: Arc<AuthRateLimiter>,
    stats: Arc<ServerStats>,
    pre_auth: PreAuthBudget,
    handshake_timeout: Duration,
    mux_connect_timeout: Duration,
    udp_pool: Option<Arc<UdpSocketPool>>,
}

#[derive(Parser, Debug)]
#[command(
    name = "bibavpn-server",
    about = "BibaVPN WSS entrypoint (use behind a real TLS proxy in production)."
)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,

    #[arg(long, required_unless_present = "lab")]
    token: Option<String>,

    /// Local demos only: allow missing `--token` (uses `change-me`), skip token denylist, relax PSK when REALITY is configured.
    #[arg(long, default_value_t = false)]
    lab: bool,

    /// WebSocket HTTP path (token is sent in AUTH frame). Default `/ws`.
    #[arg(long, default_value = "/ws")]
    ws_path: String,

    /// Accept legacy clients that use URL `/b/{token}` without AUTH frame (less secure).
    #[arg(long, default_value_t = false)]
    legacy_path_auth: bool,

    #[arg(long)]
    cert: Option<PathBuf>,

    #[arg(long)]
    key: Option<PathBuf>,

    #[arg(long)]
    self_signed_san: Option<String>,

    #[arg(long, default_value = "64")]
    max_pad: u8,

    /// BibaV2 pre-shared key (optional). Enables HELLO/ACK + AEAD outer framing.
    #[arg(long)]
    psk: Option<String>,

    /// Inner plaintext decoy bytes 0..=N before each AEAD chunk (both directions). AWG2-inspired.
    #[arg(long, default_value = "0")]
    decoy_max: u8,

    /// Max WebSocket binary bytes per message (send path; loose bound on receive).
    #[arg(long, default_value_t = DEFAULT_MAX_WS_BINARY)]
    max_ws_binary: usize,

    /// WebSocket ping interval seconds; 0 disables keepalive pings.
    #[arg(long, default_value = "25")]
    ws_ping_secs: u64,

    /// Vary WS ping interval ±N percent (0–50). Same meaning as on the client.
    #[arg(long, default_value = "0")]
    ws_ping_jitter_percent: u8,

    /// Random 0..=N ms delay before each outbound WebSocket frame (server → client).
    #[arg(long, default_value = "0")]
    ws_binary_send_jitter_ms: u8,

    /// Outbound WS send delay: random ms in `min..=max` when both set; else use `--ws-binary-send-jitter-ms`.
    #[arg(long, default_value = "0")]
    ws_jitter_min_ms: u8,

    #[arg(long, default_value = "0")]
    ws_jitter_max_ms: u8,

    /// BibaV1.2: server→client “delayed ACK buffer”: min delay (ms) per outbound binary; use with `--server-ack-delay-max-ms` (0 = off).
    #[arg(long, default_value_t = 0)]
    server_ack_delay_min_ms: u16,

    /// BibaV1.2: max delay (ms) for that buffer (0 = off). Typical stealth range 40–500; must be >= min when min > 0.
    #[arg(long, default_value_t = 0)]
    server_ack_delay_max_ms: u16,

    /// BibaV1.2: extra RTT-mask jitter 0..=N ms after ack delay, before WS send jitter (0 = off).
    #[arg(long, default_value_t = 0)]
    rtt_mask_jitter_ms: u16,

    /// BibaV1.2: when all explicit server ACK / RTT args above are 0, apply preset: `balanced` or `aggressive` (see `stealth_v12::StealthProfile::server_rtt_defaults`). `default` leaves delays off.
    #[arg(long)]
    ack_profile: Option<String>,

    /// Padding cap for UDP mux replies only (default: same as `--max-pad`).
    #[arg(long)]
    udp_max_pad: Option<u8>,

    /// MTU cap for UDP mux only (default: same as `--max-ws-binary`).
    #[arg(long)]
    udp_max_ws_binary: Option<usize>,

    /// After bind, print one `biba://...` line to **stdout** (encrypted invite for clients).
    #[arg(
        long,
        default_value_t = false,
        requires_all = ["invite_passphrase", "invite_public"]
    )]
    print_invite_uri: bool,

    /// Passphrase for the invite blob; **keep secret** and share out-of-band with clients.
    #[arg(long, requires = "print_invite_uri")]
    invite_passphrase: Option<String>,

    /// Public `host:port` for clients (e.g. VPS when `--listen` is `0.0.0.0:8443`).
    #[arg(long, requires = "print_invite_uri")]
    invite_public: Option<String>,

    /// TLS SNI / trust name in the invite (default: host from `--invite-public`).
    #[arg(long, requires = "print_invite_uri")]
    invite_sni: Option<String>,

    /// Per-request UDP `recv_from` timeout on the server for UDP mux (seconds, 1–600).
    #[arg(long, default_value_t = 120)]
    udp_mux_recv_timeout_secs: u64,

    /// Serve static files for HTTP GET (camouflage). If unset, GET still returns simple nginx-like pages.
    #[arg(long)]
    camouflage_dir: Option<PathBuf>,

    /// Reverse-proxy origin for HTTP GET (`http://host:port` only; TLS to origin not implemented).
    #[arg(long)]
    camouflage_url: Option<String>,

    /// Inner frame padding mode: `adaptive` (default), `random`, or `http-buckets`.
    #[arg(long, default_value = "adaptive")]
    pad_mode: String,

    /// Send idle padded empty frames on TCP tunnels (0 = off). Matches client `--dummy-interval-secs`.
    #[arg(long, default_value_t = 0)]
    dummy_interval_secs: u64,

    /// Biba v3 domain string for PSK key separation (must match client / invite). Default `default`.
    #[arg(long, default_value = "default")]
    proto_domain: String,

    /// Per-IP v3 AUTH failures in `--auth-failure-window-secs` before `--auth-ban-secs` temporary ban.
    #[arg(long, default_value_t = 10)]
    auth_max_failures: u32,

    #[arg(long, default_value_t = 60)]
    auth_failure_window_secs: u64,

    #[arg(long, default_value_t = 300)]
    auth_ban_secs: u64,

    /// Disable per-IP auth failure rate limiting.
    #[arg(long = "no-auth-rate-limit", default_value_t = false)]
    no_auth_rate_limit: bool,

    /// Cap concurrent TLS handshakes+sessions (0 = unlimited).
    #[arg(long, default_value_t = 512)]
    max_concurrent_sessions: usize,

    /// Max junk bytes (failed decrypt noise) before v3 AUTH completes.
    #[arg(long, default_value_t = 262144)]
    handshake_max_junk_bytes: usize,

    /// Per-phase pre-tunnel timeout in seconds: TLS accept, WS upgrade / camouflage HTTP head,
    /// REALITY exchange, the v3 handshake wait (HELLO..AUTH), and the post-AUTH wait for
    /// OPEN / MUX_OPEN / UDP_MUX_OPEN.
    #[arg(long, default_value_t = 15)]
    handshake_timeout_secs: u64,

    /// TCP connect timeout for each mux stream on the server (seconds).
    #[arg(long, default_value_t = 10)]
    mux_connect_timeout_secs: u64,

    /// Reuse up to N UDP sockets on the UDP mux server (0 = bind per datagram).
    #[arg(long, default_value_t = 64)]
    udp_socket_pool_size: usize,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[arg(long, default_value = "plain")]
    log_format: String,

    #[arg(long)]
    log_filter: Option<String>,

    /// Emit periodic stats every N seconds (0 = off).
    #[arg(long, default_value_t = 0)]
    stats_interval_secs: u64,

    /// Optional Prometheus listener (`host:port`). Serves `GET /metrics` and `GET /healthz`. Off by default; bind loopback in production.
    #[arg(long)]
    metrics_listen: Option<String>,

    /// HTTP Basic Auth password for the metrics listener (user defaults to `metrics`). Requires `--metrics-listen`.
    #[arg(long, requires = "metrics_listen")]
    metrics_password: Option<String>,

    /// HTTP Basic Auth username for the metrics listener (default `metrics`).
    #[arg(long, default_value = "metrics", requires = "metrics_password")]
    metrics_user: String,

    /// REALITY mode: target to steal TLS from (e.g., vk.com:443)
    #[arg(long)]
    reality_target: Option<String>,

    /// REALITY mode: server private key (base64 encoded X25519)
    #[arg(long)]
    reality_private_key: Option<String>,

    /// REALITY mode: allowed short IDs (hex, comma-separated). Empty = any.
    #[arg(long)]
    reality_short_ids: Option<String>,

    /// REALITY mode: enforced TLS SNI / HTTP Host allowlist (comma-separated).
    /// Default: host from `--reality-target`. An empty list accepts any name (startup WARN).
    #[arg(long)]
    reality_server_names: Option<String>,
}

type SharedCrypto = Arc<SessionCrypto>;

/// Pause after an accept error that would otherwise repeat immediately.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What the accept loop does after a failed `accept(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptRecovery {
    /// Per-connection failure (peer vanished, signal): retry immediately.
    RetryNow,
    /// Sleep before retrying, otherwise the loop spins at 100% CPU for as long
    /// as the condition lasts. `exhaustion` marks the out-of-descriptors /
    /// out-of-buffers class so the log says so.
    RetryAfterBackoff { exhaustion: bool },
}

impl AcceptRecovery {
    fn backoff(self) -> Option<Duration> {
        match self {
            AcceptRecovery::RetryNow => None,
            AcceptRecovery::RetryAfterBackoff { .. } => Some(ACCEPT_BACKOFF),
        }
    }

    fn is_exhaustion(self) -> bool {
        matches!(self, AcceptRecovery::RetryAfterBackoff { exhaustion: true })
    }
}

/// True for raw OS errors meaning "out of descriptors or kernel buffers".
/// These have no distinct `std::io::ErrorKind` on stable Rust, so they are
/// matched numerically; the values are per-platform ABI constants.
#[cfg(unix)]
fn is_accept_resource_exhaustion(code: i32) -> bool {
    // EMFILE, ENFILE and ENOMEM share values across Linux and the BSDs;
    // ENOBUFS does not.
    const EMFILE: i32 = 24;
    const ENFILE: i32 = 23;
    const ENOMEM: i32 = 12;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENOBUFS: i32 = 105;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const ENOBUFS: i32 = 55;
    matches!(code, EMFILE | ENFILE | ENOMEM | ENOBUFS)
}

#[cfg(windows)]
fn is_accept_resource_exhaustion(code: i32) -> bool {
    // WSAEMFILE, WSAENOBUFS, WSAETOOMANYREFS.
    matches!(code, 10024 | 10055 | 10059)
}

#[cfg(not(any(unix, windows)))]
fn is_accept_resource_exhaustion(_code: i32) -> bool {
    false
}

/// Classify an `accept(2)` error. Never fatal: see the accept loop comment.
fn classify_accept_error(e: &std::io::Error) -> AcceptRecovery {
    use std::io::ErrorKind;
    match e.kind() {
        // Cheap and clearly per-connection: the next accept can succeed at once.
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock => AcceptRecovery::RetryNow,
        // ENOMEM where the platform maps it to a kind.
        ErrorKind::OutOfMemory => AcceptRecovery::RetryAfterBackoff { exhaustion: true },
        // EMFILE/ENFILE/ENOBUFS have no stable `ErrorKind`, so check the raw
        // code. Unrecognised errors back off as well: losing 100ms of accept
        // throughput is cheaper than spinning on an error we do not know.
        _ => AcceptRecovery::RetryAfterBackoff {
            exhaustion: e.raw_os_error().is_some_and(is_accept_resource_exhaustion),
        },
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    logging::init(LogConfig {
        level: logging::level_directive(&args.log_level)?,
        format: args.log_format.parse::<LogFormat>()?,
        filter: args.log_filter.clone(),
    })?;

    install_ring_crypto();

    if args.lab {
        log_lab_mode_enabled();
    }
    let token = resolve_cli_token(args.token.as_deref(), args.lab)?;
    let reality_configured = server_reality_configured(
        args.reality_target.as_deref(),
        args.reality_private_key.as_deref(),
    );
    require_psk(args.psk.as_deref(), reality_configured, args.lab)?;
    if reality_configured && args.psk.as_deref().map(str::trim).is_none_or(str::is_empty) {
        log_reality_without_psk();
    }

    let ws_path = normalize_ws_path(&args.ws_path);
    let pad_mode = PadMode::from_str(args.pad_mode.trim()).context("pad-mode")?;

    let tls_cfg: Arc<ServerConfig> = match (&args.cert, &args.key, &args.self_signed_san) {
        (Some(c), Some(k), _) => {
            let c = std::fs::read(c).context("read cert")?;
            let k = std::fs::read(k).context("read key")?;
            server_config_from_pem(&c, &k)?
        }
        (None, None, Some(san)) => {
            info!("using embedded self-signed for SAN {}", san);
            server_self_signed(san)?
        }
        (None, None, None) => {
            anyhow::bail!("provide --cert and --key, or --self-signed-san for demo");
        }
        _ => {
            anyhow::bail!("use both --cert and --key together");
        }
    };

    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    info!("listening on {}", args.listen);

    if args.print_invite_uri {
        let public = args
            .invite_public
            .as_ref()
            .expect("clap requires invite_public with print_invite_uri");
        let (host_for_sni, _) = parse_host_port(public).context("invite-public host:port")?;
        let sni = args
            .invite_sni
            .clone()
            .unwrap_or_else(|| host_for_sni.clone());
        let lab_insecure = matches!(
            (&args.cert, &args.key, &args.self_signed_san),
            (None, None, Some(_))
        );
        // With `--cert`/`--key`, `lab_insecure` is false so clients use CA verification.
        // Self-signed / private-CA certs are not in the system store — embed the leaf PEM for pinning.
        let pin_cert_pem = match &args.cert {
            Some(path) => {
                let pem = std::fs::read_to_string(path).with_context(|| {
                    format!("invite: read --cert for pin_cert_pem {}", path.display())
                })?;
                let t = pem.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                }
            }
            None => None,
        };
        let passphrase = args
            .invite_passphrase
            .as_deref()
            .expect("clap requires invite_passphrase");
        let (reality_target, reality_public_key, reality_short_id) = match (
            args.reality_target.as_ref(),
            args.reality_private_key.as_ref(),
        ) {
            (Some(t), Some(priv_b64)) => {
                let privkey = base64::engine::general_purpose::STANDARD
                    .decode(priv_b64)
                    .context("invite: decode reality private key")?;
                if privkey.len() != 32 {
                    anyhow::bail!("invite: reality private key must be 32 bytes");
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&privkey);
                use x25519_dalek::{PublicKey, StaticSecret};
                let public = PublicKey::from(&StaticSecret::from(a));
                let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public.to_bytes());
                let sid = args
                    .reality_short_ids
                    .as_deref()
                    .and_then(|s| {
                        s.split(',')
                            .map(|h| h.trim())
                            .find(|h| !h.is_empty())
                    })
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| hex::encode(&public.to_bytes()[..8]));
                (Some(t.clone()), Some(pk_b64), Some(sid))
            }
            _ => (None, None, None),
        };
        let proto_domain = (!args.proto_domain.trim().is_empty()).then_some(args.proto_domain.clone());
        let invite = InviteV1 {
            v: 1,
            server: public.clone(),
            sni,
            token: token.clone(),
            proto: 3,
            proto_domain,
            psk: args.psk.clone(),
            decoy_max: args.decoy_max,
            max_pad: args.max_pad,
            max_ws_binary: args.max_ws_binary,
            ws_ping_secs: args.ws_ping_secs,
            ws_ping_jitter_percent: args.ws_ping_jitter_percent,
            ws_binary_send_jitter_ms: args.ws_binary_send_jitter_ms,
            ws_jitter_min_ms: args.ws_jitter_min_ms,
            ws_jitter_max_ms: args.ws_jitter_max_ms,
            udp_max_pad: args.udp_max_pad,
            udp_max_ws_binary: args.udp_max_ws_binary,
            udp_mux_reply_timeout_secs: DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
            insecure: lab_insecure,
            tls_profile: "default".into(),
            ws_path: Some(ws_path.clone()),
            pad_mode: Some(match pad_mode {
                PadMode::Random => "random".into(),
                PadMode::HttpBuckets => "http-buckets".into(),
                PadMode::Adaptive => "adaptive".into(),
            }),
            dummy_interval_secs: Some(args.dummy_interval_secs).filter(|&x| x > 0),
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
            reality_target,
            reality_public_key,
            reality_short_id,
            pin_cert_pem,
            server_ack_delay_min_ms: Some(args.server_ack_delay_min_ms),
            server_ack_delay_max_ms: Some(args.server_ack_delay_max_ms),
            rtt_mask_jitter_ms: Some(args.rtt_mask_jitter_ms),
            ack_profile: args.ack_profile.clone(),
        };
        let uri = encode_invite_v1(&invite, passphrase).context("build invite URI")?;
        println!("{}", uri);
        eprintln!("bibavpn-server: invite URI on stdout; keep --invite-passphrase secret (not in log aggregation).");
    }

    let max_pad = args.max_pad;
    let psk = args.psk.clone();
    let decoy_max = args.decoy_max;
    let max_ws_binary = args.max_ws_binary;
    let ws_ping_secs = args.ws_ping_secs;
    let ws_ping_jitter_percent = args.ws_ping_jitter_percent;
    let ws_binary_send_jitter_ms = args.ws_binary_send_jitter_ms;
    let ws_jitter_min_ms = args.ws_jitter_min_ms;
    let ws_jitter_max_ms = args.ws_jitter_max_ms;
    let mut s_ack_lo = args.server_ack_delay_min_ms;
    let mut s_ack_hi = args.server_ack_delay_max_ms;
    if s_ack_lo > 0 && s_ack_hi < s_ack_lo {
        std::mem::swap(&mut s_ack_lo, &mut s_ack_hi);
    }
    let mut server_ws_out = ServerWsOutTiming {
        ack_delay_min_ms: s_ack_lo,
        ack_delay_max_ms: s_ack_hi,
        rtt_mask_jitter_ms: args.rtt_mask_jitter_ms,
    };
    if s_ack_lo == 0
        && s_ack_hi == 0
        && args.rtt_mask_jitter_ms == 0
    {
        if let Some(s) = args.ack_profile.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let p = StealthProfile::from_str(s).context("--ack-profile")?;
            if let Some(d) = p.server_rtt_defaults() {
                let mut a = d.ack_delay_min_ms;
                let mut b = d.ack_delay_max_ms;
                if a > 0 && b < a {
                    std::mem::swap(&mut a, &mut b);
                }
                server_ws_out = ServerWsOutTiming {
                    ack_delay_min_ms: a,
                    ack_delay_max_ms: b,
                    rtt_mask_jitter_ms: d.rtt_mask_jitter_ms,
                };
            }
        }
    }
    let udp_mux_pad = args.udp_max_pad.unwrap_or(max_pad);
    let udp_mux_ws = args.udp_max_ws_binary.unwrap_or(max_ws_binary);
    let udp_mux_recv = Duration::from_secs(args.udp_mux_recv_timeout_secs.clamp(1, 600));
    let legacy_path_auth = args.legacy_path_auth;
    let dummy_interval_secs = args.dummy_interval_secs;
    let camouflage_dir = args.camouflage_dir.clone();
    let camouflage_url = args.camouflage_url.clone();

    // ===== REALITY Mode Setup =====
    let reality_config: Option<RealityServerConfig> = if let (Some(target), Some(privkey_b64)) = (
        args.reality_target.as_ref(),
        args.reality_private_key.as_ref(),
    ) {
        let privkey = base64::engine::general_purpose::STANDARD
            .decode(privkey_b64)
            .context("decode reality private key")?;

        if privkey.len() != 32 {
            anyhow::bail!("reality private key must be 32 bytes");
        }

        let mut privkey_arr = [0u8; 32];
        privkey_arr.copy_from_slice(&privkey);

        let server_names = args
            .reality_server_names
            .as_ref()
            .map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec![extract_sni(target)]);

        if server_names.is_empty() {
            warn!(
                target: "bibavpn_security",
                "REALITY server-name allowlist is empty; accepting ANY TLS SNI / HTTP Host"
            );
        }

        let short_ids: Vec<[u8; 8]> = args
            .reality_short_ids
            .as_ref()
            .map(|s| {
                s.split(',')
                    .filter_map(|hex_str| {
                        let hex_str = hex_str.trim();
                        if hex_str.is_empty() {
                            return Some([0u8; 8]); // empty = allow any
                        }
                        let bytes = hex::decode(hex_str).ok()?;
                        if bytes.len() != 8 {
                            return None;
                        }
                        let mut arr = [0u8; 8];
                        arr.copy_from_slice(&bytes);
                        Some(arr)
                    })
                    .collect()
            })
            .unwrap_or_default();

        info!(
            "REALITY mode: target={}, server_names={:?}, short_ids={} entries",
            target,
            server_names,
            short_ids.len()
        );

        // `is_short_id_allowed` is permissive for an empty list or an all-zero
        // entry: any short ID passes. Clients still have to pass the REALITY
        // AUTH frame, but the operator should know the ID is not pinned.
        let wildcard_short_id = short_ids.iter().any(|id| id.iter().all(|&b| b == 0));
        if short_ids.is_empty() || wildcard_short_id {
            let reason = if short_ids.is_empty() {
                "empty allowlist"
            } else {
                "all-zeros wildcard entry"
            };
            warn!(
                target: "bibavpn_security",
                reason,
                "REALITY short-ID allowlist accepts ANY short ID; pin clients with --reality-short-ids"
            );
        }

        Some(RealityServerConfig {
            private_key: privkey_arr,
            target: target.clone(),
            server_names,
            short_ids,
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: 0,
        })
    } else {
        None
    };

    if args.legacy_path_auth {
        warn!(
            target: "bibavpn_security",
            "--legacy-path-auth is deprecated; use standard ws path + AUTH frame only; not recommended for production"
        );
    }

    let auth_cfg = AuthRateLimiterConfig {
        enabled: !args.no_auth_rate_limit,
        max_failures: args.auth_max_failures.max(1),
        window: Duration::from_secs(args.auth_failure_window_secs.max(1)),
        ban: Duration::from_secs(args.auth_ban_secs.max(1)),
    };
    let auth = AuthRateLimiter::new(auth_cfg);
    let stats = ServerStats::new();
    let conn_sem = if args.max_concurrent_sessions > 0 {
        Some(Arc::new(Semaphore::new(args.max_concurrent_sessions)))
    } else {
        None
    };
    let udp_pool = if args.udp_socket_pool_size > 0 {
        Some(UdpSocketPool::new(args.udp_socket_pool_size))
    } else {
        None
    };
    let pre_auth = PreAuthBudget {
        max_junk_frames: 256,
        max_junk_bytes: args.handshake_max_junk_bytes.max(1024),
        max_decrypt_failures: 64,
    };
    let handshake_timeout = Duration::from_secs(args.handshake_timeout_secs.max(1));
    let mux_connect_timeout = Duration::from_secs(args.mux_connect_timeout_secs.max(1));

    log_server_listen_caps(
        args.legacy_path_auth,
        !args.no_auth_rate_limit,
        args.max_concurrent_sessions,
        args.udp_socket_pool_size,
    );

    if let Some(ref metrics_listen) = args.metrics_listen {
        let metrics_auth = match args.metrics_password.as_deref() {
            Some(pw) if !pw.is_empty() => MetricsAuth::basic(args.metrics_user.trim(), pw),
            _ => MetricsAuth::disabled(),
        };
        spawn_metrics_listener(
            metrics_listen.clone(),
            Arc::clone(&stats),
            Arc::clone(&auth),
            metrics_auth,
        );
    }

    if args.stats_interval_secs > 0 {
        let stats_c = Arc::clone(&stats);
        let auth_c = Arc::clone(&auth);
        let iv = Duration::from_secs(args.stats_interval_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(iv).await;
                info!(
                    target: "bibavpn_server",
                    active_sessions = stats_c.active_sessions(),
                    auth_bans_active = auth_c.bans_active.load(Ordering::Relaxed),
                    "periodic server stats"
                );
            }
        });
    }

    // Start SpiderX background crawler if REALITY is enabled
    if let Some(ref cfg) = reality_config {
        let target = cfg.target.clone();
        let spiderx_interval = 30u64; // Fetch every 30 seconds
        tokio::spawn(async move {
            use bibavpn::reality::spawn_spiderx;
            spawn_spiderx(target, spiderx_interval).await;
        });
        info!("SpiderX background crawler started for {}", cfg.target);
    }

    // A failed accept(2) must never take the listener down: EMFILE/ENFILE/ENOBUFS
    // (fd or kernel-buffer exhaustion, i.e. exactly what a connection flood
    // produces) and ECONNABORTED (peer gone between SYN and accept) are all
    // transient, and a proxy that exits on them is trivially DoS-able. Neither
    // tokio nor the OS reports a permanently dead listener distinguishably here,
    // so no error is treated as fatal; a listener that never recovers shows up as
    // a climbing bibavpn_accepts_failed_total plus these rate-limited warnings.
    static ACCEPT_ERR_LOG: LogEvery = LogEvery::new(8, 256);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                stats.inc_accept_failed();
                let recovery = classify_accept_error(&e);
                let backoff = recovery.backoff();
                if ACCEPT_ERR_LOG.should_emit() {
                    warn!(
                        target: "bibavpn_server",
                        error_kind = ?e.kind(),
                        errno = e.raw_os_error().unwrap_or(0),
                        resource_exhaustion = recovery.is_exhaustion(),
                        backoff_ms = backoff.map(|d| d.as_millis() as u64).unwrap_or(0),
                        accepts_failed_total = stats.accepts_failed_total.load(Ordering::Relaxed),
                        "accept failed, still serving: {e:#}"
                    );
                }
                if let Some(d) = backoff {
                    tokio::time::sleep(d).await;
                }
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let token = token.clone();
        let ws_path = ws_path.clone();
        let camo = CamouflageServeConfig {
            static_dir: camouflage_dir.clone(),
            reverse_proxy: camouflage_url.clone(),
        };
        let psk_conn = psk.clone();
        let proto_domain = args.proto_domain.clone();
        let reality_cfg = reality_config.clone();
        let server_ws_out = server_ws_out;
        let auth = Arc::clone(&auth);
        let stats = Arc::clone(&stats);
        let conn_sem = conn_sem.clone();
        let pre_auth = pre_auth.clone();
        let udp_pool = udp_pool.clone();
        let handshake_timeout = handshake_timeout;
        let mux_connect_timeout = mux_connect_timeout;
        let session_id = rand::random::<u64>();

        tokio::spawn(async move {
            let permit = match &conn_sem {
                Some(sem) => {
                    match timeout(Duration::from_secs(5), sem.clone().acquire_owned()).await {
                        Ok(Ok(p)) => Some(p),
                        Ok(Err(_)) => return,
                        Err(_) => {
                            stats.inc_sessions_rejected_busy();
                            debug!(
                                target: "bibavpn_server",
                                %peer,
                                "dropped: concurrent session semaphore acquire timeout (server busy)"
                            );
                            return;
                        }
                    }
                }
                None => None,
            };

            if let Err(e) = auth.check_allowed(peer.ip()).await {
                stats.inc_auth_rejected_banned();
                debug!(
                    target: "bibavpn_security",
                    %peer,
                    session_id,
                    "rejected: {e:#}"
                );
                drop(permit);
                return;
            }

            let _sess = stats.session_guard();

            let params = ServerConnParams {
                peer,
                session_id,
                auth,
                stats: Arc::clone(&stats),
                pre_auth,
                handshake_timeout,
                mux_connect_timeout,
                udp_pool,
            };

            if let Err(e) = handle_one(
                stream,
                acceptor,
                token,
                ws_path,
                legacy_path_auth,
                max_pad,
                psk_conn,
                decoy_max,
                max_ws_binary,
                ws_ping_secs,
                ws_ping_jitter_percent,
                ws_binary_send_jitter_ms,
                ws_jitter_min_ms,
                ws_jitter_max_ms,
                udp_mux_pad,
                udp_mux_ws,
                udp_mux_recv,
                pad_mode,
                dummy_interval_secs,
                server_ws_out,
                camo,
                proto_domain,
                reality_cfg,
                params,
            )
            .await
            {
                stats.inc_session_error();
                error!(
                    target: "bibavpn_server",
                    %peer,
                    session_id,
                    "session error: {e:#}"
                );
            }
            drop(permit);
        });
    }
}

async fn read_next_binary_after_reality<S>(ws: &mut WebSocketStream<S>) -> anyhow::Result<Bytes>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let m = ws
            .next()
            .await
            .context("eof after REALITY")?
            .context("ws error after REALITY")?;
        match m {
            Message::Binary(b) => return Ok(b),
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.context("pong after REALITY")?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => anyhow::bail!("closed after REALITY"),
            _ => {}
        }
    }
}

async fn server_handshake_v3_after_first_hello<S>(
    ws: &mut WebSocketStream<S>,
    first_hello: &[u8],
    token: &str,
    psk: &str,
    decoy_max: u8,
    proto_domain: &str,
    auth: &Arc<AuthRateLimiter>,
    stats: &Arc<ServerStats>,
    peer_ip: std::net::IpAddr,
    pre_auth: &PreAuthBudget,
    handshake_timeout: Duration,
) -> anyhow::Result<SharedCrypto>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let c = crypto_layer::parse_hello_v3(first_hello).context("parse v3 HELLO")?;
    let (ack, s_rand) = crypto_layer::build_ack(psk, proto_domain, &c)?;
    ws.send(Message::Binary(Bytes::from(ack)))
        .await
        .context("send v3 ACK (REALITY follow-up)")?;
    let crypto = Arc::new(SessionCrypto::new(
        psk,
        proto_domain,
        &c,
        &s_rand,
        decoy_max,
    ));
    let auth_c = Arc::clone(auth);
    let wait = async {
        server_wait_v3_auth(ws, &crypto, token, &auth_c, stats, peer_ip, pre_auth).await
    };
    match timeout(handshake_timeout, wait).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            stats.inc_handshake_timeout();
            auth.record_failure(peer_ip).await;
            anyhow::bail!("handshake timeout waiting for v3 AUTH (REALITY path)");
        }
    }
    Ok(crypto)
}

async fn run_session_after_v3_handshake<S>(
    ws: WebSocketStream<S>,
    crypto: SharedCrypto,
    udp_mux_max_pad: u8,
    udp_mux_max_ws_binary: usize,
    udp_mux_recv_timeout: Duration,
    max_pad: u8,
    decoy_max: u8,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    ws_jitter_min_ms: u8,
    ws_jitter_max_ms: u8,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
    server_out: ServerWsOutTiming,
    mux_connect_timeout: Duration,
    udp_socket_pool: Option<Arc<UdpSocketPool>>,
    handshake_timeout: Duration,
    pre_auth: &PreAuthBudget,
    auth: &Arc<AuthRateLimiter>,
    stats: &Arc<ServerStats>,
    peer_ip: std::net::IpAddr,
    session_id: u64,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match wait_first_channel_with_timeout(
        ws,
        &crypto,
        pre_auth,
        auth,
        stats,
        peer_ip,
        session_id,
        handshake_timeout,
    )
    .await?
    {
        FirstChannel::Tcp {
            host,
            port,
            mut ws,
            supports_open_status,
        } => {
            info!("OPEN {host}:{port}");
            let mut pad_st = AdaptivePadState::default();
            // Bound the dial so a blackholed target cannot tie up the session
            // (and its concurrency permit) until the OS TCP timeout (~minutes).
            let connect = timeout(mux_connect_timeout, TcpStream::connect((host.as_str(), port)))
                .await
                .unwrap_or_else(|_| {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "connect timed out",
                    ))
                });
            let remote = match connect {
                Ok(remote) => remote,
                Err(e) => {
                    if supports_open_status {
                        if let Ok(inner) =
                            encode_v3_open_err(&format!("connect {host}:{port}: {e:#}"))
                        {
                            let mut wire = Vec::new();
                            if write_padded_frame_with_mode_state(
                                &mut wire,
                                &inner,
                                max_pad,
                                pad_mode,
                                Some(&mut pad_st),
                            )
                            .is_ok()
                            {
                                if let Ok(blob) = crypto.seal_server_to_client(&wire) {
                                    let _ = ws.send(Message::Binary(Bytes::from(blob))).await;
                                }
                            }
                        }
                        return Ok(());
                    }
                    return Err(e).with_context(|| format!("connect {host}:{port}"));
                }
            };
            let _ = remote.set_nodelay(true);
            if supports_open_status {
                let inner = encode_v3_open_ok();
                let mut wire = Vec::new();
                write_padded_frame_with_mode_state(
                    &mut wire,
                    &inner,
                    max_pad,
                    pad_mode,
                    Some(&mut pad_st),
                )
                .context("pack OPEN_OK v3")?;
                let blob = crypto
                    .seal_server_to_client(&wire)
                    .context("seal OPEN_OK v3")?;
                ws.send(Message::Binary(Bytes::from(blob)))
                    .await
                    .context("send OPEN_OK v3")?;
            }
            bibavpn::ws_bridge::bridge_ws_tcp_padded(
                ws,
                Vec::<bibavpn::ws_bridge::WsBridgePrefetch>::new(),
                remote,
                Vec::new(),
                max_pad,
                decoy_max,
                Some(crypto.clone()),
                max_ws_binary,
                ws_ping_secs,
                ws_ping_jitter_percent,
                ws_binary_send_jitter_ms,
                ws_jitter_min_ms,
                ws_jitter_max_ms,
                TunnelEnd::Server,
                pad_mode,
                dummy_interval_secs,
                server_out,
            )
            .await?;
        }
        FirstChannel::UdpMux { ws } => {
            info!("UDP mux (same WSS/TLS envelope as TCP)");
            bibavpn::udp_mux::bridge_ws_udp_mux_server(
                ws,
                udp_mux_max_pad,
                decoy_max,
                crypto.clone(),
                udp_mux_max_ws_binary,
                ws_ping_secs,
                ws_ping_jitter_percent,
                ws_binary_send_jitter_ms,
                ws_jitter_min_ms,
                ws_jitter_max_ms,
                udp_mux_recv_timeout,
                pad_mode,
                server_out,
                udp_socket_pool,
            )
            .await?;
        }
        FirstChannel::Mux { ws } => {
            info!("TCP mux (many streams / one WSS)");
            bibavpn::tcp_mux::bridge_ws_tcp_mux_server(
                ws,
                max_pad,
                decoy_max,
                Some(crypto.clone()),
                max_ws_binary,
                ws_ping_secs,
                ws_ping_jitter_percent,
                ws_binary_send_jitter_ms,
                ws_jitter_min_ms,
                ws_jitter_max_ms,
                pad_mode,
                dummy_interval_secs,
                server_out,
                mux_connect_timeout,
            )
            .await?;
        }
    }
    Ok(())
}

/// Bound one pre-tunnel setup phase (TLS accept, WS upgrade / camouflage HTTP head,
/// REALITY exchange) with `dur`.
///
/// The concurrency permit and the session guard are taken before any peer I/O, so a
/// peer that opens a socket and then stalls would otherwise hold a slot until it gives
/// up: a handful of silent sockets can exhaust `--max-concurrent-sessions`. Expiry is
/// counted as a handshake timeout and returns an error, which releases both.
/// No `auth.record_failure`: a peer that never spoke has not failed authentication.
async fn with_setup_timeout<T, F>(
    phase: &'static str,
    dur: Duration,
    stats: &Arc<ServerStats>,
    peer: SocketAddr,
    session_id: u64,
    fut: F,
) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    match timeout(dur, fut).await {
        Ok(r) => r,
        Err(_) => {
            let secs = dur.as_secs();
            stats.inc_handshake_timeout();
            debug!(
                target: "bibavpn_server",
                %peer,
                session_id,
                "pre-tunnel timeout in {phase} after {secs}s; releasing concurrency permit"
            );
            anyhow::bail!("{phase} timeout after {secs}s");
        }
    }
}

async fn handle_one(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    token: String,
    ws_path: String,
    legacy_path_auth: bool,
    max_pad: u8,
    psk: Option<String>,
    decoy_max: u8,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    ws_jitter_min_ms: u8,
    ws_jitter_max_ms: u8,
    udp_mux_max_pad: u8,
    udp_mux_max_ws_binary: usize,
    udp_mux_recv_timeout: Duration,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
    server_out: ServerWsOutTiming,
    camo: CamouflageServeConfig,
    proto_domain: String,
    reality_config: Option<RealityServerConfig>,
    params: ServerConnParams,
) -> anyhow::Result<()> {
    let span = tracing::info_span!(
        target: "bibavpn_server",
        "session",
        session_id = params.session_id,
        peer_ip = %params.peer.ip()
    );
    let _span_enter = span.enter();

    let tls = with_setup_timeout(
        "tls accept",
        params.handshake_timeout,
        &params.stats,
        params.peer,
        params.session_id,
        async move { acceptor.accept(tcp).await.context("tls accept") },
    )
    .await?;

    let tls_sni = tls.get_ref().1.server_name().map(str::to_string);

    // Covers the HTTP head read (`incoming::read_http_head` has no deadline of its own)
    // plus writing the camouflage answer; a real probe is served long before it expires.
    let Some((mut ws, ws_kind, http_host)) = with_setup_timeout(
        "websocket upgrade / camouflage http",
        params.handshake_timeout,
        &params.stats,
        params.peer,
        params.session_id,
        accept_websocket_or_camouflage(
            tls,
            &ws_path,
            legacy_path_auth,
            &token,
            camo,
            Some(params.peer),
        ),
    )
    .await?
    else {
        return Ok(());
    };

    static LEGACY_CONN_LOG: AtomicU64 = AtomicU64::new(0);
    if matches!(ws_kind, WsHandshakeKind::LegacyPath) {
        let n = LEGACY_CONN_LOG.fetch_add(1, Ordering::Relaxed);
        if n < 8 || n % 64 == 0 {
            warn!(
                target: "bibavpn_security",
                peer_ip = %params.peer.ip(),
                session_id = params.session_id,
                "legacy path WebSocket auth in use (deprecated)"
            );
        }
    }

    let peer_ip = params.peer.ip();
    let auth = &params.auth;
    let pre_auth = &params.pre_auth;
    let handshake_timeout = params.handshake_timeout;
    let mux_connect_timeout = params.mux_connect_timeout;
    let udp_pool = params.udp_pool.clone();

    if let Some(ref reality_cfg) = reality_config {
        info!("REALITY mode: app tunnel after X25519");
        // REALITY authenticates only the server, so the client must prove it
        // knows the session token (MAC bound to this handshake) *before* any
        // application frame is honoured — otherwise this is an open proxy.
        // Bounded like the other pre-tunnel phases, but with its own arms: this
        // one is an auth step, so it also feeds the per-IP rate limiter.
        match timeout(
            handshake_timeout,
            server_handshake_reality(
                &mut ws,
                reality_cfg,
                &token,
                tls_sni.as_deref(),
                http_host.as_deref(),
            ),
        )
        .await
        {
            Ok(Ok(_session_key)) => {
                auth.record_success(peer_ip).await;
            }
            Ok(Err(e)) => {
                auth.record_failure(peer_ip).await;
                warn!(
                    target: "bibavpn_security",
                    %peer_ip,
                    session_id = params.session_id,
                    "REALITY handshake/AUTH rejected: {e:#}"
                );
                return Err(e).context("REALITY handshake");
            }
            Err(_) => {
                params.stats.inc_handshake_timeout();
                auth.record_failure(peer_ip).await;
                anyhow::bail!("handshake timeout waiting for REALITY AUTH");
            }
        }

        let domain_trim = proto_domain.trim();
        if domain_trim.is_empty() {
            anyhow::bail!("--proto-domain must not be empty");
        }

        let next = with_setup_timeout(
            "first frame after REALITY",
            handshake_timeout,
            &params.stats,
            params.peer,
            params.session_id,
            async {
                read_next_binary_after_reality(&mut ws)
                    .await
                    .context("after REALITY: first application frame")
            },
        )
        .await?;

        if is_v3_mux_open(next.as_ref()) {
            info!("REALITY: TCP mux (plaintext mux records)");
            params.stats.inc_handshake_success();
            return bibavpn::tcp_mux::bridge_ws_tcp_mux_server(
                ws,
                max_pad,
                decoy_max,
                None,
                max_ws_binary,
                ws_ping_secs,
                ws_ping_jitter_percent,
                ws_binary_send_jitter_ms,
                ws_jitter_min_ms,
                ws_jitter_max_ms,
                pad_mode,
                dummy_interval_secs,
                server_out,
                mux_connect_timeout,
            )
            .await
            .context("REALITY TCP mux");
        }

        if !next.is_empty() && next[0] == crypto_layer::V3_HELLO_TAG {
            let secret =
                psk.as_deref()
                    .context("REALITY + v3 requires server --psk (UDP mux path)")?;
            let crypto = server_handshake_v3_after_first_hello(
                &mut ws,
                next.as_ref(),
                &token,
                secret,
                decoy_max,
                domain_trim,
                auth,
                &params.stats,
                peer_ip,
                pre_auth,
                handshake_timeout,
            )
            .await
            .context("REALITY + v3 PSK")?;
            return run_session_after_v3_handshake(
                ws,
                crypto,
                udp_mux_max_pad,
                udp_mux_max_ws_binary,
                udp_mux_recv_timeout,
                max_pad,
                decoy_max,
                max_ws_binary,
                ws_ping_secs,
                ws_ping_jitter_percent,
                ws_binary_send_jitter_ms,
                ws_jitter_min_ms,
                ws_jitter_max_ms,
                pad_mode,
                dummy_interval_secs,
                server_out,
                mux_connect_timeout,
                udp_pool,
                handshake_timeout,
                pre_auth,
                auth,
                &params.stats,
                peer_ip,
                params.session_id,
            )
            .await;
        }

        anyhow::bail!(
            "after REALITY: expected mux open or v3 HELLO, got len {} first=0x{:02x}",
            next.len(),
            next.first().copied().unwrap_or(0)
        );
    }

    let domain_trim = proto_domain.trim();
    if domain_trim.is_empty() {
        anyhow::bail!("--proto-domain must not be empty");
    }

    let crypto = server_handshake_v3(
        &mut ws,
        &token,
        psk.as_deref(),
        decoy_max,
        domain_trim,
        auth,
        &params.stats,
        peer_ip,
        pre_auth,
        handshake_timeout,
    )
    .await
    .context("handshake")?;

    run_session_after_v3_handshake(
        ws,
        crypto,
        udp_mux_max_pad,
        udp_mux_max_ws_binary,
        udp_mux_recv_timeout,
        max_pad,
        decoy_max,
        max_ws_binary,
        ws_ping_secs,
        ws_ping_jitter_percent,
        ws_binary_send_jitter_ms,
        ws_jitter_min_ms,
        ws_jitter_max_ms,
        pad_mode,
        dummy_interval_secs,
        server_out,
        mux_connect_timeout,
        udp_pool,
        handshake_timeout,
        pre_auth,
        auth,
        &params.stats,
        peer_ip,
        params.session_id,
    )
    .await
}

#[derive(Debug)]
enum FirstChannel<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    Tcp {
        host: String,
        port: u16,
        supports_open_status: bool,
        ws: WebSocketStream<S>,
    },
    UdpMux {
        ws: WebSocketStream<S>,
    },
    Mux {
        ws: WebSocketStream<S>,
    },
}

async fn wait_first_channel_with_timeout<S>(
    ws: WebSocketStream<S>,
    crypto: &SharedCrypto,
    pre_auth: &PreAuthBudget,
    auth: &Arc<AuthRateLimiter>,
    stats: &Arc<ServerStats>,
    peer_ip: std::net::IpAddr,
    session_id: u64,
    handshake_timeout: Duration,
) -> anyhow::Result<FirstChannel<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match timeout(
        handshake_timeout,
        wait_first_channel(ws, crypto, pre_auth, auth, peer_ip),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            stats.inc_handshake_timeout();
            auth.record_failure(peer_ip).await;
            debug!(
                target: "bibavpn_server",
                %peer_ip,
                session_id,
                "handshake timeout waiting for OPEN / MUX_OPEN / UDP_MUX_OPEN; releasing concurrency permit"
            );
            warn!(
                target: "bibavpn_security",
                %peer_ip,
                session_id,
                "handshake timeout waiting for OPEN / MUX_OPEN / UDP_MUX_OPEN"
            );
            anyhow::bail!("handshake timeout waiting for OPEN / MUX_OPEN / UDP_MUX_OPEN");
        }
    }
}

async fn wait_first_channel<S>(
    mut ws: WebSocketStream<S>,
    crypto: &SharedCrypto,
    pre_auth: &PreAuthBudget,
    auth: &Arc<AuthRateLimiter>,
    peer_ip: std::net::IpAddr,
) -> anyhow::Result<FirstChannel<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use bibavpn::server_limits::PreAuthBudgetTracker;
    let mut tracker = PreAuthBudgetTracker::default();
    while let Some(m) = ws.next().await {
        let m = m.context("ws read")?;
        match m {
            Message::Binary(b) => {
                let raw = crypto
                    .open_client_to_server(b.as_ref())
                    .context("decrypt v3 control")?;
                let inner = read_padded_frame_into(raw).context("padded v3 control")?;
                match classify_v3_first_channel(&inner) {
                    V3FirstChannelKind::TcpOpen { host, port, flags } => {
                        return Ok(FirstChannel::Tcp {
                            host,
                            port,
                            supports_open_status: (flags & OPEN_FLAG_STATUS) != 0,
                            ws,
                        });
                    }
                    V3FirstChannelKind::UdpMux => {
                        return Ok(FirstChannel::UdpMux { ws });
                    }
                    V3FirstChannelKind::Mux => {
                        return Ok(FirstChannel::Mux { ws });
                    }
                    V3FirstChannelKind::NotChannelOpen => {
                        if let Err(e) = tracker.note_binary_frame(b.len(), pre_auth) {
                            auth.record_failure(peer_ip).await;
                            return Err(e);
                        }
                    }
                }
            }
            Message::Ping(p) => {
                ws.send(Message::Pong(p))
                    .await
                    .context("pong during OPEN wait")?;
            }
            Message::Close(_) => anyhow::bail!("closed before channel open"),
            _ => {}
        }
    }
    anyhow::bail!("eof before OPEN / UDP_MUX / MUX")
}

async fn server_handshake_v3<S>(
    ws: &mut WebSocketStream<S>,
    token: &str,
    psk: Option<&str>,
    decoy_max: u8,
    proto_domain: &str,
    auth: &Arc<AuthRateLimiter>,
    stats: &Arc<ServerStats>,
    peer_ip: std::net::IpAddr,
    pre_auth: &PreAuthBudget,
    handshake_timeout: Duration,
) -> anyhow::Result<SharedCrypto>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let domain = proto_domain.to_string();
    let auth_f = Arc::clone(auth);
    let peer = peer_ip;
    let fut = async {
        let mut pre_hello = PreHelloJunkTracker::default();
        loop {
            let m = ws
                .next()
                .await
                .context("eof during handshake")?
                .context("ws error")?;
            match m {
                Message::Binary(b) => {
                    let c = match account_pre_hello_binary(
                        b.as_ref(),
                        &mut pre_hello,
                        MAX_PRE_HELLO_FRAMES,
                        MAX_PRE_HELLO_BYTES,
                    )? {
                        Some(c) => c,
                        None => continue,
                    };
                    let secret = psk.context("Biba v3 requires server --psk")?;
                    info!("Biba v3 PSK mode, decoy_max={decoy_max}");
                    let (ack, s_rand) = crypto_layer::build_ack(secret, domain.as_str(), &c)?;
                    ws.send(Message::Binary(Bytes::from(ack)))
                        .await
                        .context("send v3 ACK")?;
                    let crypto = Arc::new(SessionCrypto::new(
                        secret,
                        domain.as_str(),
                        &c,
                        &s_rand,
                        decoy_max,
                    ));
                    let auth_c = Arc::clone(&auth_f);
                    server_wait_v3_auth(ws, &crypto, token, &auth_c, stats, peer, pre_auth)
                        .await?;
                    return Ok(crypto);
                }
                Message::Ping(p) => {
                    ws.send(Message::Pong(p)).await.context("pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => anyhow::bail!("closed during handshake"),
                _ => {}
            }
        }
    };
    match timeout(handshake_timeout, fut).await {
        Ok(Ok(crypto)) => Ok(crypto),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            stats.inc_handshake_timeout();
            auth_f.record_failure(peer).await;
            anyhow::bail!("handshake timeout");
        }
    }
}

async fn server_wait_v3_auth<S>(
    ws: &mut WebSocketStream<S>,
    crypto: &SharedCrypto,
    expected_token: &str,
    auth: &Arc<AuthRateLimiter>,
    stats: &Arc<ServerStats>,
    peer_ip: std::net::IpAddr,
    pre_auth: &PreAuthBudget,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use bibavpn::server_limits::PreAuthBudgetTracker;
    let mut tracker = PreAuthBudgetTracker::default();
    loop {
        let m = ws
            .next()
            .await
            .context("eof before v3 AUTH")?
            .context("ws read")?;
        match m {
            Message::Binary(b) => {
                if let Err(e) = tracker.note_binary_frame(b.len(), pre_auth) {
                    auth.record_failure(peer_ip).await;
                    return Err(e);
                }
                let raw = match crypto.open_client_to_server(b.as_ref()) {
                    Ok(x) => x,
                    Err(_) => {
                        if let Err(e) = tracker.note_decrypt_failure(pre_auth) {
                            auth.record_failure(peer_ip).await;
                            return Err(e);
                        }
                        continue;
                    }
                };
                let inner = read_padded_frame_into(raw).context("v3 auth frame")?;
                let tok = decode_v3_auth(&inner).context("decode v3 auth")?;
                if !crypto_layer::secret_eq(tok.as_str(), expected_token) {
                    auth.record_failure(peer_ip).await;
                    warn!(
                        target: "bibavpn_security",
                        %peer_ip,
                        "v3 auth token mismatch"
                    );
                    anyhow::bail!("v3 auth token mismatch");
                }
                auth.record_success(peer_ip).await;
                stats.inc_handshake_success();
                return Ok(());
            }
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.context("pong")?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => anyhow::bail!("closed before v3 AUTH"),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn transient_per_connection_accept_errors_retry_immediately() {
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
        ] {
            let r = classify_accept_error(&Error::from(kind));
            assert_eq!(r, AcceptRecovery::RetryNow, "kind {kind:?}");
            assert_eq!(r.backoff(), None, "kind {kind:?}");
            assert!(!r.is_exhaustion(), "kind {kind:?}");
        }
    }

    #[test]
    fn out_of_memory_accept_error_backs_off() {
        let r = classify_accept_error(&Error::from(ErrorKind::OutOfMemory));
        assert_eq!(r, AcceptRecovery::RetryAfterBackoff { exhaustion: true });
        assert_eq!(r.backoff(), Some(ACCEPT_BACKOFF));
    }

    #[test]
    fn unknown_accept_error_backs_off_without_exhaustion_flag() {
        let r = classify_accept_error(&Error::from(ErrorKind::PermissionDenied));
        assert_eq!(r, AcceptRecovery::RetryAfterBackoff { exhaustion: false });
        assert_eq!(r.backoff(), Some(ACCEPT_BACKOFF));
    }

    // Raw codes for the current platform: EMFILE, ENFILE, ENOMEM, ENOBUFS
    // (WSAEMFILE, WSAENOBUFS, WSAETOOMANYREFS on Windows). Most have no stable
    // `ErrorKind`, which is the case the raw-code rule exists for.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const EXHAUSTION_CODES: &[i32] = &[24, 23, 12, 105];
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    const EXHAUSTION_CODES: &[i32] = &[24, 23, 12, 55];
    #[cfg(windows)]
    const EXHAUSTION_CODES: &[i32] = &[10024, 10055, 10059];
    #[cfg(not(any(unix, windows)))]
    const EXHAUSTION_CODES: &[i32] = &[];

    #[test]
    fn descriptor_exhaustion_accept_errors_back_off() {
        for &code in EXHAUSTION_CODES {
            let r = classify_accept_error(&Error::from_raw_os_error(code));
            assert!(
                r.is_exhaustion(),
                "errno {code} should be exhaustion: {r:?}"
            );
            assert_eq!(r.backoff(), Some(ACCEPT_BACKOFF), "errno {code}");
        }
    }

    #[test]
    fn accept_backoff_is_short() {
        assert!(ACCEPT_BACKOFF >= Duration::from_millis(50));
        assert!(ACCEPT_BACKOFF <= Duration::from_millis(250));
    }
}

#[cfg(test)]
mod first_channel_wait_tests {
    use super::*;
    use bibavpn::crypto_layer::{build_ack, build_hello_v3, SessionCrypto};
    use bibavpn::frame::PadMode;
    use bibavpn::protocol::{
        encode_v3_mux_open, encode_v3_open_ok, encode_v3_open_with_flags, encode_v3_udp_mux_open,
    };
    use bibavpn::server_limits::AuthRateLimiterConfig;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use tokio_tungstenite::tungstenite::protocol::Role;

    fn test_crypto() -> SharedCrypto {
        let (c, _hello) = build_hello_v3();
        let psk = "test-psk";
        let dom = "test.domain";
        let (_ack, s) = build_ack(psk, dom, &c).unwrap();
        Arc::new(SessionCrypto::new(psk, dom, &c, &s, 8))
    }

    fn seal_client_frame(crypto: &SessionCrypto, inner: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        write_padded_frame_with_mode_state(&mut wire, inner, 8, PadMode::Random, None).unwrap();
        crypto.seal_client_to_server(&wire).unwrap()
    }

    async fn ws_pair() -> (
        WebSocketStream<tokio::io::DuplexStream>,
        WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
        let server = WebSocketStream::from_raw_socket(server_io, Role::Server, None).await;
        (client, server)
    }

    fn wait_ctx() -> (
        Arc<ServerStats>,
        Arc<AuthRateLimiter>,
        PreAuthBudget,
        IpAddr,
    ) {
        (
            ServerStats::new(),
            AuthRateLimiter::new(AuthRateLimiterConfig::default()),
            PreAuthBudget::default(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        )
    }

    #[tokio::test]
    async fn wait_first_channel_times_out_on_silent_peer() {
        let (_client, server) = ws_pair().await;
        let crypto = test_crypto();
        let (stats, auth, pre_auth, peer) = wait_ctx();
        let before = stats
            .handshake_timeouts_total
            .load(Ordering::Relaxed);

        let err = wait_first_channel_with_timeout(
            server,
            &crypto,
            &pre_auth,
            &auth,
            &stats,
            peer,
            1,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("handshake timeout waiting for OPEN / MUX_OPEN / UDP_MUX_OPEN"),
            "{err:#}"
        );
        assert_eq!(
            stats.handshake_timeouts_total.load(Ordering::Relaxed),
            before + 1
        );
    }

    #[tokio::test]
    async fn wait_first_channel_times_out_on_ping_only_peer() {
        let (mut client, server) = ws_pair().await;
        let crypto = test_crypto();
        let (stats, auth, pre_auth, peer) = wait_ctx();
        let before = stats
            .handshake_timeouts_total
            .load(Ordering::Relaxed);

        let client_task = tokio::spawn(async move {
            loop {
                client
                    .send(Message::Ping(Bytes::from_static(b"ping")))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let err = wait_first_channel_with_timeout(
            server,
            &crypto,
            &pre_auth,
            &auth,
            &stats,
            peer,
            2,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        client_task.abort();

        assert!(
            err.to_string()
                .contains("handshake timeout waiting for OPEN / MUX_OPEN / UDP_MUX_OPEN"),
            "{err:#}"
        );
        assert_eq!(
            stats.handshake_timeouts_total.load(Ordering::Relaxed),
            before + 1
        );
    }

    #[tokio::test]
    async fn wait_first_channel_accepts_mux_open() {
        let (mut client, server) = ws_pair().await;
        let crypto = test_crypto();
        let (stats, auth, pre_auth, peer) = wait_ctx();

        let sealed = seal_client_frame(&crypto, &encode_v3_mux_open());
        client
            .send(Message::Binary(Bytes::from(sealed)))
            .await
            .unwrap();

        let ch = wait_first_channel_with_timeout(
            server,
            &crypto,
            &pre_auth,
            &auth,
            &stats,
            peer,
            3,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert!(matches!(ch, FirstChannel::Mux { .. }));
        assert_eq!(
            stats.handshake_timeouts_total.load(Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn wait_first_channel_accepts_open_and_udp_mux_open() {
        let crypto = test_crypto();
        let (stats, auth, pre_auth, peer) = wait_ctx();

        let (mut client, server) = ws_pair().await;
        let open = encode_v3_open_with_flags("example.org", 443, OPEN_FLAG_STATUS).unwrap();
        client
            .send(Message::Binary(Bytes::from(
                seal_client_frame(&crypto, &open),
            )))
            .await
            .unwrap();
        let ch = wait_first_channel_with_timeout(
            server,
            &crypto,
            &pre_auth,
            &auth,
            &stats,
            peer,
            4,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(matches!(
            ch,
            FirstChannel::Tcp {
                ref host,
                port: 443,
                supports_open_status: true,
                ..
            } if host == "example.org"
        ));

        let (mut client, server) = ws_pair().await;
        client
            .send(Message::Binary(Bytes::from(seal_client_frame(
                &crypto,
                &encode_v3_udp_mux_open(),
            ))))
            .await
            .unwrap();
        let ch = wait_first_channel_with_timeout(
            server,
            &crypto,
            &pre_auth,
            &auth,
            &stats,
            peer,
            5,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(matches!(ch, FirstChannel::UdpMux { .. }));
    }

    #[tokio::test]
    async fn wait_first_channel_junk_budget_exceeded_before_timeout() {
        let (mut client, server) = ws_pair().await;
        let crypto = test_crypto();
        let stats = ServerStats::new();
        let auth = AuthRateLimiter::new(AuthRateLimiterConfig::default());
        let pre_auth = PreAuthBudget {
            max_junk_frames: 2,
            max_junk_bytes: 1024 * 1024,
            max_decrypt_failures: 64,
        };
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let junk = seal_client_frame(&crypto, &encode_v3_open_ok());

        for _ in 0..3 {
            client
                .send(Message::Binary(Bytes::from(junk.clone())))
                .await
                .unwrap();
        }

        let err = wait_first_channel_with_timeout(
            server,
            &crypto,
            &pre_auth,
            &auth,
            &stats,
            peer,
            6,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("too much pre-auth data before v3 AUTH"),
            "{err:#}"
        );
        assert_eq!(
            stats.handshake_timeouts_total.load(Ordering::Relaxed),
            0
        );
    }
}

