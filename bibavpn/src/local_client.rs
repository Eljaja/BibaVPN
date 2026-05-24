//! Shared SOCKS5 / HTTP CONNECT front-end for desktop binary and Android JNI.

use std::sync::{Arc, OnceLock};

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info};

use crate::client_tls_stream::ClientTlsStream;
use crate::crypto_layer::{self, SessionCrypto};
use crate::decoy_traffic::{run_one_decoy_get, spawn_decoy_gets, DecoyConfig};
use crate::desync;
use crate::frame::{AdaptivePadState, PadMode, DEFAULT_MAX_WS_BINARY};
use crate::http_connect;
use crate::protocol::{
    decode_v3_open_err, encode_v3_auth, encode_v3_mux_open, encode_v3_open_with_flags,
    is_v3_open_ok, OPEN_FLAG_STATUS,
};
use crate::retry::{sleep_outbound_backoff, OUTBOUND_CONNECT_ATTEMPTS};
use crate::ServerWsOutTiming;
use crate::stealth::{
    build_websocket_request, default_user_agent_for_profile, WsHandshakeParams,
    DEFAULT_ACCEPT_LANGUAGE,
};
use crate::activity::ActivityTracker;
use crate::stealth_v12::{DecoyMode, DesyncMode, StealthProfile, TcpFooling};
use crate::tcp_mux::{
    self, MuxClientConfig, MuxOpenStreamDropped, TcpMuxClientSlot,
    TcpMuxSessionPool,
};
use crate::tls_util::{client_tls_config, ClientTlsParams, TlsClientProfile, TlsStack};
use crate::udp_mux::{spawn_udp_mux_driver, UdpMuxConfig, UdpMuxHandle};
use crate::ws_bridge::{self, TunnelEnd};
use crate::{
    read_padded_frame_into, write_padded_frame_with_mode_state, socks5,
    socks5::SocksCommand,
};
use bytes::Bytes;

/// SOCKS UDP: limit concurrent in-flight mux requests per datagram worker pool.
const SOCKS_UDP_WORKERS: usize = 256;

fn tcp_mux_connect_serial() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

async fn tcp_mux_slot_has_sessions(slot: &TcpMuxSlot) -> bool {
    let g = slot.lock().await;
    match g.as_ref() {
        Some(pool) => !pool.sessions.lock().await.is_empty(),
        None => false,
    }
}

/// After the shared mux WSS dies, reopen quickly without the full outbound backoff ladder.
const TCP_MUX_SLOT_RETRIES: u32 = 8;
const OPEN_STATUS_WAIT: Duration = Duration::from_millis(350);

async fn sleep_mux_slot_retry(attempt: u32) {
    let ms = (50u64 * (attempt as u64 + 1)).min(800);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

fn tcp_mux_writer_gone(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.downcast_ref::<crate::tcp_mux::MuxWriterStopped>().is_some())
        || format!("{e:#}").contains("tcp mux writer stopped")
}

type TcpMuxSlot = TcpMuxClientSlot;

async fn tcp_mux_open_stream_with_retry(
    mut local: TcpStream,
    host: String,
    port: u16,
    tcp_uplink_prefix: Vec<u8>,
    cfg: Arc<ClientCfg>,
    tcp_mux_slot: TcpMuxSlot,
) -> anyhow::Result<()> {
    for attempt in 0..TCP_MUX_SLOT_RETRIES {
        if tcp_mux_slot.lock().await.is_none() {
            connect_tcp_mux_handle(&cfg, &tcp_mux_slot).await?;
        }
        let h = {
            let slot = tcp_mux_slot.lock().await;
            let Some(pool) = slot.as_ref() else {
                drop(slot);
                continue;
            };
            pool.pick().await
        };
        let Some(h) = h else {
            *tcp_mux_slot.lock().await = None;
            sleep_mux_slot_retry(attempt).await;
            continue;
        };
        match h
            .open_stream(local, host.clone(), port, tcp_uplink_prefix.clone())
            .await
        {
            Ok(()) => return Ok(()),
            Err(MuxOpenStreamDropped { local: l, err }) => {
                if tcp_mux_writer_gone(&err) {
                    let mut slot = tcp_mux_slot.lock().await;
                    *slot = None;
                    local = l;
                    if attempt + 1 >= TCP_MUX_SLOT_RETRIES {
                        return Err(err);
                    }
                    sleep_mux_slot_retry(attempt).await;
                } else {
                    return Err(err);
                }
            }
        }
    }
    Err(anyhow::anyhow!("tcp mux: open stream retries exhausted"))
}

/// User-facing options (CLI, JSON over JNI, etc.).
#[derive(Clone, Debug)]
pub struct LocalClientOptions {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    pub token: String,
    pub socks_bind: String,
    /// When set, SOCKS5 listener requires RFC 1929 username/password (no no-auth).
    pub socks_auth: Option<(String, String)>,
    pub http_proxy_bind: Option<String>,
    /// Passed through for decoy GETs and logging.
    pub insecure_tls: bool,
    pub max_pad: u8,
    pub junk_frames: u32,
    pub early_ws_frames: u8,
    pub psk: Option<String>,
    pub decoy_max: u8,
    pub ws_host: Option<String>,
    pub ws_origin: Option<String>,
    pub ws_user_agent: Option<String>,
    pub ws_accept_language: Option<String>,
    pub ws_extra_headers: Arc<Vec<(String, String)>>,
    pub max_ws_binary: usize,
    pub ws_ping_secs: u64,
    /// Vary WS ping interval ± this percent (0–50).
    pub ws_ping_jitter_percent: u8,
    /// Random 0..=N ms before each outbound WS binary (TCP tunnel + UDP mux client path).
    pub ws_binary_send_jitter_ms: u8,
    /// If both non-zero and `min <= max`, delay each outbound WS binary by a random ms in this range.
    pub ws_jitter_min_ms: u8,
    pub ws_jitter_max_ms: u8,
    /// Padding cap for UDP mux only (default: same as `max_pad`).
    pub udp_max_pad: Option<u8>,
    /// MTU cap for UDP mux only (default: same as `max_ws_binary`).
    pub udp_max_ws_binary: Option<usize>,
    /// Max seconds to wait for a UDP mux reply per SOCKS datagram (`0` = unlimited).
    pub udp_mux_reply_timeout_secs: u64,
    /// `biba` / uTLS-style rustls hints (cipher order + ALPN). Also set from `biba://` invite.
    pub tls_profile: TlsClientProfile,
    /// PEM bytes (`CERTIFICATE` blocks). Leaf must match one DER exactly; mutually exclusive with `insecure_tls`.
    pub pinned_certs_pem: Option<Vec<u8>>,
    /// WebSocket HTTP path; token is sent in AUTH frame, not in URL (default `/ws`).
    pub ws_path: String,
    /// Multiplex SOCKS TCP over one WSS (default true). Set false for legacy per-connection tunnels.
    pub use_tcp_mux: bool,
    pub pad_mode: PadMode,
    /// Idle dummy WSS binary interval (0 = off).
    pub dummy_interval_secs: u64,
    /// Parallel decoy HTTPS GETs to the same server (camouflage).
    pub decoy_gets: bool,
    pub decoy_gets_interval_secs: u64,
    pub decoy_gets_paths: Vec<String>,
    /// Wire protocol: only `3` (opaque PSK hello + sealed control; requires PSK).
    pub proto: u8,
    /// Domain label for v3 PSK KDF; empty = use `sni`.
    pub proto_domain: String,
    /// REALITY: front domain / SNI (e.g. vk.com).
    pub reality_target: Option<String>,
    /// REALITY: server's public key (32 bytes).
    pub reality_public_key: Option<[u8; 32]>,
    /// REALITY: short ID (8 bytes).
    pub reality_short_id: Option<[u8; 8]>,
    /// Richer decoy HTTP (see `decoy_traffic`).
    pub decoy_mode: DecoyMode,
    /// Raw-socket desync modes: mostly logged until a platform hook exists.
    pub desync_mode: DesyncMode,
    pub tcp_fooling: TcpFooling,
    /// Log-only: TLS record fragmentation is not implemented for rustls.
    pub tls_fragment: bool,
    /// Parallel full mux sessions to the same server (round-robin new SOCKS streams); 1–4.
    pub ws_parallel: u8,
    /// After this many seconds without main decoy activity, emit an extra browser-style decoy (0 = off).
    pub idle_decoy_secs: u64,
    /// When set (e.g. from CLI), overrides individual knob defaults for stealth presets.
    pub stealth_profile: Option<StealthProfile>,
    /// `rustls` (default) or `boring` (BoringSSL; build with `boring-tls` feature).
    pub tls_stack: TlsStack,
}

#[derive(Clone)]
struct ClientCfg {
    server_host: String,
    server_port: u16,
    sni: String,
    token: String,
    insecure_tls: bool,
    tls: Arc<rustls::ClientConfig>,
    max_pad: u8,
    junk_frames: u32,
    early_ws_frames: u8,
    psk: Option<String>,
    decoy_max: u8,
    ws_host: Option<String>,
    ws_origin: Option<String>,
    ws_user_agent: Option<String>,
    ws_accept_language: Option<String>,
    ws_extra_headers: Arc<Vec<(String, String)>>,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    ws_jitter_min_ms: u8,
    ws_jitter_max_ms: u8,
    udp_mux_max_pad: u8,
    udp_mux_max_ws_binary: usize,
    udp_mux_reply_timeout_secs: u64,
    tls_profile: TlsClientProfile,
    ws_path: String,
    use_tcp_mux: bool,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
    decoy_gets: bool,
    decoy_gets_interval_secs: u64,
    decoy_gets_paths: Vec<String>,
    proto: u8,
    proto_domain: String,
    reality_target: Option<String>,
    reality_public_key: Option<[u8; 32]>,
    reality_short_id: Option<[u8; 8]>,
    decoy_mode: DecoyMode,
    desync_mode: DesyncMode,
    tcp_fooling: TcpFooling,
    tls_fragment: bool,
    ws_parallel: u8,
    idle_decoy_secs: u64,
    /// Mux read/write activity for `idle_decoy_secs` (only set when that feature is on).
    activity: Option<Arc<ActivityTracker>>,
    socks_auth: Option<(String, String)>,
    tls_stack: TlsStack,
    /// Used to reject Boring + pin until that combination is supported.
    pinned_certs_pem: Option<Vec<u8>>,
}

impl ClientCfg {
    fn udp_mux_config(&self) -> UdpMuxConfig {
        UdpMuxConfig {
            server_host: self.server_host.clone(),
            server_port: self.server_port,
            sni: self.sni.clone(),
            token: self.token.clone(),
            tls: self.tls.clone(),
            max_pad: self.udp_mux_max_pad,
            junk_frames: self.junk_frames,
            early_ws_frames: self.early_ws_frames,
            psk: self.psk.clone(),
            decoy_max: self.decoy_max,
            ws_host: self.ws_host.clone(),
            ws_origin: self.ws_origin.clone(),
            ws_user_agent: self.ws_user_agent.clone(),
            ws_accept_language: self.ws_accept_language.clone(),
            ws_extra_headers: self.ws_extra_headers.clone(),
            max_ws_binary: self.udp_mux_max_ws_binary,
            ws_ping_secs: self.ws_ping_secs,
            ws_ping_jitter_percent: self.ws_ping_jitter_percent,
            ws_binary_send_jitter_ms: self.ws_binary_send_jitter_ms,
            ws_jitter_min_ms: self.ws_jitter_min_ms,
            ws_jitter_max_ms: self.ws_jitter_max_ms,
            tls_profile: self.tls_profile,
            ws_path: self.ws_path.clone(),
            pad_mode: self.pad_mode,
            proto: self.proto,
            proto_domain: self.proto_domain.clone(),
            reality_public_key: self.reality_public_key,
            reality_short_id: self.reality_short_id,
        }
    }
}

fn effective_proto_domain(cfg: &ClientCfg) -> String {
    let t = cfg.proto_domain.trim();
    if t.is_empty() {
        "default".to_string()
    } else {
        t.to_string()
    }
}

pub fn normalize_ws_path(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        return "/ws".to_string();
    }
    if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

/// REALITY handshake: send client hello with public key + short ID, receive server hello
async fn reality_client_handshake<S>(
    ws: &mut WebSocketStream<S>,
    cfg: &ClientCfg,
) -> anyhow::Result<([u8; 32], [u8; 8])>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let server_expected_pubkey = cfg
        .reality_public_key
        .ok_or_else(|| anyhow::anyhow!("REALITY: no server public key configured"))?;

    let short_id = cfg.reality_short_id.unwrap_or_else(|| rand::random::<[u8; 8]>());

    let session_key =
        crate::reality::reality_client_exchange_verify(ws, &server_expected_pubkey, &short_id)
            .await?;

    info!("REALITY handshake complete, session key derived, server verified");

    Ok((session_key, short_id))
}

type SharedCrypto = Arc<SessionCrypto>;

type ClientWs = WebSocketStream<ClientTlsStream>;

async fn upgrade_client_tls(cfg: &ClientCfg, tcp: TcpStream) -> anyhow::Result<ClientTlsStream> {
    desync::after_tcp_connect(&tcp, cfg.desync_mode, cfg.tcp_fooling).await?;
    desync::note_tls_fragment_requested(cfg.tls_fragment);

    match cfg.tls_stack {
        TlsStack::Rustls => {
            let domain = ServerName::try_from(cfg.sni.clone())?;
            let connector = tokio_rustls::TlsConnector::from(cfg.tls.clone());
            let t = connector
                .connect(domain, tcp)
                .await
                .context("tls (rustls)")?;
            Ok(ClientTlsStream::Rustls(t))
        }
        TlsStack::Boring => {
            #[cfg(feature = "boring-tls")]
            {
                let params = crate::tls_boring::BoringTlsParams {
                    insecure: cfg.insecure_tls,
                    pinned_certs_pem: cfg.pinned_certs_pem.clone(),
                    tls_fragment: cfg.tls_fragment,
                };
                let t = crate::tls_boring::upgrade_tcp_boring(tcp, &cfg.sni, &params)
                    .await
                    .context("tls (boring)")?;
                Ok(ClientTlsStream::Boring(t))
            }
            #[cfg(not(feature = "boring-tls"))]
            {
                Err(anyhow::anyhow!(
                    "Boring stack not compiled: build with `cargo build -p bibavpn --features boring-tls`"
                ))
            }
        }
    }
}

/// TCP + TLS + WebSocket upgrade (no v3 / REALITY application frames).
async fn dial_outer_wss(cfg: &ClientCfg, log_context: &str) -> anyhow::Result<ClientWs> {
    let path = cfg.ws_path.clone();
    let tcp =
        crate::outbound_protect::tcp_connect_host_protected(&cfg.server_host, cfg.server_port)
            .await
            .with_context(|| format!("connect server {}:{}", cfg.server_host, cfg.server_port))?;
    let _ = tcp.set_nodelay(true);
    let tls = upgrade_client_tls(cfg, tcp).await?;

    let ws_host = cfg
        .ws_host
        .as_deref()
        .or(if cfg.reality_target.is_some() {
            Some(cfg.sni.as_str())
        } else {
            None
        });
    let ws_origin = cfg.ws_origin.as_deref();
    let ws_ua = cfg.ws_user_agent.as_deref();
    let ws_al = cfg.ws_accept_language.as_deref();
    let extra = cfg.ws_extra_headers.as_ref().clone();
    let req = build_websocket_request(WsHandshakeParams {
        host_for_tcp: &cfg.server_host,
        port: cfg.server_port,
        path: &path,
        sni: &cfg.sni,
        host_header: ws_host,
        origin: ws_origin,
        user_agent: ws_ua,
        accept_language: ws_al,
        extra_headers: &extra,
        tls_profile: cfg.tls_profile,
    });

    let (ws, _) = tokio_tungstenite::client_async(req, tls)
        .await
        .map_err(|e| anyhow::anyhow!(e))
        .context("websocket")?;

    info!(
        target: "bibavpn_client",
        server = %cfg.server_host,
        port = cfg.server_port,
        sni = %cfg.sni,
        path = %path,
        context = log_context,
        "outer WSS up"
    );
    Ok(ws)
}

/// One attempt: TCP + TLS + WS + noise + v3 hello + sealed AUTH.
async fn one_try_wss_session(cfg: &ClientCfg) -> anyhow::Result<(ClientWs, SharedCrypto)> {
    anyhow::ensure!(cfg.proto >= 3, "only Biba protocol v3 is supported (use --proto 3)");
    anyhow::ensure!(cfg.psk.is_some(), "Biba v3 requires --psk (or invite psk)");

    let mut ws = dial_outer_wss(cfg, "v3 tunnel").await?;

    info!(
        target: "bibavpn_client",
        proto = cfg.proto,
        "WSS handshake OK, sending noise + auth / v3 hello"
    );

    send_noise_binaries(&mut ws, u32::from(cfg.early_ws_frames), cfg.max_ws_binary).await?;
    send_noise_binaries(&mut ws, cfg.junk_frames, cfg.max_ws_binary)
        .await
        .context("junk frames")?;

    let secret = cfg.psk.as_ref().expect("psk checked");
    let dom = effective_proto_domain(cfg);
    let (c_rand, hello) = crypto_layer::build_hello_v3();
    ws.send(Message::Binary(Bytes::from(hello)))
        .await
        .context("send v3 HELLO")?;
    loop {
        let m = ws.next().await.context("eof before ACK")??;
        match m {
            Message::Binary(b) => {
                let s_rand =
                    crypto_layer::parse_ack(secret, dom.as_str(), b.as_ref(), &c_rand)?;
                let crypto = Arc::new(SessionCrypto::new(
                    secret,
                    dom.as_str(),
                    &c_rand,
                    &s_rand,
                    cfg.decoy_max,
                ));
                let mut pad_st = AdaptivePadState::default();
                let auth_inner = encode_v3_auth(&cfg.token).context("encode v3 AUTH")?;
                let mut wire = Vec::new();
                write_padded_frame_with_mode_state(
                    &mut wire,
                    &auth_inner,
                    cfg.max_pad,
                    cfg.pad_mode,
                    Some(&mut pad_st),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                let blob = crypto
                    .seal_client_to_server(&wire)
                    .context("seal v3 AUTH")?;
                ws.send(Message::Binary(Bytes::from(blob)))
                    .await
                    .context("send v3 AUTH")?;
                return Ok((ws, crypto));
            }
            Message::Pong(_) => continue,
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.context("pong")?;
            }
            Message::Close(_) => anyhow::bail!("ws closed before ACK"),
            _ => {}
        }
    }
}

async fn wait_open_status_or_payload<S>(
    ws: &mut WebSocketStream<S>,
    crypto: &SharedCrypto,
) -> anyhow::Result<Vec<Message>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let m = ws.next().await.context("eof before OPEN result")??;
        match m {
            Message::Binary(b) => {
                let raw = crypto
                    .open_server_to_client(b.as_ref())
                    .context("decrypt OPEN status")?;
                let inner = read_padded_frame_into(raw).context("padded OPEN status")?;
                if is_v3_open_ok(&inner) {
                    return Ok(Vec::new());
                }
                if let Ok(err) = decode_v3_open_err(&inner) {
                    anyhow::bail!("remote OPEN failed: {err}");
                }
                return Ok(vec![Message::Binary(Bytes::from(inner))]);
            }
            Message::Ping(p) => {
                ws.send(Message::Pong(p))
                    .await
                    .context("pong during OPEN wait")?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => anyhow::bail!("closed before OPEN result"),
            other => return Ok(vec![other]),
        }
    }
}

async fn open_legacy_biba_channel(
    cfg: &Arc<ClientCfg>,
    host: &str,
    port: u16,
) -> anyhow::Result<(ClientWs, SharedCrypto, Vec<Message>)> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..OUTBOUND_CONNECT_ATTEMPTS {
        match one_try_wss_session(cfg).await {
            Ok((mut ws, crypto)) => {
                let open = encode_v3_open_with_flags(host, port, OPEN_FLAG_STATUS)?;
                let mut wire = Vec::new();
                let mut pad_st = AdaptivePadState::default();
                write_padded_frame_with_mode_state(
                    &mut wire,
                    &open,
                    cfg.max_pad,
                    cfg.pad_mode,
                    Some(&mut pad_st),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                let blob = crypto
                    .seal_client_to_server(&wire)
                    .context("seal OPEN v3")?;
                if blob.len() > cfg.max_ws_binary {
                    anyhow::bail!("sealed OPEN exceeds --max-ws-binary");
                }
                ws.send(Message::Binary(Bytes::from(blob)))
                    .await
                    .context("send OPEN v3")?;
                let prefetched = match timeout(
                    OPEN_STATUS_WAIT,
                    wait_open_status_or_payload(&mut ws, &crypto),
                )
                .await
                {
                    Ok(res) => res?,
                    Err(_) => Vec::new(),
                };
                return Ok((ws, crypto, prefetched));
            }
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 >= OUTBOUND_CONNECT_ATTEMPTS {
                    break;
                }
                sleep_outbound_backoff(attempt).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("tunnel: connect failed")))
}

async fn connect_tcp_mux_handle(
    cfg: &Arc<ClientCfg>,
    tcp_mux_slot: &TcpMuxSlot,
) -> anyhow::Result<()> {
    // Check if REALITY mode is enabled
    if cfg.reality_target.is_some() {
        return connect_reality_tcp_mux_handle(cfg, tcp_mux_slot).await;
    }

    let _connect_serial = tcp_mux_connect_serial().lock().await;
    if tcp_mux_slot_has_sessions(tcp_mux_slot).await {
        return Ok(());
    }

    let n = cfg.ws_parallel.max(1).min(4) as usize;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..OUTBOUND_CONNECT_ATTEMPTS {
        let res: anyhow::Result<()> = async {
            let mut sessions = Vec::with_capacity(n);
            for _ in 0..n {
                let (mut ws, crypto) = one_try_wss_session(cfg).await?;
                let mo = encode_v3_mux_open();
                let mut wire = Vec::new();
                let mut pad_st = AdaptivePadState::default();
                write_padded_frame_with_mode_state(
                    &mut wire,
                    &mo,
                    cfg.max_pad,
                    cfg.pad_mode,
                    Some(&mut pad_st),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                let blob = crypto
                    .seal_client_to_server(&wire)
                    .context("seal MUX_OPEN v3")?;
                if blob.len() > cfg.max_ws_binary {
                    anyhow::bail!("sealed MUX_OPEN exceeds --max-ws-binary");
                }
                ws.send(Message::Binary(Bytes::from(blob)))
                    .await
                    .context("send MUX_OPEN v3")?;
                let mcfg = MuxClientConfig {
                    max_pad: cfg.max_pad,
                    decoy_max: cfg.decoy_max,
                    max_ws_binary: cfg.max_ws_binary,
                    ws_ping_secs: cfg.ws_ping_secs,
                    ws_ping_jitter_percent: cfg.ws_ping_jitter_percent,
                    ws_binary_send_jitter_ms: cfg.ws_binary_send_jitter_ms,
                    ws_jitter_min_ms: cfg.ws_jitter_min_ms,
                    ws_jitter_max_ms: cfg.ws_jitter_max_ms,
                    transport_v2: true,
                    pad_mode: cfg.pad_mode,
                    dummy_interval_secs: cfg.dummy_interval_secs,
                    activity: cfg.activity.clone(),
                };
                let (sid, h) = tcp_mux::spawn_tcp_mux_client(
                    ws,
                    Some(crypto),
                    mcfg,
                    tcp_mux_slot.clone(),
                );
                sessions.push((sid, h));
                info!(
                    target: "bibavpn_client",
                    session_id = sid,
                    server = %cfg.server_host,
                    port = cfg.server_port,
                    parallel = n,
                    "TCP mux WSS ready"
                );
            }
            *tcp_mux_slot.lock().await = Some(TcpMuxSessionPool::from_sessions(sessions));
            Ok(())
        }
        .await;
        match res {
            Ok(()) => return Ok(()),
            Err(e) => {
                *tcp_mux_slot.lock().await = None;
                last_err = Some(e);
                if attempt + 1 >= OUTBOUND_CONNECT_ATTEMPTS {
                    break;
                }
                sleep_outbound_backoff(attempt).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("tcp mux: connect failed")))
}

/// REALITY mode: one or more parallel WSS sessions (same as non-REALITY multi-WSS), each with REALITY handshake + MUX_OPEN.
async fn connect_reality_tcp_mux_handle(
    cfg: &Arc<ClientCfg>,
    tcp_mux_slot: &TcpMuxSlot,
) -> anyhow::Result<()> {
    use tokio_tungstenite::tungstenite::Message;

    let _connect_serial = tcp_mux_connect_serial().lock().await;
    if tcp_mux_slot_has_sessions(tcp_mux_slot).await {
        return Ok(());
    }

    let n = cfg.ws_parallel.max(1).min(4) as usize;
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..OUTBOUND_CONNECT_ATTEMPTS {
        let res: anyhow::Result<()> = async {
            let _target = cfg.reality_target.as_ref().expect("reality target");
            let mut sessions = Vec::with_capacity(n);

            for _ in 0..n {
                let mut ws = dial_outer_wss(cfg, "REALITY mux").await?;

                info!(
                    target: "bibavpn_client",
                    server = %cfg.server_host,
                    port = cfg.server_port,
                    parallel = n,
                    "REALITY: WSS up, key exchange"
                );

                let (_session_key, short_id) = reality_client_handshake(&mut ws, cfg).await?;

                info!(
                    "REALITY: handshake complete, short_id={:02x?}",
                    &short_id[..4]
                );

                let open = encode_v3_mux_open();
                ws.send(Message::Binary(Bytes::from(open)))
                    .await
                    .context("send MUX_OPEN v3 (REALITY)")?;

                let mcfg = MuxClientConfig {
                    max_pad: cfg.max_pad,
                    decoy_max: cfg.decoy_max,
                    max_ws_binary: cfg.max_ws_binary,
                    ws_ping_secs: cfg.ws_ping_secs,
                    ws_ping_jitter_percent: cfg.ws_ping_jitter_percent,
                    ws_binary_send_jitter_ms: cfg.ws_binary_send_jitter_ms,
                    ws_jitter_min_ms: cfg.ws_jitter_min_ms,
                    ws_jitter_max_ms: cfg.ws_jitter_max_ms,
                    transport_v2: false,
                    pad_mode: cfg.pad_mode,
                    dummy_interval_secs: cfg.dummy_interval_secs,
                    activity: cfg.activity.clone(),
                };

                let (sid, h) =
                    tcp_mux::spawn_tcp_mux_client(ws, None, mcfg, tcp_mux_slot.clone());
                sessions.push((sid, h));
                info!(
                    target: "bibavpn_client",
                    session_id = sid,
                    server = %cfg.server_host,
                    parallel = n,
                    "REALITY tunnel ready"
                );
            }
            *tcp_mux_slot.lock().await = Some(TcpMuxSessionPool::from_sessions(sessions));
            Ok(())
        }
        .await;

        match res {
            Ok(()) => return Ok(()),
            Err(e) => {
                *tcp_mux_slot.lock().await = None;
                last_err = Some(e);
                if attempt + 1 >= OUTBOUND_CONNECT_ATTEMPTS {
                    break;
                }
                sleep_outbound_backoff(attempt).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("REALITY tcp mux: connect failed")))
}

/// Build TLS config and run SOCKS5 (+ optional HTTP CONNECT) until `shutdown` becomes `true`.
///
/// `socks_ready`: if set, `()` is sent once `socks_bind` is listening (before any `accept`).
pub async fn run_local_client(
    opts: LocalClientOptions,
    mut shutdown: watch::Receiver<bool>,
    socks_ready: Option<std::sync::mpsc::Sender<()>>,
) -> anyhow::Result<()> {
    if opts.insecure_tls {
        info!("TLS: certificate verification disabled (lab only)");
    }
    if opts.tls_profile != TlsClientProfile::default() {
        info!("TLS client profile: {:?}", opts.tls_profile);
    }
    if opts.pinned_certs_pem.is_some() {
        info!("TLS: certificate pinning enabled (leaf must match PEM)");
    }
    if opts.socks_auth.is_some() {
        info!("SOCKS5: username/password required on local listener");
    }
    if opts.socks_auth.is_some() && opts.http_proxy_bind.is_some() {
        tracing::warn!(
            "HTTP local proxy has no auth handshake; SOCKS username/password applies only to the SOCKS port"
        );
    }

    let ws_parallel = opts.ws_parallel.max(1).min(4);
    let activity = if opts.use_tcp_mux && opts.idle_decoy_secs > 0 {
        Some(Arc::new(ActivityTracker::new()))
    } else {
        None
    };

    let tls = client_tls_config(&ClientTlsParams {
        insecure: opts.insecure_tls,
        profile: opts.tls_profile,
        pinned_certs_pem: opts.pinned_certs_pem.clone(),
    })?;

    let udp_mux_max_pad = opts.udp_max_pad.unwrap_or(opts.max_pad);
    let udp_mux_max_ws_binary = opts.udp_max_ws_binary.unwrap_or(opts.max_ws_binary);

    if opts.psk.is_some() {
        info!(
            "Biba v3 PSK mode, decoy_max={}, max_ws_binary={}, ws_ping_secs={}",
            opts.decoy_max, opts.max_ws_binary, opts.ws_ping_secs
        );
    }
    if opts.use_tcp_mux {
        if ws_parallel > 1 {
            info!(
                "TCP mode: multiplexed WSS, {ws_parallel} parallel outer connection(s) (round-robin new streams)"
            );
        } else {
            info!("TCP mode: multiplexed WSS (one outer connection)");
        }
    } else {
        info!("TCP mode: legacy per-connection WSS (--no-mux)");
    }
    if opts.tls_stack != TlsStack::Rustls {
        info!("outer TLS stack: {:?}", opts.tls_stack);
    }

    info!(
        target: "bibavpn_client",
        server = %opts.server_host,
        port = opts.server_port,
        sni = %opts.sni,
        socks_bind = %opts.socks_bind,
        http_proxy = ?opts.http_proxy_bind,
        use_tcp_mux = opts.use_tcp_mux,
        ws_path = %normalize_ws_path(&opts.ws_path),
        "local client starting"
    );

    let cfg = Arc::new(ClientCfg {
        server_host: opts.server_host.clone(),
        server_port: opts.server_port,
        sni: crate::reality::effective_tls_sni(&opts.sni, opts.reality_target.as_deref()),
        token: opts.token,
        insecure_tls: opts.insecure_tls,
        tls,
        max_pad: opts.max_pad,
        junk_frames: opts.junk_frames,
        early_ws_frames: opts.early_ws_frames,
        psk: opts.psk,
        decoy_max: opts.decoy_max,
        ws_host: opts.ws_host,
        ws_origin: opts.ws_origin,
        ws_user_agent: opts.ws_user_agent,
        ws_accept_language: opts.ws_accept_language,
        ws_extra_headers: opts.ws_extra_headers,
        max_ws_binary: opts.max_ws_binary,
        ws_ping_secs: opts.ws_ping_secs,
        ws_ping_jitter_percent: opts.ws_ping_jitter_percent,
        ws_binary_send_jitter_ms: opts.ws_binary_send_jitter_ms,
        ws_jitter_min_ms: opts.ws_jitter_min_ms,
        ws_jitter_max_ms: opts.ws_jitter_max_ms,
        udp_mux_max_pad,
        udp_mux_max_ws_binary,
        udp_mux_reply_timeout_secs: opts.udp_mux_reply_timeout_secs,
        tls_profile: opts.tls_profile,
        ws_path: normalize_ws_path(&opts.ws_path),
        use_tcp_mux: opts.use_tcp_mux,
        pad_mode: opts.pad_mode,
        dummy_interval_secs: opts.dummy_interval_secs,
        decoy_gets: opts.decoy_gets,
        decoy_gets_interval_secs: opts.decoy_gets_interval_secs,
        decoy_gets_paths: opts.decoy_gets_paths.clone(),
        proto: opts.proto,
        proto_domain: opts.proto_domain.clone(),
        reality_target: opts.reality_target.clone(),
        reality_public_key: opts.reality_public_key,
        reality_short_id: opts.reality_short_id,
        decoy_mode: opts.decoy_mode,
        desync_mode: opts.desync_mode,
        tcp_fooling: opts.tcp_fooling,
        tls_fragment: opts.tls_fragment,
        ws_parallel,
        idle_decoy_secs: opts.idle_decoy_secs,
        activity,
        socks_auth: opts.socks_auth.clone(),
        tls_stack: opts.tls_stack,
        pinned_certs_pem: opts.pinned_certs_pem.clone(),
    });

    if cfg.decoy_gets {
        let ua = cfg
            .ws_user_agent
            .clone()
            .unwrap_or_else(|| default_user_agent_for_profile(cfg.tls_profile).to_string());
        let al = cfg
            .ws_accept_language
            .clone()
            .unwrap_or_else(|| DEFAULT_ACCEPT_LANGUAGE.to_string());
        spawn_decoy_gets(
            DecoyConfig {
                server_host: cfg.server_host.clone(),
                server_port: cfg.server_port,
                sni: cfg.sni.clone(),
                insecure: cfg.insecure_tls,
                tls_profile: cfg.tls_profile,
                pinned_certs_pem: opts.pinned_certs_pem.clone(),
                interval_secs: cfg.decoy_gets_interval_secs.max(5),
                paths: cfg.decoy_gets_paths.clone(),
                user_agent: ua,
                accept_language: al,
                mode: cfg.decoy_mode,
            },
            shutdown.clone(),
        );
    }

    if let Some(ref act) = cfg.activity {
        if cfg.idle_decoy_secs > 0 {
            let idle_s = cfg.idle_decoy_secs;
            let ua = cfg
                .ws_user_agent
                .clone()
                .unwrap_or_else(|| default_user_agent_for_profile(cfg.tls_profile).to_string());
            let al = cfg
                .ws_accept_language
                .clone()
                .unwrap_or_else(|| DEFAULT_ACCEPT_LANGUAGE.to_string());
            let decoy = DecoyConfig {
                server_host: cfg.server_host.clone(),
                server_port: cfg.server_port,
                sni: cfg.sni.clone(),
                insecure: cfg.insecure_tls,
                tls_profile: cfg.tls_profile,
                pinned_certs_pem: opts.pinned_certs_pem.clone(),
                interval_secs: idle_s.max(5),
                paths: cfg.decoy_gets_paths.clone(),
                user_agent: ua,
                accept_language: al,
                mode: cfg.decoy_mode,
            };
            let act = act.clone();
            let mut sd = shutdown.clone();
            info!(
                "idle decoy: after {} s without tunneled traffic, issue HTTPS GET (mode {:?})",
                idle_s, cfg.decoy_mode
            );
            tokio::spawn(async move {
                loop {
                    if *sd.borrow() {
                        break;
                    }
                    tokio::select! {
                        _ = sd.changed() => { if *sd.borrow() { break; } }
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {
                            if act.idle_secs() >= idle_s {
                                run_one_decoy_get(&decoy).await;
                                tokio::time::sleep(Duration::from_secs(idle_s.max(5))).await;
                            }
                        }
                    }
                }
            });
        }
    }

    let udp_mux_slot: Arc<Mutex<Option<UdpMuxHandle>>> = Arc::new(Mutex::new(None));
    let tcp_mux_slot: TcpMuxSlot = Arc::new(Mutex::new(None));

    let socks_listener = TcpListener::bind(&opts.socks_bind)
        .await
        .with_context(|| format!("bind socks {}", opts.socks_bind))?;
    info!("SOCKS5 on {}", opts.socks_bind);
    if let Some(tx) = socks_ready {
        let _ = tx.send(());
    }

    if let Some(ref http_bind) = opts.http_proxy_bind {
        let http_listener = TcpListener::bind(http_bind)
            .await
            .with_context(|| format!("bind http proxy {http_bind}"))?;
        info!("HTTP proxy (CONNECT + http:// forward) on {http_bind}");
        let cfg_http = cfg.clone();
        let tcp_mux_http = tcp_mux_slot.clone();
        let mut shutdown_http = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_http.changed() => {
                        if *shutdown_http.borrow() {
                            break;
                        }
                    }
                    res = http_listener.accept() => {
                        match res {
                            Ok((sock, peer)) => {
                                let c = cfg_http.clone();
                                let tms = tcp_mux_http.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_http_peer(sock, c, tms).await {
                                        error!("http {peer}: {e:#}");
                                    }
                                });
                            }
                            Err(e) => {
                                error!("http accept: {e:#}");
                            }
                        }
                    }
                }
            }
        });
    }

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("local client shutdown");
                    return Ok(());
                }
            }
            res = socks_listener.accept() => {
                let (sock, peer) = res.context("socks accept")?;
                let c = cfg.clone();
                let ums = udp_mux_slot.clone();
                let tms = tcp_mux_slot.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks_peer(sock, c, ums, tms).await {
                        error!("socks {peer}: {e:#}");
                    }
                });
            }
        }
    }
}

pub fn parse_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    let s = s.trim();
    if let Some(i) = s.rfind(':') {
        let (h, p) = s.split_at(i);
        let p = p.trim_start_matches(':').parse::<u16>()?;
        return Ok((h.to_string(), p));
    }
    anyhow::bail!("expected host:port, got {s}");
}

pub fn parse_ws_header(line: &str) -> anyhow::Result<(String, String)> {
    let (k, v) = line
        .split_once(':')
        .with_context(|| format!("--ws-header must be 'Name: value', got {line:?}"))?;
    Ok((k.trim().to_string(), v.trim().to_string()))
}

async fn handle_socks_peer(
    mut local: TcpStream,
    cfg: Arc<ClientCfg>,
    udp_mux_slot: Arc<Mutex<Option<UdpMuxHandle>>>,
    tcp_mux_slot: TcpMuxSlot,
) -> anyhow::Result<()> {
    match socks5::socks5_read_command(&mut local, cfg.socks_auth.as_ref()).await? {
        SocksCommand::Connect { host, port } => {
            if cfg.use_tcp_mux {
                socks5::socks5_reply_ok(&mut local).await?;
                tcp_mux_open_stream_with_retry(local, host, port, Vec::new(), cfg, tcp_mux_slot)
                    .await
            } else {
                let (ws, crypto, prefetched_ws_messages) =
                    match open_legacy_biba_channel(&cfg, &host, port).await {
                        Ok(x) => x,
                        Err(e) => {
                            let _ = socks5::socks5_reply_err(&mut local).await;
                            return Err(e);
                        }
                    };
                socks5::socks5_reply_ok(&mut local).await?;
                ws_bridge::bridge_ws_tcp_padded(
                    ws,
                    prefetched_ws_messages,
                    local,
                    Vec::new(),
                    cfg.max_pad,
                    cfg.decoy_max,
                    Some(crypto),
                    cfg.max_ws_binary,
                    cfg.ws_ping_secs,
                    cfg.ws_ping_jitter_percent,
                    cfg.ws_binary_send_jitter_ms,
                    cfg.ws_jitter_min_ms,
                    cfg.ws_jitter_max_ms,
                    TunnelEnd::Client,
                    cfg.pad_mode,
                    cfg.dummy_interval_secs,
                    ServerWsOutTiming::default(),
                )
                .await
            }
        }
        SocksCommand::UdpAssociate { .. } => {
            let udp = UdpSocket::bind("0.0.0.0:0")
                .await
                .context("bind udp relay")?;
            let relay_port = udp.local_addr()?.port();
            socks5::socks5_reply_udp_associate(&mut local, relay_port).await?;
            run_socks_udp_assoc(local, udp, cfg, udp_mux_slot).await
        }
    }
}

/// SOCKS TCP control connection stays open per RFC; UDP relay shares one WSS UDP mux.
async fn run_socks_udp_assoc(
    mut ctrl: TcpStream,
    udp: UdpSocket,
    cfg: Arc<ClientCfg>,
    mux_slot: Arc<Mutex<Option<UdpMuxHandle>>>,
) -> anyhow::Result<()> {
    let (close_tx, mut close_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        loop {
            match ctrl.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = close_tx.send(());
    });

    let handle = {
        let mut g = mux_slot.lock().await;
        if g.is_none() {
            *g = Some(spawn_udp_mux_driver(cfg.udp_mux_config()));
        }
        g.as_ref().expect("udp mux just set").clone()
    };

    let workers = Arc::new(Semaphore::new(SOCKS_UDP_WORKERS));
    let udp = Arc::new(udp);
    let mut mbuf = vec![0u8; 65535];
    let reply_timeout_secs = if cfg.udp_mux_reply_timeout_secs == 0 {
        DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS
    } else {
        cfg.udp_mux_reply_timeout_secs
    };
    let reply_timeout = Duration::from_secs(reply_timeout_secs);

    loop {
        tokio::select! {
            biased;
            _ = close_rx.recv() => {
                break;
            }
            r = udp.recv_from(&mut mbuf) => {
                let (n, peer) = r.context("socks udp recv")?;
                let data = mbuf[..n].to_vec();
                let udp = udp.clone();
                let handle = handle.clone();
                let permit = match workers.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    let res: anyhow::Result<()> = async {
                        let (dst_host, dst_port, payload) =
                            crate::protocol::parse_socks5_udp_datagram(&data).context("socks udp parse")?;
                        let mut collision_retries = 0u8;
                        loop {
                            let xid: u64 = rand::random();
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            handle.forward(xid, dst_host.clone(), dst_port, payload.clone(), tx)?;
                            let reply = match timeout(reply_timeout, rx).await {
                                Ok(inner) => inner,
                                Err(_) => {
                                    error!("udp mux: reply timeout for xid {xid}");
                                    return Ok(());
                                }
                            };
                            match reply {
                                Ok(Ok(socks_body)) => {
                                    udp.send_to(&socks_body, peer).await?;
                                    return Ok(());
                                }
                                Ok(Err(e)) => {
                                    if e.to_string().contains("udp_mux_xid_collision")
                                        && collision_retries < 8
                                    {
                                        collision_retries = collision_retries.saturating_add(1);
                                        continue;
                                    }
                                    error!("udp mux: {e:#}");
                                    return Ok(());
                                }
                                Err(_) => {
                                    error!("udp mux driver dropped channel");
                                    return Ok(());
                                }
                            }
                        }
                    }
                    .await;
                    if let Err(e) = res {
                        error!("socks udp worker: {e:#}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_http_peer(
    mut local: TcpStream,
    cfg: Arc<ClientCfg>,
    tcp_mux_slot: TcpMuxSlot,
) -> anyhow::Result<()> {
    match http_connect::http_proxy_handshake(&mut local).await {
        Ok(http_connect::HttpProxyHandshake::Connect {
            host,
            port,
            client_prefetch,
        }) => {
            if cfg.use_tcp_mux {
                http_connect::reply_connect_ok(&mut local).await?;
                tcp_mux_open_stream_with_retry(
                    local,
                    host,
                    port,
                    client_prefetch,
                    cfg,
                    tcp_mux_slot,
                )
                .await
            } else {
                let (ws, crypto, prefetched_ws_messages) =
                    match open_legacy_biba_channel(&cfg, &host, port).await {
                        Ok(x) => x,
                        Err(e) => {
                            let _ =
                                http_connect::reply_connect_error(&mut local, 502, "Bad Gateway")
                                    .await;
                            return Err(e);
                        }
                    };
                http_connect::reply_connect_ok(&mut local).await?;
                ws_bridge::bridge_ws_tcp_padded(
                    ws,
                    prefetched_ws_messages,
                    local,
                    client_prefetch,
                    cfg.max_pad,
                    cfg.decoy_max,
                    Some(crypto),
                    cfg.max_ws_binary,
                    cfg.ws_ping_secs,
                    cfg.ws_ping_jitter_percent,
                    cfg.ws_binary_send_jitter_ms,
                    cfg.ws_jitter_min_ms,
                    cfg.ws_jitter_max_ms,
                    TunnelEnd::Client,
                    cfg.pad_mode,
                    cfg.dummy_interval_secs,
                    ServerWsOutTiming::default(),
                )
                .await
            }
        }
        Ok(http_connect::HttpProxyHandshake::ForwardHttp {
            host,
            port,
            to_origin,
        }) => {
            if cfg.use_tcp_mux {
                tcp_mux_open_stream_with_retry(local, host, port, to_origin, cfg, tcp_mux_slot)
                    .await
            } else {
                tunnel_to_biba(local, host, port, cfg, to_origin).await
            }
        }
        Err(e) => {
            let _ = http_connect::reply_connect_error(&mut local, 400, "Bad Request").await;
            Err(e)
        }
    }
}

fn junk_upper_bound(max_ws_binary: usize) -> usize {
    max_ws_binary.saturating_sub(1).clamp(32, 512)
}

async fn send_noise_binaries<S>(
    ws: &mut WebSocketStream<S>,
    count: u32,
    max_ws_binary: usize,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if count == 0 {
        return Ok(());
    }
    let hi = junk_upper_bound(max_ws_binary);
    for _ in 0..count {
        let n: usize = {
            let mut r = rand::thread_rng();
            r.gen_range(32..=hi)
        };
        let mut v = vec![0u8; n];
        OsRng.fill_bytes(&mut v);
        if v.len() > max_ws_binary {
            anyhow::bail!("noise frame exceeds --max-ws-binary");
        }
        ws.send(Message::Binary(Bytes::from(v))).await?;
    }
    Ok(())
}

async fn tunnel_to_biba(
    local: TcpStream,
    host: String,
    port: u16,
    cfg: Arc<ClientCfg>,
    tcp_uplink_prefix: Vec<u8>,
) -> anyhow::Result<()> {
    let (ws, crypto, prefetched_ws_messages) = open_legacy_biba_channel(&cfg, &host, port).await?;
    ws_bridge::bridge_ws_tcp_padded(
        ws,
        prefetched_ws_messages,
        local,
        tcp_uplink_prefix,
        cfg.max_pad,
        cfg.decoy_max,
        Some(crypto),
        cfg.max_ws_binary,
        cfg.ws_ping_secs,
        cfg.ws_ping_jitter_percent,
        cfg.ws_binary_send_jitter_ms,
        cfg.ws_jitter_min_ms,
        cfg.ws_jitter_max_ms,
        TunnelEnd::Client,
        cfg.pad_mode,
        cfg.dummy_interval_secs,
        ServerWsOutTiming::default(),
    )
    .await
}

/// Default `max_ws_binary` for clients (BibaV2.1 MTU cap).
pub const DEFAULT_CLIENT_MAX_WS_BINARY: usize = DEFAULT_MAX_WS_BINARY;

/// Default SOCKS UDP-mux reply wait (seconds). Server embeds this in `biba://` invites for clients.
pub const DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS: u64 = 130;

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn normalize_ws_path_defaults_and_prefix() {
        assert_eq!(normalize_ws_path(""), "/ws");
        assert_eq!(normalize_ws_path("  "), "/ws");
        assert_eq!(normalize_ws_path("/custom"), "/custom");
        assert_eq!(normalize_ws_path("no-slash"), "/no-slash");
    }

    #[test]
    fn parse_host_port_ipv4_and_bracket_ipv6() {
        let (h, p) = parse_host_port("203.0.113.7:8443").unwrap();
        assert_eq!(h, "203.0.113.7");
        assert_eq!(p, 8443);
        let (h6, p6) = parse_host_port("[2001:db8::1]:443").unwrap();
        assert_eq!(h6, "[2001:db8::1]");
        assert_eq!(p6, 443);
    }

    #[test]
    fn parse_host_port_rejects_missing_port() {
        assert!(parse_host_port("example.com").is_err());
        assert!(parse_host_port("").is_err());
    }

    #[test]
    fn parse_ws_header_splits_name_value() {
        let (k, v) = parse_ws_header("X-Custom: hello world").unwrap();
        assert_eq!(k, "X-Custom");
        assert_eq!(v, "hello world");
    }

    #[test]
    fn parse_ws_header_requires_colon() {
        assert!(parse_ws_header("BadHeader").is_err());
    }
}
