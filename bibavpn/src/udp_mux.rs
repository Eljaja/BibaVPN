//! UDP datagram relay inside the same TLS + WebSocket transport as TCP tunnels (DPI profile).

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use rustls::pki_types::ServerName;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use crate::transport::{OuterMsg, WsConn};
use tracing::{error, info, trace, warn};

use crate::crypto_layer::{self, SessionCrypto};
use crate::frame::{AdaptivePadState, PadMode};
use crate::protocol::{
    decode_udp_rep, decode_udp_req, encode_udp_rep, encode_udp_req, encode_v3_auth,
    encode_v3_udp_mux_open,
};
use crate::retry::{
    maybe_server_ack_and_rtt_mask, maybe_ws_send_jitter, sleep_outbound_backoff, sleep_ws_ping_period,
    ServerWsOutTiming, WsSendJitter,
};
use crate::stealth::{build_websocket_request, WsHandshakeParams};
use crate::tls_util::TlsClientProfile;
use crate::ws_bridge::SharedCrypto;
use crate::{
    read_padded_frame_borrow, read_padded_frame_into, write_padded_frame_with_mode_state,
};

/// Max concurrent server-side UDP request tasks per mux session.
const UDP_MUX_SERVER_MAX_INFLIGHT: usize = 512;

/// Max outstanding client replies per mux session (bounded map growth).
const UDP_MUX_CLIENT_PENDING_CAP: usize = 2048;

/// Max queued UDP forwarding commands per client driver (backpressure).
const UDP_MUX_CMD_QUEUE_CAP: usize = 16384;

/// Resolve all socket addresses for a UDP destination (stable sort).
pub async fn resolve_udp_dest(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    let mut v: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("lookup {host}:{port}"))?
        .collect();
    v.sort_by_key(|a| a.to_string());
    Ok(v)
}

async fn bind_udp_for_family(want_v6: bool) -> anyhow::Result<UdpSocket> {
    if want_v6 {
        UdpSocket::bind("[::]:0")
            .await
            .context("udp mux bind v6")
    } else {
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("udp mux bind v4")
    }
}

struct UdpPoolInner {
    max_idle_per_family: usize,
    v4_idle: Mutex<Vec<UdpSocket>>,
    v6_idle: Mutex<Vec<UdpSocket>>,
    sem: Arc<Semaphore>,
}

/// Reuse bound UDP sockets on the server to cut `bind(2)` churn (`--udp-socket-pool-size`).
pub struct UdpSocketPool {
    inner: Arc<UdpPoolInner>,
}

pub struct UdpLease {
    inner: Arc<UdpPoolInner>,
    sock: Option<UdpSocket>,
    v6: bool,
    _permit: OwnedSemaphorePermit,
}

impl UdpSocketPool {
    pub fn new(cap: usize) -> Arc<Self> {
        let cap = cap.max(1);
        Arc::new(Self {
            inner: Arc::new(UdpPoolInner {
                max_idle_per_family: cap,
                v4_idle: Mutex::new(Vec::new()),
                v6_idle: Mutex::new(Vec::new()),
                sem: Arc::new(Semaphore::new(cap)),
            }),
        })
    }

    pub async fn lease(self: &Arc<Self>, v6: bool) -> anyhow::Result<UdpLease> {
        let permit = self
            .inner
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("udp socket pool closed"))?;
        let sock = {
            let idle = if v6 {
                &self.inner.v6_idle
            } else {
                &self.inner.v4_idle
            };
            let mut g = idle.lock().await;
            g.pop()
        };
        let sock = match sock {
            Some(s) => s,
            None => bind_udp_for_family(v6).await?,
        };
        Ok(UdpLease {
            inner: Arc::clone(&self.inner),
            sock: Some(sock),
            v6,
            _permit: permit,
        })
    }
}

impl UdpLease {
    fn sock_mut(&mut self) -> &mut UdpSocket {
        self.sock.as_mut().expect("udp lease socket")
    }
}

impl Drop for UdpLease {
    fn drop(&mut self) {
        let Some(sock) = self.sock.take() else {
            return;
        };
        let inner = self.inner.clone();
        let v6 = self.v6;
        tokio::spawn(async move {
            let idle = if v6 {
                &inner.v6_idle
            } else {
                &inner.v4_idle
            };
            let mut g = idle.lock().await;
            if g.len() < inner.max_idle_per_family {
                g.push(sock);
            }
        });
    }
}

enum UdpSockHolder {
    Pooled(UdpLease),
    Ephemeral(UdpSocket),
}

impl UdpSockHolder {
    fn sock_mut(&mut self) -> &mut UdpSocket {
        match self {
            UdpSockHolder::Pooled(l) => l.sock_mut(),
            UdpSockHolder::Ephemeral(s) => s,
        }
    }
}

/// Config snapshot for opening a UDP-mux WebSocket (mirrors `local_client::ClientCfg` mux fields).
#[derive(Clone)]
pub struct UdpMuxConfig {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    pub token: String,
    pub tls: Arc<rustls::ClientConfig>,
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
    pub ws_ping_jitter_percent: u8,
    pub ws_binary_send_jitter_ms: u8,
    pub ws_jitter_min_ms: u8,
    pub ws_jitter_max_ms: u8,
    pub tls_profile: TlsClientProfile,
    pub ws_path: String,
    pub pad_mode: PadMode,
    pub proto: u8,
    pub proto_domain: String,
    /// When set, run REALITY X25519 exchange after WSS upgrade (before v3 PSK).
    pub reality_public_key: Option<[u8; 32]>,
    pub reality_short_id: Option<[u8; 8]>,
}

impl UdpMuxConfig {
    fn send_jitter(&self) -> WsSendJitter {
        WsSendJitter {
            min_ms: self.ws_jitter_min_ms,
            max_ms: self.ws_jitter_max_ms,
            legacy_0_to_max: self.ws_binary_send_jitter_ms,
        }
    }
}

pub enum ClientUdpCmd {
    Forward {
        xid: u64,
        dst_host: String,
        dst_port: u16,
        payload: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<Vec<u8>>>,
    },
}

#[derive(Clone)]
pub struct UdpMuxHandle {
    tx: mpsc::Sender<ClientUdpCmd>,
}

impl UdpMuxHandle {
    pub fn forward(
        &self,
        xid: u64,
        dst_host: String,
        dst_port: u16,
        payload: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<anyhow::Result<Vec<u8>>>,
    ) -> anyhow::Result<()> {
        self.tx
            .try_send(ClientUdpCmd::Forward {
                xid,
                dst_host,
                dst_port,
                payload,
                reply,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    anyhow::anyhow!("udp mux command queue full (backpressure)")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    anyhow::anyhow!("udp mux driver stopped")
                }
            })?;
        Ok(())
    }
}

/// Start background driver; returns handle for submitting UDP requests.
pub fn spawn_udp_mux_driver(
    cfg: UdpMuxConfig,
    mut shutdown: watch::Receiver<bool>,
    tasks: &mut Vec<JoinHandle<()>>,
) -> UdpMuxHandle {
    let (tx, rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
    tasks.push(tokio::spawn(async move {
        if let Err(e) = run_udp_mux_driver_forever(cfg, rx, shutdown).await {
            error!("udp mux client: {e:#}");
        }
    }));
    UdpMuxHandle { tx }
}

async fn run_udp_mux_driver_forever(
    cfg: UdpMuxConfig,
    mut cmd_rx: mpsc::Receiver<ClientUdpCmd>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let (ws, crypto) = connect_udp_mux_ws_resilient(&cfg, &mut shutdown).await?;
        let stop = run_udp_mux_one_session(ws, crypto, &cfg, &mut cmd_rx).await?;
        if stop {
            return Ok(());
        }
        if *shutdown.borrow() {
            return Ok(());
        }
    }
}

async fn connect_udp_mux_ws_resilient(
    cfg: &UdpMuxConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<(
    WsConn<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    SharedCrypto,
)> {
    let mut streak = 0u32;
    loop {
        if *shutdown.borrow() {
            anyhow::bail!("udp mux: shutdown");
        }
        match connect_udp_mux_ws(cfg).await {
            Ok(x) => return Ok(x),
            Err(e) => {
                warn!("udp mux connect failed (streak {streak}): {e:#}");
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            anyhow::bail!("udp mux: shutdown");
                        }
                    }
                    _ = sleep_outbound_backoff(streak.min(10)) => {}
                }
                streak = streak.saturating_add(1);
            }
        }
    }
}

fn junk_upper_bound(max_ws_binary: usize) -> usize {
    max_ws_binary.saturating_sub(1).clamp(32, 512)
}

async fn send_noise_binaries<S>(
    ws: &mut WsConn<S>,
    count: u32,
    max_ws_binary: usize,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if count == 0 {
        return Ok(());
    }
    let hi = junk_upper_bound(max_ws_binary);
    for _ in 0..count {
        let n: usize = rand::thread_rng().gen_range(32..=hi);
        let mut v = vec![0u8; n];
        OsRng.fill_bytes(&mut v);
        ws.send(OuterMsg::Data(Bytes::from(v))).await?;
    }
    Ok(())
}

fn effective_udp_proto_domain(cfg: &UdpMuxConfig) -> String {
    let t = cfg.proto_domain.trim();
    if t.is_empty() {
        "default".to_string()
    } else {
        t.to_string()
    }
}

fn short_hash8(s: &str) -> String {
    let hex = blake3::hash(s.as_bytes()).to_hex().to_string();
    hex[..8].to_string()
}

async fn connect_udp_mux_ws(
    cfg: &UdpMuxConfig,
) -> anyhow::Result<(
    WsConn<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    SharedCrypto,
)> {
    anyhow::ensure!(cfg.proto >= 3, "only Biba protocol v3 is supported (proto 3)");
    anyhow::ensure!(
        cfg.psk.is_some(),
        "Biba v3 UDP mux requires --psk (or invite psk)"
    );
    let tcp =
        crate::outbound_protect::tcp_connect_host_protected(&cfg.server_host, cfg.server_port)
            .await
            .with_context(|| format!("connect server {}:{}", cfg.server_host, cfg.server_port))?;
    let _ = tcp.set_nodelay(true);
    let domain = ServerName::try_from(cfg.sni.clone())?;
    let connector = tokio_rustls::TlsConnector::from(cfg.tls.clone());
    let tls = connector.connect(domain, tcp).await.context("tls")?;
    let path = cfg.ws_path.clone();
    let ws_host = cfg.ws_host.as_deref();
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
        .context("websocket")?;
    let mut ws = WsConn::from_websocket(ws);

    if let Some(pk) = cfg.reality_public_key {
        let short_id = cfg
            .reality_short_id
            .unwrap_or_else(|| rand::random::<[u8; 8]>());
        crate::reality::reality_client_exchange_verify(&mut ws, &pk, &short_id, &cfg.token)
            .await
            .context("REALITY handshake (udp mux)")?;
    }

    send_noise_binaries(&mut ws, u32::from(cfg.early_ws_frames), cfg.max_ws_binary).await?;
    send_noise_binaries(&mut ws, cfg.junk_frames, cfg.max_ws_binary)
        .await
        .context("junk frames")?;

    let secret = cfg.psk.as_ref().expect("psk checked");
    let dom = effective_udp_proto_domain(cfg);
    info!(
        target: "bibavpn_client",
        sni = %cfg.sni,
        proto_domain = %cfg.proto_domain,
        effective_proto_domain = %dom,
        psk_hash8 = %short_hash8(secret),
        "udp mux using transport identity"
    );
    let (c_rand, hello) = crypto_layer::build_hello_v3();
    ws.send(OuterMsg::Data(Bytes::from(hello)))
        .await
        .context("send v3 HELLO (udp mux)")?;
    loop {
        let m = ws.next().await.context("eof before ACK (udp mux)")??;
        match m {
            OuterMsg::Data(b) => {
                let s_rand =
                    crypto_layer::parse_ack(secret, dom.as_str(), b.as_ref(), &c_rand)?;
                let crypto = Arc::new(SessionCrypto::new(
                    secret,
                    dom.as_str(),
                    &c_rand,
                    &s_rand,
                    cfg.decoy_max,
                ));
                let mut udp_adaptive = AdaptivePadState::default();
                let auth_inner = encode_v3_auth(&cfg.token).context("encode v3 AUTH (udp mux)")?;
                let mut wire = Vec::new();
                write_padded_frame_with_mode_state(
                    &mut wire,
                    &auth_inner,
                    cfg.max_pad,
                    cfg.pad_mode,
                    Some(&mut udp_adaptive),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                let blob = crypto
                    .seal_client_to_server(&wire)
                    .context("seal v3 AUTH (udp mux)")?;
                ws.send(OuterMsg::Data(Bytes::from(blob)))
                    .await
                    .context("send v3 AUTH (udp mux)")?;
                let open = encode_v3_udp_mux_open();
                let mut w2 = Vec::new();
                write_padded_frame_with_mode_state(
                    &mut w2,
                    &open,
                    cfg.max_pad,
                    cfg.pad_mode,
                    Some(&mut udp_adaptive),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                let ob = crypto
                    .seal_client_to_server(&w2)
                    .context("seal UDP_MUX v3")?;
                if ob.len() > cfg.max_ws_binary {
                    anyhow::bail!("sealed UDP_MUX_OPEN exceeds cap");
                }
                ws.send(OuterMsg::Data(Bytes::from(ob)))
                    .await
                    .context("send UDP_MUX_OPEN v3")?;
                return Ok((ws, crypto));
            }
            OuterMsg::Pong(_) => continue,
            OuterMsg::Ping(p) => {
                ws.send(OuterMsg::Pong(p)).await.context("pong")?;
            }
            OuterMsg::Close => anyhow::bail!("ws closed before ACK (udp mux)"),
            _ => {}
        }
    }
}

fn pack_tunnel_out(
    crypto: &SharedCrypto,
    max_pad: u8,
    pad_mode: PadMode,
    max_ws_binary: usize,
    body: &[u8],
    adaptive: &mut AdaptivePadState,
) -> anyhow::Result<Vec<u8>> {
    let mut wire = Vec::new();
    write_padded_frame_with_mode_state(
        &mut wire,
        body,
        max_pad,
        pad_mode,
        Some(adaptive),
    )
    .context("pack frame")?;
    let blob: Vec<u8> = crypto
        .seal_client_to_server(&wire)
        .context("seal c2s (udp mux)")?;
    if blob.len() > max_ws_binary {
        anyhow::bail!(
            "WS binary {} exceeds max_ws_binary {}",
            blob.len(),
            max_ws_binary
        );
    }
    Ok(blob)
}

fn unpack_tunnel_in(crypto: &SharedCrypto, b: &[u8]) -> anyhow::Result<Vec<u8>> {
    let raw = crypto
        .open_server_to_client(b)
        .context("open s2c (udp mux)")?;
    read_padded_frame_into(raw).map_err(|e| anyhow::anyhow!("{e}"))
}

/// One WSS session. Returns `Ok(true)` if the command channel closed (shutdown). `Ok(false)` = reconnect.
async fn run_udp_mux_one_session(
    ws: WsConn<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    crypto: SharedCrypto,
    cfg: &UdpMuxConfig,
    cmd_rx: &mut mpsc::Receiver<ClientUdpCmd>,
) -> anyhow::Result<bool> {
    let mut udp_adaptive = AdaptivePadState::default();
    let mut pending: HashMap<u64, tokio::sync::oneshot::Sender<anyhow::Result<Vec<u8>>>> =
        HashMap::new();
    let (ws_tx, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let mut bad_frames: u32 = 0;

    let _ping = if cfg.ws_ping_secs > 0 {
        let w = ws_tx.clone();
        let secs = cfg.ws_ping_secs;
        let jit = cfg.ws_ping_jitter_percent;
        Some(tokio::spawn(async move {
            loop {
                sleep_ws_ping_period(secs, jit).await;
                let mut g = w.lock().await;
                if g.send(OuterMsg::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
        }))
    } else {
        None
    };

    let mut shutdown = false;
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    shutdown = true;
                    break;
                };
                match cmd {
                    ClientUdpCmd::Forward { xid, dst_host, dst_port, payload, reply } => {
                        if pending.len() >= UDP_MUX_CLIENT_PENDING_CAP {
                            let _ = reply.send(Err(anyhow::anyhow!(
                                "udp mux: too many pending replies (cap {})",
                                UDP_MUX_CLIENT_PENDING_CAP
                            )));
                            continue;
                        }
                        match pending.entry(xid) {
                            Entry::Occupied(_) => {
                                let _ = reply.send(Err(anyhow::anyhow!("udp_mux_xid_collision")));
                                continue;
                            }
                            Entry::Vacant(e) => {
                                e.insert(reply);
                            }
                        }
                        let req = match encode_udp_req(xid, &dst_host, dst_port, &payload) {
                            Ok(r) => r,
                            Err(e) => {
                                if let Some(tx) = pending.remove(&xid) {
                                    let _ = tx.send(Err(e));
                                }
                                continue;
                            }
                        };
                        let blob = match pack_tunnel_out(
                            &crypto,
                            cfg.max_pad,
                            cfg.pad_mode,
                            cfg.max_ws_binary,
                            &req,
                            &mut udp_adaptive,
                        ) {
                            Ok(b) => b,
                            Err(e) => {
                                if let Some(tx) = pending.remove(&xid) {
                                    let _ = tx.send(Err(e));
                                }
                                continue;
                            }
                        };
                        maybe_ws_send_jitter(cfg.send_jitter()).await;
                        let mut g = ws_tx.lock().await;
                        if let Err(e) = g.send(OuterMsg::Data(Bytes::from(blob))).await {
                            if let Some(tx) = pending.remove(&xid) {
                                let _ = tx.send(Err(anyhow::anyhow!(e)));
                            }
                            break;
                        }
                    }
                }
            }
            msg = ws_rx.next() => {
                let Some(msg) = msg else { break };
                match msg.context("ws read")? {
                    OuterMsg::Data(b) => {
                        let inner = match unpack_tunnel_in(&crypto, b.as_ref()) {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("udp mux: drop bad frame: {e:#}");
                                bad_frames = bad_frames.saturating_add(1);
                                if bad_frames >= 24 {
                                    anyhow::bail!("udp mux: too many bad frames; reconnecting");
                                }
                                continue;
                            }
                        };
                        bad_frames = 0;
                        let rep = match decode_udp_rep(&inner) {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("udp mux: bad UDP_REP: {e:#}");
                                bad_frames = bad_frames.saturating_add(1);
                                if bad_frames >= 24 {
                                    anyhow::bail!("udp mux: too many bad frames; reconnecting");
                                }
                                continue;
                            }
                        };
                        let (xid, sh, sp, pl) = rep;
                        // Snoop DNS answers to learn IP->domain for domain-based
                        // split routing on full-TUN clients (mobile). No-op unless
                        // bypass domains are configured. See `domain_route`.
                        if sp == 53 {
                            crate::domain_route::record_dns(&pl);
                        }
                        if let Some(tx) = pending.remove(&xid) {
                            match crate::protocol::build_socks5_udp_datagram(&sh, sp, &pl) {
                                Ok(body) => { let _ = tx.send(Ok(body)); }
                                Err(e) => { let _ = tx.send(Err(e)); }
                            }
                        } else {
                            trace!("udp mux: reply for unknown xid {xid} (likely timed out client-side)");
                        }
                    }
                    OuterMsg::Ping(p) => {
                        let mut g = ws_tx.lock().await;
                        let _ = g.send(OuterMsg::Pong(p)).await;
                    }
                    OuterMsg::Pong(_) => {}
                    OuterMsg::Close => break,
                    _ => {}
                }
            }
        }
    }

    for (_, tx) in pending.drain() {
        let _ = tx.send(Err(anyhow::anyhow!("udp mux session ended")));
    }
    Ok(shutdown)
}

/// Server side: UDP over WebSocket after `UDP_MUX_OPEN`. Each request uses a dedicated UDP socket
/// so replies attach to the correct `xid` (parallel requests to the same host no longer collide).
pub async fn bridge_ws_udp_mux_server<S>(
    ws: WsConn<S>,
    max_pad: u8,
    _decoy_max: u8,
    crypto: SharedCrypto,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    ws_jitter_min_ms: u8,
    ws_jitter_max_ms: u8,
    recv_timeout: Duration,
    pad_mode: PadMode,
    server_out_timing: ServerWsOutTiming,
    udp_socket_pool: Option<Arc<UdpSocketPool>>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let udp_socket_pool = udp_socket_pool;
    let udp_adaptive = Arc::new(std::sync::Mutex::new(AdaptivePadState::default()));
    let ws_send_j = WsSendJitter {
        min_ms: ws_jitter_min_ms,
        max_ms: ws_jitter_max_ms,
        legacy_0_to_max: ws_binary_send_jitter_ms,
    };
    let sem = Arc::new(Semaphore::new(UDP_MUX_SERVER_MAX_INFLIGHT));
    let (ws_sink, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_sink));
    let mut bad_frames: u32 = 0;

    let _ping = if ws_ping_secs > 0 {
        let w = ws_tx.clone();
        Some(tokio::spawn(async move {
            loop {
                sleep_ws_ping_period(ws_ping_secs, ws_ping_jitter_percent).await;
                let mut g = w.lock().await;
                if g.send(OuterMsg::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
        }))
    } else {
        None
    };

    loop {
        let m = ws_rx.next().await;
        let Some(m) = m else {
            break;
        };
        let m = m.context("websocket read")?;
        match m {
            OuterMsg::Data(b) => {
                if b.len() > max_ws_binary.saturating_mul(4) {
                    anyhow::bail!("oversized WS binary");
                }
                let raw = crypto
                    .open_client_to_server(b.as_ref())
                    .context("open c2s (udp mux)")?;
                let plain = match read_padded_frame_borrow(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("udp mux server: skip bad padded frame: {e}");
                        bad_frames = bad_frames.saturating_add(1);
                        if bad_frames >= 64 {
                            anyhow::bail!("udp mux server: too many bad client frames");
                        }
                        continue;
                    }
                };
                bad_frames = 0;
                let (xid, host, port, payload) = match decode_udp_req(plain) {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("udp mux server: bad UDP_REQ: {e:#}");
                        bad_frames = bad_frames.saturating_add(1);
                        if bad_frames >= 64 {
                            anyhow::bail!("udp mux server: too many bad client frames");
                        }
                        continue;
                    }
                };

                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| anyhow::anyhow!("udp mux sem closed"))?;
                let ws_tx = ws_tx.clone();
                let crypto = crypto.clone();
                let udp_ad = udp_adaptive.clone();
                let wsj = ws_send_j;
                let server_out = server_out_timing;
                let udp_pool = udp_socket_pool.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = async {
                        let addrs = resolve_udp_dest(&host, port).await?;
                        if addrs.is_empty() {
                            anyhow::bail!("no addr for {host}:{port}");
                        }
                        let mut last_err: Option<anyhow::Error> = None;
                        for (i, dest) in addrs.iter().copied().enumerate() {
                            if i > 0 {
                                trace!(
                                    target: "bibavpn_udp",
                                    %dest,
                                    "udp mux server: resolve fallback"
                                );
                            }
                            let want_v6 = dest.is_ipv6();
                            let mut holder = if let Some(ref pool) = udp_pool {
                                UdpSockHolder::Pooled(pool.lease(want_v6).await?)
                            } else {
                                UdpSockHolder::Ephemeral(bind_udp_for_family(want_v6).await?)
                            };
                            let sock = holder.sock_mut();
                            // Do not enable SO_BROADCAST: it let a client steer
                            // relayed UDP at broadcast addresses (amplification).
                            if let Err(e) = sock.send_to(&payload, dest).await {
                                last_err = Some(anyhow::Error::from(e).context("udp send"));
                                continue;
                            }
                            let mut rbuf = vec![0u8; 65535];
                            match timeout(recv_timeout, sock.recv_from(&mut rbuf)).await {
                                Ok(Ok((n, src))) => {
                                    let rep_plain = encode_udp_rep(
                                        xid,
                                        &src.ip().to_string(),
                                        src.port(),
                                        &rbuf[..n],
                                    )?;
                                    let mut wire = Vec::new();
                                    {
                                        let mut g = udp_ad
                                            .lock()
                                            .map_err(|e| anyhow::anyhow!("udp adaptive: {e}"))?;
                                        write_padded_frame_with_mode_state(
                                            &mut wire,
                                            &rep_plain,
                                            max_pad,
                                            pad_mode,
                                            Some(&mut *g),
                                        )
                                        .context("pad rep")?;
                                    }
                                    let blob: Vec<u8> = crypto
                                        .seal_server_to_client(&wire)
                                        .context("seal s2c (udp mux)")?;
                                    if blob.len() > max_ws_binary {
                                        anyhow::bail!("udp rep ws frame too large");
                                    }
                                    maybe_server_ack_and_rtt_mask(server_out).await;
                                    maybe_ws_send_jitter(wsj).await;
                                    let mut g = ws_tx.lock().await;
                                    g.send(OuterMsg::Data(Bytes::from(blob)))
                                        .await
                                        .context("ws send udp rep")?;
                                    return Ok::<_, anyhow::Error>(());
                                }
                                Ok(Err(e)) => {
                                    last_err = Some(anyhow::Error::from(e));
                                    continue;
                                }
                                Err(_) => {
                                    let rep_plain = encode_udp_rep(xid, "0.0.0.0", 0, &[])?;
                                    let mut wire = Vec::new();
                                    {
                                        let mut g = udp_ad
                                            .lock()
                                            .map_err(|e| anyhow::anyhow!("udp adaptive: {e}"))?;
                                        write_padded_frame_with_mode_state(
                                            &mut wire,
                                            &rep_plain,
                                            max_pad,
                                            pad_mode,
                                            Some(&mut *g),
                                        )
                                        .context("pad rep")?;
                                    }
                                    let blob: Vec<u8> = crypto
                                        .seal_server_to_client(&wire)
                                        .context("seal s2c (udp mux)")?;
                                    if blob.len() > max_ws_binary {
                                        anyhow::bail!("udp rep ws frame too large");
                                    }
                                    maybe_server_ack_and_rtt_mask(server_out).await;
                                    maybe_ws_send_jitter(wsj).await;
                                    let mut g = ws_tx.lock().await;
                                    g.send(OuterMsg::Data(Bytes::from(blob)))
                                        .await
                                        .context("ws send udp rep (timeout)")?;
                                    return Ok::<_, anyhow::Error>(());
                                }
                            }
                        }
                        Err(last_err.unwrap_or_else(|| {
                            anyhow::anyhow!("udp mux: all resolve targets failed")
                        }))
                    }
                    .await
                    {
                        error!(target: "bibavpn_udp", "udp mux server outbound: {e:#}");
                    }
                });
            }
            OuterMsg::Ping(p) => {
                let mut g = ws_tx.lock().await;
                g.send(OuterMsg::Pong(p)).await.context("ws pong")?;
            }
            OuterMsg::Pong(_) => {}
            OuterMsg::Close => break,
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_layer::{build_ack, build_hello_v3, SessionCrypto};
    use crate::protocol::{decode_udp_rep, decode_udp_req, encode_udp_rep, encode_udp_req};
    use std::sync::Arc;

    fn test_session_crypto() -> SharedCrypto {
        let (c, _hello) = build_hello_v3();
        let psk = "udp-mux-test-psk";
        let dom = "lab";
        let (_ack, s) = build_ack(psk, dom, &c).unwrap();
        Arc::new(SessionCrypto::new(psk, dom, &c, &s, 4))
    }

    #[test]
    fn pack_unpack_tunnel_roundtrip_udp_req() {
        let crypto = test_session_crypto();
        let mut adaptive = AdaptivePadState::default();
        let inner = encode_udp_req(0xDEAD_BEEF_0000_0001, "1.1.1.1", 53, b"dns-q").unwrap();
        let blob = pack_tunnel_out(&crypto, 16, PadMode::Random, 65_536, &inner, &mut adaptive)
            .unwrap();
        let raw = crypto.open_client_to_server(&blob).unwrap();
        let plain = read_padded_frame_into(raw).unwrap();
        assert_eq!(plain, inner);
        let (xid, host, port, payload) = decode_udp_req(&plain).unwrap();
        assert_eq!(xid, 0xDEAD_BEEF_0000_0001);
        assert_eq!(host, "1.1.1.1");
        assert_eq!(port, 53);
        assert_eq!(payload, b"dns-q");
    }

    #[test]
    fn pack_unpack_tunnel_roundtrip_udp_rep() {
        let crypto = test_session_crypto();
        let mut adaptive = AdaptivePadState::default();
        let inner = encode_udp_rep(42, "8.8.8.8", 53, b"dns-a").unwrap();
        let sealed = {
            let mut wire = Vec::new();
            write_padded_frame_with_mode_state(
                &mut wire,
                &inner,
                8,
                PadMode::Random,
                Some(&mut adaptive),
            )
            .unwrap();
            crypto.seal_server_to_client(&wire).unwrap()
        };
        let plain = unpack_tunnel_in(&crypto, &sealed).unwrap();
        let (xid, host, port, payload) = decode_udp_rep(&plain).unwrap();
        assert_eq!(xid, 42);
        assert_eq!(host, "8.8.8.8");
        assert_eq!(port, 53);
        assert_eq!(payload, b"dns-a");
    }

    #[test]
    fn pack_tunnel_rejects_ws_binary_cap() {
        let crypto = test_session_crypto();
        let mut adaptive = AdaptivePadState::default();
        let inner = encode_udp_req(1, "example.com", 443, &vec![0u8; 2048]).unwrap();
        let err = pack_tunnel_out(&crypto, 64, PadMode::Random, 256, &inner, &mut adaptive)
            .unwrap_err();
        assert!(format!("{err:#}").contains("max_ws_binary"));
    }

    #[test]
    fn unpack_tunnel_rejects_garbage_ciphertext() {
        let crypto = test_session_crypto();
        assert!(unpack_tunnel_in(&crypto, &[0u8; 32]).is_err());
    }

    #[test]
    fn pending_xid_map_insert_collision() {
        let mut pending: HashMap<u64, u64> = HashMap::new();
        assert!(pending.insert(1, 10).is_none());
        assert_eq!(pending.insert(1, 20), Some(10));
        assert_eq!(pending.get(&1), Some(&20));
    }
}
