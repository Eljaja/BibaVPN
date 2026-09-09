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
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{interval, timeout, Duration, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info, trace, warn};

use crate::crypto_layer::{self, SessionCrypto};
use crate::frame::{AdaptivePadState, PadMode};
use crate::protocol::{
    decode_udp_rep, decode_udp_req, encode_udp_rep, encode_udp_req, encode_v3_auth,
    encode_v3_udp_mux_open,
};
use crate::retry::{
    maybe_server_ack_and_rtt_mask, maybe_ws_send_jitter, sleep_outbound_backoff,
    sleep_ws_ping_period, ServerWsOutTiming, WsSendJitter,
};
use crate::stealth::{build_websocket_request, WsHandshakeParams};
use crate::tls_util::TlsClientProfile;
use crate::ws_bridge::SharedCrypto;
use crate::{read_padded_frame_borrow, read_padded_frame_into, write_padded_frame_with_mode_state};

/// Max concurrent server-side UDP request tasks per mux session.
const UDP_MUX_SERVER_MAX_INFLIGHT: usize = 512;

/// Max outstanding client replies per mux session (bounded map growth).
const UDP_MUX_CLIENT_PENDING_CAP: usize = 2048;

/// Max queued UDP forwarding commands per client driver (backpressure).
const UDP_MUX_CMD_QUEUE_CAP: usize = 16384;

/// Upper bound on waiting for session-owned tasks (Ping / workers) to exit.
const SESSION_TASK_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

/// Idle reclaim of client pending slots whose SOCKS oneshot receiver was dropped.
#[cfg(not(test))]
const CLIENT_PENDING_RECLAIM_TICK: Duration = Duration::from_secs(1);
#[cfg(test)]
const CLIENT_PENDING_RECLAIM_TICK: Duration = Duration::from_millis(50);

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::sync::{Mutex, Semaphore};

    pub static PING_TASKS_ALIVE: AtomicUsize = AtomicUsize::new(0);
    /// When true, Ping / server worker WS sends block until released or the task is aborted.
    pub static BLOCK_WS_SEND: AtomicBool = AtomicBool::new(false);
    pub static WS_SEND_BLOCKED_WAITERS: AtomicUsize = AtomicUsize::new(0);
    pub static SERVER_INFLIGHT_SEM: Mutex<Option<Arc<Semaphore>>> = Mutex::const_new(None);
    pub static SERVER_SESSION_TASKS: AtomicUsize = AtomicUsize::new(0);
    pub static CLIENT_IDLE_PENDING: AtomicUsize = AtomicUsize::new(0);
    pub static CLIENT_IDLE_TICKS: AtomicUsize = AtomicUsize::new(0);
    pub static DRAIN_REMAINING: AtomicUsize = AtomicUsize::new(0);

    pub struct CountGuard(&'static AtomicUsize);
    impl CountGuard {
        pub fn new(counter: &'static AtomicUsize) -> Self {
            counter.fetch_add(1, Ordering::SeqCst);
            Self(counter)
        }
    }
    impl Drop for CountGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    /// Serializes tests that spawn hundreds of UDP workers (avoids fd / static races).
    pub static SERVER_STRESS_LOCK: Mutex<()> = Mutex::const_new(());

    pub async fn server_stress_lock() -> tokio::sync::MutexGuard<'static, ()> {
        let guard = SERVER_STRESS_LOCK.lock().await;
        *SERVER_INFLIGHT_SEM.lock().await = None;
        guard
    }

    pub async fn maybe_block_ws_send() {
        if !BLOCK_WS_SEND.load(Ordering::SeqCst) {
            return;
        }
        let _waiting = CountGuard::new(&WS_SEND_BLOCKED_WAITERS);
        loop {
            if !BLOCK_WS_SEND.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
    }

    pub fn server_session_tasks() -> usize {
        SERVER_SESSION_TASKS.load(Ordering::SeqCst)
    }
}

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
        UdpSocket::bind("[::]:0").await.context("udp mux bind v6")
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
    /// Return socket to the idle pool on drop only when true (never sent, or recv consumed).
    recycle_on_drop: bool,
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
            recycle_on_drop: true,
        })
    }

    #[cfg(test)]
    async fn idle_count(&self, v6: bool) -> usize {
        let idle = if v6 {
            &self.inner.v6_idle
        } else {
            &self.inner.v4_idle
        };
        idle.lock().await.len()
    }
}

impl UdpLease {
    fn sock_mut(&mut self) -> &mut UdpSocket {
        self.sock.as_mut().expect("udp lease socket")
    }

    /// After `send_to` without a matching `recv_from` the fd must not re-enter the pool.
    fn mark_sent_awaiting_reply(&mut self) {
        self.recycle_on_drop = false;
    }

    /// After `recv_from` consumed a datagram the bound socket is safe to pool again.
    fn mark_reply_consumed(&mut self) {
        self.recycle_on_drop = true;
    }
}

impl Drop for UdpLease {
    fn drop(&mut self) {
        if !self.recycle_on_drop {
            return;
        }
        let Some(sock) = self.sock.take() else {
            return;
        };
        let inner = self.inner.clone();
        let v6 = self.v6;
        tokio::spawn(async move {
            let idle = if v6 { &inner.v6_idle } else { &inner.v4_idle };
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

    fn mark_sent_awaiting_reply(&mut self) {
        if let UdpSockHolder::Pooled(l) = self {
            l.mark_sent_awaiting_reply();
        }
    }

    fn mark_reply_consumed(&mut self) {
        if let UdpSockHolder::Pooled(l) = self {
            l.mark_reply_consumed();
        }
    }
}

struct PendingUdpEntry {
    reply: tokio::sync::oneshot::Sender<anyhow::Result<Vec<u8>>>,
    /// Set when the forwarded datagram was a parseable DNS query to port 53.
    dns_expect: Option<(u16, String)>,
}

fn reclaim_closed_pending(pending: &mut HashMap<u64, PendingUdpEntry>) {
    pending.retain(|_, entry| !entry.reply.is_closed());
}

fn reap_finished_tasks(tasks: &mut JoinSet<()>) {
    while tasks.try_join_next().is_some() {}
}

async fn drain_session_tasks(mut tasks: JoinSet<()>) {
    tasks.abort_all();
    let deadline = tokio::time::Instant::now() + SESSION_TASK_DRAIN_TIMEOUT;
    while !tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, tasks.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }
    #[cfg(test)]
    test_hooks::DRAIN_REMAINING.store(tasks.len(), std::sync::atomic::Ordering::SeqCst);
}

fn spawn_udp_mux_ping<S>(
    tasks: &mut JoinSet<()>,
    ws_tx: Arc<Mutex<futures_util::stream::SplitSink<WebSocketStream<S>, Message>>>,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if ws_ping_secs == 0 {
        return;
    }
    tasks.spawn(async move {
        #[cfg(test)]
        struct PingAliveGuard;
        #[cfg(test)]
        impl Drop for PingAliveGuard {
            fn drop(&mut self) {
                test_hooks::PING_TASKS_ALIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        #[cfg(test)]
        {
            test_hooks::PING_TASKS_ALIVE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        #[cfg(test)]
        let _alive = PingAliveGuard;
        loop {
            sleep_ws_ping_period(ws_ping_secs, ws_ping_jitter_percent).await;
            #[cfg(test)]
            test_hooks::maybe_block_ws_send().await;
            let mut g = ws_tx.lock().await;
            if g.send(Message::Ping(Bytes::new())).await.is_err() {
                break;
            }
        }
    });
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
    WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
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
    ws: &mut WebSocketStream<S>,
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
        ws.send(Message::Binary(Bytes::from(v))).await?;
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
    WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    SharedCrypto,
)> {
    anyhow::ensure!(
        cfg.proto >= 3,
        "only Biba protocol v3 is supported (proto 3)"
    );
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
    let (mut ws, _) = tokio_tungstenite::client_async(req, tls)
        .await
        .context("websocket")?;

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
    ws.send(Message::Binary(Bytes::from(hello)))
        .await
        .context("send v3 HELLO (udp mux)")?;
    loop {
        let m = ws.next().await.context("eof before ACK (udp mux)")??;
        match m {
            Message::Binary(b) => {
                let s_rand = crypto_layer::parse_ack(secret, dom.as_str(), b.as_ref(), &c_rand)?;
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
                ws.send(Message::Binary(Bytes::from(blob)))
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
                ws.send(Message::Binary(Bytes::from(ob)))
                    .await
                    .context("send UDP_MUX_OPEN v3")?;
                return Ok((ws, crypto));
            }
            Message::Pong(_) => continue,
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.context("pong")?;
            }
            Message::Close(_) => anyhow::bail!("ws closed before ACK (udp mux)"),
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
    write_padded_frame_with_mode_state(&mut wire, body, max_pad, pad_mode, Some(adaptive))
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
async fn run_udp_mux_one_session<S>(
    ws: WebSocketStream<S>,
    crypto: SharedCrypto,
    cfg: &UdpMuxConfig,
    cmd_rx: &mut mpsc::Receiver<ClientUdpCmd>,
) -> anyhow::Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut udp_adaptive = AdaptivePadState::default();
    let mut pending: HashMap<u64, PendingUdpEntry> = HashMap::new();
    let (ws_tx, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let mut bad_frames: u32 = 0;
    let mut session_tasks = JoinSet::new();
    spawn_udp_mux_ping(
        &mut session_tasks,
        ws_tx.clone(),
        cfg.ws_ping_secs,
        cfg.ws_ping_jitter_percent,
    );
    let mut reclaim_tick = interval(CLIENT_PENDING_RECLAIM_TICK);
    reclaim_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

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
                        reclaim_closed_pending(&mut pending);
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
                                let dns_expect = if dst_port == 53 {
                                    crate::domain_route::parse_dns_query(&payload)
                                } else {
                                    None
                                };
                                e.insert(PendingUdpEntry { reply, dns_expect });
                            }
                        }
                        let req = match encode_udp_req(xid, &dst_host, dst_port, &payload) {
                            Ok(r) => r,
                            Err(e) => {
                                if let Some(entry) = pending.remove(&xid) {
                                    let _ = entry.reply.send(Err(e));
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
                                if let Some(entry) = pending.remove(&xid) {
                                    let _ = entry.reply.send(Err(e));
                                }
                                continue;
                            }
                        };
                        maybe_ws_send_jitter(cfg.send_jitter()).await;
                        let mut g = ws_tx.lock().await;
                        if let Err(e) = g.send(Message::Binary(Bytes::from(blob))).await {
                            if let Some(entry) = pending.remove(&xid) {
                                let _ = entry.reply.send(Err(anyhow::anyhow!(e)));
                            }
                            break;
                        }
                    }
                }
            }
            msg = ws_rx.next() => {
                let Some(msg) = msg else { break };
                match msg.context("ws read")? {
                    Message::Binary(b) => {
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
                        let Some(entry) = pending.remove(&xid) else {
                            trace!("udp mux: reply for unknown xid {xid} (likely timed out client-side)");
                            continue;
                        };
                        // Snoop DNS answers only for replies to DNS queries this client sent.
                        if sp == 53 {
                            if let Some((expected_id, ref expected_qname)) = entry.dns_expect {
                                crate::domain_route::record_dns(&pl, expected_id, expected_qname);
                            }
                        }
                        match crate::protocol::build_socks5_udp_datagram(&sh, sp, &pl) {
                            Ok(body) => { let _ = entry.reply.send(Ok(body)); }
                            Err(e) => { let _ = entry.reply.send(Err(e)); }
                        }
                    }
                    Message::Ping(p) => {
                        let mut g = ws_tx.lock().await;
                        let _ = g.send(Message::Pong(p)).await;
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            _ = reclaim_tick.tick() => {
                reclaim_closed_pending(&mut pending);
                #[cfg(test)]
                {
                    test_hooks::CLIENT_IDLE_PENDING.store(pending.len(), std::sync::atomic::Ordering::SeqCst);
                    test_hooks::CLIENT_IDLE_TICKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    }

    for (_, entry) in pending.drain() {
        let _ = entry
            .reply
            .send(Err(anyhow::anyhow!("udp mux session ended")));
    }
    drain_session_tasks(session_tasks).await;
    Ok(shutdown)
}

/// Server side: UDP over WebSocket after `UDP_MUX_OPEN`. Each request uses a dedicated UDP socket
/// so replies attach to the correct `xid` (parallel requests to the same host no longer collide).
pub async fn bridge_ws_udp_mux_server<S>(
    ws: WebSocketStream<S>,
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
    #[cfg(test)]
    {
        *test_hooks::SERVER_INFLIGHT_SEM.lock().await = Some(sem.clone());
    }
    let (ws_sink, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_sink));
    let mut bad_frames: u32 = 0;
    let mut session_tasks = JoinSet::new();
    spawn_udp_mux_ping(
        &mut session_tasks,
        ws_tx.clone(),
        ws_ping_secs,
        ws_ping_jitter_percent,
    );

    loop {
        reap_finished_tasks(&mut session_tasks);

        let m = ws_rx.next().await;
        let Some(m) = m else {
            break;
        };
        let m = m.context("websocket read")?;
        match m {
            Message::Binary(b) => {
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
                #[cfg(test)]
                let worker_count = test_hooks::CountGuard::new(&test_hooks::SERVER_SESSION_TASKS);
                session_tasks.spawn(async move {
                    #[cfg(test)]
                    let _worker_count = worker_count;
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
                            {
                                let sock = holder.sock_mut();
                                // Do not enable SO_BROADCAST: it let a client steer
                                // relayed UDP at broadcast addresses (amplification).
                                if let Err(e) = sock.send_to(&payload, dest).await {
                                    last_err = Some(anyhow::Error::from(e).context("udp send"));
                                    continue;
                                }
                            }
                            holder.mark_sent_awaiting_reply();
                            let mut rbuf = vec![0u8; 65535];
                            match timeout(recv_timeout, holder.sock_mut().recv_from(&mut rbuf))
                                .await
                            {
                                Ok(Ok((n, src))) => {
                                    holder.mark_reply_consumed();
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
                                    #[cfg(test)]
                                    test_hooks::maybe_block_ws_send().await;
                                    let mut g = ws_tx.lock().await;
                                    g.send(Message::Binary(Bytes::from(blob)))
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
                                    #[cfg(test)]
                                    test_hooks::maybe_block_ws_send().await;
                                    let mut g = ws_tx.lock().await;
                                    g.send(Message::Binary(Bytes::from(blob)))
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
            Message::Ping(p) => {
                let mut g = ws_tx.lock().await;
                g.send(Message::Pong(p)).await.context("ws pong")?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }

    drain_session_tasks(session_tasks).await;
    #[cfg(test)]
    {
        *test_hooks::SERVER_INFLIGHT_SEM.lock().await = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_layer::{build_ack, build_hello_v3, SessionCrypto};
    use crate::protocol::{decode_udp_rep, decode_udp_req, encode_udp_rep, encode_udp_req};
    use crate::retry::ServerWsOutTiming;
    use crate::tls_util::TlsClientProfile;
    use futures_util::StreamExt;
    use std::sync::Arc;
    use tokio::io::DuplexStream;
    use tokio::sync::Semaphore;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::WebSocketStream;

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
        let blob =
            pack_tunnel_out(&crypto, 16, PadMode::Random, 65_536, &inner, &mut adaptive).unwrap();
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
        let err =
            pack_tunnel_out(&crypto, 64, PadMode::Random, 256, &inner, &mut adaptive).unwrap_err();
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

    fn seal_c2s(crypto: &SessionCrypto, inner: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        write_padded_frame_with_mode_state(&mut wire, inner, 8, PadMode::Random, None).unwrap();
        crypto.seal_client_to_server(&wire).unwrap()
    }

    fn seal_s2c(crypto: &SessionCrypto, inner: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        write_padded_frame_with_mode_state(&mut wire, inner, 8, PadMode::Random, None).unwrap();
        crypto.seal_server_to_client(&wire).unwrap()
    }

    async fn ws_duplex_pair() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        tokio::join!(
            WebSocketStream::from_raw_socket(a, Role::Client, None),
            WebSocketStream::from_raw_socket(b, Role::Server, None),
        )
    }

    fn test_udp_mux_cfg(ws_ping_secs: u64) -> UdpMuxConfig {
        UdpMuxConfig {
            server_host: "127.0.0.1".into(),
            server_port: 1,
            sni: "localhost".into(),
            token: "test-token".into(),
            tls: crate::tls_util::client_config_insecure(),
            max_pad: 8,
            junk_frames: 0,
            early_ws_frames: 0,
            psk: Some("udp-mux-test-psk".into()),
            decoy_max: 4,
            ws_host: None,
            ws_origin: None,
            ws_user_agent: None,
            ws_accept_language: None,
            ws_extra_headers: Arc::new(Vec::new()),
            max_ws_binary: 65_536,
            ws_ping_secs,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            tls_profile: TlsClientProfile::Chrome132,
            ws_path: "/ws".into(),
            pad_mode: PadMode::Random,
            proto: 3,
            proto_domain: "lab".into(),
            reality_public_key: None,
            reality_short_id: None,
        }
    }

    #[test]
    fn reclaim_closed_pending_drops_stale_entries() {
        let mut pending: HashMap<u64, PendingUdpEntry> = HashMap::new();
        let (tx_open, rx_open) = tokio::sync::oneshot::channel();
        let (tx_closed, rx_closed) = tokio::sync::oneshot::channel();
        drop(rx_closed);
        pending.insert(
            1,
            PendingUdpEntry {
                reply: tx_closed,
                dns_expect: None,
            },
        );
        pending.insert(
            2,
            PendingUdpEntry {
                reply: tx_open,
                dns_expect: None,
            },
        );
        reclaim_closed_pending(&mut pending);
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&2));
        drop(rx_open);
        reclaim_closed_pending(&mut pending);
        assert!(pending.is_empty());
    }

    #[test]
    fn pending_cap_recovers_after_closed_oneshot_reclaim() {
        let mut pending: HashMap<u64, PendingUdpEntry> = HashMap::new();
        for i in 0..UDP_MUX_CLIENT_PENDING_CAP {
            let (tx, rx) = tokio::sync::oneshot::channel();
            drop(rx);
            pending.insert(
                i as u64,
                PendingUdpEntry {
                    reply: tx,
                    dns_expect: None,
                },
            );
        }
        reclaim_closed_pending(&mut pending);
        assert!(pending.is_empty());
        let (tx, _rx) = tokio::sync::oneshot::channel();
        assert!(pending.len() < UDP_MUX_CLIENT_PENDING_CAP);
        pending.insert(
            99,
            PendingUdpEntry {
                reply: tx,
                dns_expect: None,
            },
        );
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn pending_xid_collision_rejects_occupied_slot() {
        let mut pending: HashMap<u64, PendingUdpEntry> = HashMap::new();
        let (tx1, _rx1) = tokio::sync::oneshot::channel();
        pending.insert(
            7,
            PendingUdpEntry {
                reply: tx1,
                dns_expect: None,
            },
        );
        assert!(matches!(pending.entry(7), Entry::Occupied(_)));
        reclaim_closed_pending(&mut pending);
        assert!(pending.contains_key(&7));
        assert!(matches!(pending.entry(7), Entry::Occupied(_)));
    }

    #[test]
    fn late_rep_after_reclaim_is_unknown_xid() {
        let mut pending: HashMap<u64, PendingUdpEntry> = HashMap::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(rx);
        pending.insert(
            42,
            PendingUdpEntry {
                reply: tx,
                dns_expect: None,
            },
        );
        reclaim_closed_pending(&mut pending);
        assert!(pending.remove(&42).is_none());
    }

    #[tokio::test]
    async fn pooled_lease_recycles_when_never_sent() {
        let _guard = test_hooks::server_stress_lock().await;
        let pool = UdpSocketPool::new(2);
        let lease = pool.lease(false).await.unwrap();
        drop(lease);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.idle_count(false).await, 1);
    }

    #[tokio::test]
    async fn pooled_lease_discarded_after_send_without_recv() {
        let _guard = test_hooks::server_stress_lock().await;
        let pool = UdpSocketPool::new(2);
        let mut lease = pool.lease(false).await.unwrap();
        lease.mark_sent_awaiting_reply();
        drop(lease);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.idle_count(false).await, 0);
    }

    #[tokio::test]
    async fn pooled_lease_recycles_after_recv_consumed() {
        let _guard = test_hooks::server_stress_lock().await;
        let pool = UdpSocketPool::new(2);
        let mut lease = pool.lease(false).await.unwrap();
        lease.mark_sent_awaiting_reply();
        lease.mark_reply_consumed();
        drop(lease);
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.idle_count(false).await, 1);
    }

    fn spawn_peer_ws_drain(peer: WebSocketStream<DuplexStream>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let (_tx, mut rx) = peer.split();
            while rx.next().await.is_some() {}
        })
    }

    async fn recv_udp_req_on_peer(
        peer: &mut WebSocketStream<DuplexStream>,
        crypto: &SessionCrypto,
    ) -> u64 {
        let msg = timeout(Duration::from_secs(3), peer.next())
            .await
            .expect("request must reach peer")
            .unwrap()
            .unwrap();
        let Message::Binary(blob) = msg else {
            panic!("expected UDP request")
        };
        let wire = crypto.open_client_to_server(&blob).unwrap();
        decode_udp_req(read_padded_frame_borrow(&wire).unwrap())
            .unwrap()
            .0
    }

    async fn wait_for_blocked_send() {
        timeout(Duration::from_secs(3), async {
            while test_hooks::WS_SEND_BLOCKED_WAITERS.load(std::sync::atomic::Ordering::SeqCst) == 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("WS send must be blocked before cancellation");
    }

    async fn inject_udp_rep_on_peer(
        peer: &mut WebSocketStream<DuplexStream>,
        crypto: &SessionCrypto,
        xid: u64,
        host: &str,
        port: u16,
        payload: &[u8],
    ) {
        let inner = encode_udp_rep(xid, host, port, payload).unwrap();
        let sealed = seal_s2c(crypto, &inner);
        peer.send(Message::Binary(Bytes::from(sealed)))
            .await
            .unwrap();
    }

    async fn assert_ping_tasks_gone() {
        for _ in 0..50 {
            if test_hooks::PING_TASKS_ALIVE.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                return;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            test_hooks::PING_TASKS_ALIVE.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "ping task still alive"
        );
    }

    #[tokio::test]
    async fn ping_task_owned_by_join_set_and_drained() {
        let _guard = test_hooks::server_stress_lock().await;
        let (client_ws, _server_ws) = ws_duplex_pair().await;
        let (ws_tx, _ws_rx) = client_ws.split();
        let ws_tx = Arc::new(Mutex::new(ws_tx));
        let mut tasks = JoinSet::new();
        spawn_udp_mux_ping(&mut tasks, ws_tx, 3600, 0);
        assert_eq!(tasks.len(), 1);
        for _ in 0..50 {
            if test_hooks::PING_TASKS_ALIVE.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            test_hooks::PING_TASKS_ALIVE.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        drain_session_tasks(tasks).await;
        assert_ping_tasks_gone().await;
    }

    #[tokio::test]
    async fn client_session_reclaims_on_idle_tick() {
        let _guard = test_hooks::server_stress_lock().await;
        let (mut peer_ws, server_ws) = ws_duplex_pair().await;
        let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
        let drain = tokio::spawn(async move {
            while let Some(Ok(Message::Binary(_))) = peer_ws.next().await {
                observed_tx.send(()).unwrap();
            }
        });
        let crypto = test_session_crypto();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
        let cfg = test_udp_mux_cfg(0);
        let session = tokio::spawn(async move {
            run_udp_mux_one_session(server_ws, crypto, &cfg, &mut cmd_rx).await
        });

        let mut receivers = Vec::with_capacity(UDP_MUX_CLIENT_PENDING_CAP);
        for i in 0..UDP_MUX_CLIENT_PENDING_CAP {
            let (tx, rx) = tokio::sync::oneshot::channel();
            receivers.push(rx);
            cmd_tx
                .try_send(ClientUdpCmd::Forward {
                    xid: i as u64,
                    dst_host: "1.1.1.1".into(),
                    dst_port: 53,
                    payload: vec![0x00, 0x01],
                    reply: tx,
                })
                .unwrap();
        }
        let (cap_tx, cap_rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .send(ClientUdpCmd::Forward {
                xid: 9_998,
                dst_host: "1.1.1.1".into(),
                dst_port: 53,
                payload: vec![0, 1],
                reply: cap_tx,
            })
            .await
            .unwrap();
        let cap_error = timeout(Duration::from_secs(3), cap_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(cap_error.to_string().contains("too many pending replies"));
        for _ in 0..UDP_MUX_CLIENT_PENDING_CAP {
            timeout(Duration::from_secs(3), observed_rx.recv())
                .await
                .unwrap()
                .unwrap();
        }
        let tick = test_hooks::CLIENT_IDLE_TICKS.load(std::sync::atomic::Ordering::SeqCst);
        receivers.clear();
        timeout(Duration::from_secs(3), async {
            loop {
                if test_hooks::CLIENT_IDLE_TICKS.load(std::sync::atomic::Ordering::SeqCst) > tick
                    && test_hooks::CLIENT_IDLE_PENDING.load(std::sync::atomic::Ordering::SeqCst)
                        == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle tick must reclaim the full map without another Forward");

        let (tx, mut rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .try_send(ClientUdpCmd::Forward {
                xid: 9_999,
                dst_host: "1.1.1.1".into(),
                dst_port: 53,
                payload: vec![0x00, 0x01],
                reply: tx,
            })
            .unwrap();
        timeout(Duration::from_secs(3), observed_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        drop(cmd_tx);
        let stop = tokio::time::timeout(Duration::from_secs(2), session)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stop);
        drain.abort();
    }

    #[tokio::test]
    async fn client_session_pending_cap_rejects_excess_forward() {
        let _guard = test_hooks::server_stress_lock().await;
        let (mut peer_ws, server_ws) = ws_duplex_pair().await;
        let _drain = spawn_peer_ws_drain(peer_ws);
        let crypto = test_session_crypto();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
        let cfg = test_udp_mux_cfg(0);
        let session = tokio::spawn(async move {
            run_udp_mux_one_session(server_ws, crypto, &cfg, &mut cmd_rx).await
        });

        let mut receivers = Vec::with_capacity(UDP_MUX_CLIENT_PENDING_CAP + 1);
        for i in 0..UDP_MUX_CLIENT_PENDING_CAP {
            let (tx, rx) = tokio::sync::oneshot::channel();
            receivers.push(rx);
            cmd_tx
                .try_send(ClientUdpCmd::Forward {
                    xid: i as u64,
                    dst_host: "1.1.1.1".into(),
                    dst_port: 53,
                    payload: vec![0x00, 0x01],
                    reply: tx,
                })
                .unwrap();
        }
        let (tx_cap, rx_cap) = tokio::sync::oneshot::channel();
        cmd_tx
            .try_send(ClientUdpCmd::Forward {
                xid: UDP_MUX_CLIENT_PENDING_CAP as u64,
                dst_host: "1.1.1.1".into(),
                dst_port: 53,
                payload: vec![0x00, 0x01],
                reply: tx_cap,
            })
            .unwrap();
        let cap_err = tokio::time::timeout(Duration::from_secs(1), rx_cap)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(cap_err.to_string().contains("too many pending replies"));

        drop(cmd_tx);
        drop(receivers);
        let _ = tokio::time::timeout(Duration::from_secs(2), session).await;
    }

    #[tokio::test]
    async fn client_session_xid_collision_through_driver() {
        let _guard = test_hooks::server_stress_lock().await;
        let (mut peer_ws, server_ws) = ws_duplex_pair().await;
        let _drain = spawn_peer_ws_drain(peer_ws);
        let crypto = test_session_crypto();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
        let cfg = test_udp_mux_cfg(0);
        let session = tokio::spawn(async move {
            run_udp_mux_one_session(server_ws, crypto, &cfg, &mut cmd_rx).await
        });

        let (tx1, mut rx1) = tokio::sync::oneshot::channel();
        cmd_tx
            .try_send(ClientUdpCmd::Forward {
                xid: 77,
                dst_host: "1.1.1.1".into(),
                dst_port: 53,
                payload: vec![0x00, 0x01],
                reply: tx1,
            })
            .unwrap();
        let (tx2, rx2) = tokio::sync::oneshot::channel();
        cmd_tx
            .try_send(ClientUdpCmd::Forward {
                xid: 77,
                dst_host: "1.1.1.1".into(),
                dst_port: 53,
                payload: vec![0x00, 0x02],
                reply: tx2,
            })
            .unwrap();
        let collision = tokio::time::timeout(Duration::from_secs(1), rx2)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(collision.to_string().contains("udp_mux_xid_collision"));
        assert!(rx1.try_recv().is_err());

        drop(cmd_tx);
        drop(rx1);
        let _ = tokio::time::timeout(Duration::from_secs(2), session).await;
    }

    #[tokio::test]
    async fn client_session_late_rep_after_reclaim_not_delivered_to_reuse() {
        let _guard = test_hooks::server_stress_lock().await;
        let (mut peer_ws, server_ws) = ws_duplex_pair().await;
        let crypto = test_session_crypto();
        let crypto_peer = crypto.clone();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
        let cfg = test_udp_mux_cfg(0);
        let session = tokio::spawn(async move {
            run_udp_mux_one_session(server_ws, crypto, &cfg, &mut cmd_rx).await
        });

        let (tx_old, rx_old) = tokio::sync::oneshot::channel();
        cmd_tx
            .try_send(ClientUdpCmd::Forward {
                xid: 5,
                dst_host: "1.1.1.1".into(),
                dst_port: 53,
                payload: vec![0x00, 0x01],
                reply: tx_old,
            })
            .unwrap();
        assert_eq!(
            recv_udp_req_on_peer(&mut peer_ws, crypto_peer.as_ref()).await,
            5
        );
        let tick = test_hooks::CLIENT_IDLE_TICKS.load(std::sync::atomic::Ordering::SeqCst);
        drop(rx_old);
        timeout(Duration::from_secs(3), async {
            while test_hooks::CLIENT_IDLE_TICKS.load(std::sync::atomic::Ordering::SeqCst) == tick
                || test_hooks::CLIENT_IDLE_PENDING.load(std::sync::atomic::Ordering::SeqCst) != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        inject_udp_rep_on_peer(
            &mut peer_ws,
            crypto_peer.as_ref(),
            5,
            "8.8.8.8",
            53,
            b"late",
        )
        .await;
        // Pong proves the preceding stale reply has been consumed.
        peer_ws
            .send(Message::Ping(Bytes::from_static(b"barrier")))
            .await
            .unwrap();
        let pong = timeout(Duration::from_secs(3), peer_ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(pong, Message::Pong(_)));

        let (tx_new, mut rx_new) = tokio::sync::oneshot::channel();
        cmd_tx
            .try_send(ClientUdpCmd::Forward {
                xid: 5,
                dst_host: "1.1.1.1".into(),
                dst_port: 53,
                payload: vec![0x00, 0x02],
                reply: tx_new,
            })
            .unwrap();
        assert_eq!(
            recv_udp_req_on_peer(&mut peer_ws, crypto_peer.as_ref()).await,
            5
        );
        assert!(
            matches!(
                rx_new.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "late REP must not complete reuse"
        );

        inject_udp_rep_on_peer(
            &mut peer_ws,
            crypto_peer.as_ref(),
            5,
            "9.9.9.9",
            53,
            b"fresh",
        )
        .await;
        let body = tokio::time::timeout(Duration::from_secs(1), rx_new)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(body.ends_with(b"fresh"));

        drop(cmd_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), session).await;
    }

    #[tokio::test]
    async fn client_session_ping_does_not_outlive_cmd_close() {
        let _guard = test_hooks::server_stress_lock().await;
        let (mut peer_ws, server_ws) = ws_duplex_pair().await;
        let _drain = spawn_peer_ws_drain(peer_ws);
        let crypto = test_session_crypto();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
        let cfg = test_udp_mux_cfg(1);
        let session = tokio::spawn(async move {
            run_udp_mux_one_session(server_ws, crypto, &cfg, &mut cmd_rx).await
        });
        drop(cmd_tx);
        let stop = tokio::time::timeout(Duration::from_secs(2), session)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stop);
        assert_ping_tasks_gone().await;
    }

    #[tokio::test]
    async fn client_session_ping_aborted_while_send_blocked() {
        let _guard = test_hooks::server_stress_lock().await;
        test_hooks::BLOCK_WS_SEND.store(true, std::sync::atomic::Ordering::SeqCst);
        let (mut peer_ws, server_ws) = ws_duplex_pair().await;
        let _drain = spawn_peer_ws_drain(peer_ws);
        let crypto = test_session_crypto();
        let (cmd_tx, mut cmd_rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
        let cfg = test_udp_mux_cfg(1);
        let session = tokio::spawn(async move {
            run_udp_mux_one_session(server_ws, crypto, &cfg, &mut cmd_rx).await
        });
        wait_for_blocked_send().await;
        session.abort();
        let _ = tokio::time::timeout(Duration::from_secs(2), session).await;
        test_hooks::BLOCK_WS_SEND.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_ping_tasks_gone().await;
        drop(cmd_tx);
    }

    #[tokio::test]
    async fn server_empty_timeout_rep_reaches_client_pending() {
        let _guard = test_hooks::server_stress_lock().await;
        let (client_ws, server_ws) = ws_duplex_pair().await;
        let crypto = test_session_crypto();
        let crypto_srv = crypto.clone();
        let server = tokio::spawn(async move {
            bridge_ws_udp_mux_server(
                server_ws,
                8,
                4,
                crypto_srv,
                65_536,
                0,
                0,
                0,
                0,
                0,
                Duration::from_millis(20),
                PadMode::Random,
                ServerWsOutTiming::default(),
                None,
            )
            .await
        });

        let (cmd_tx, mut cmd_rx) = mpsc::channel(UDP_MUX_CMD_QUEUE_CAP);
        let cfg = test_udp_mux_cfg(0);
        let client = tokio::spawn(async move {
            run_udp_mux_one_session(client_ws, crypto.clone(), &cfg, &mut cmd_rx).await
        });

        let (tx, rx) = tokio::sync::oneshot::channel();
        cmd_tx
            .try_send(ClientUdpCmd::Forward {
                xid: 11,
                dst_host: "127.0.0.1".into(),
                dst_port: 9,
                payload: b"probe".to_vec(),
                reply: tx,
            })
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!reply.is_empty());
        drop(cmd_tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), client).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    async fn flood_server_udp_reqs(
        client_ws: &mut WebSocketStream<DuplexStream>,
        crypto: &SessionCrypto,
        count: usize,
    ) {
        // Local discard port: send succeeds, recv blocks until session/worker cancel.
        for i in 0..count {
            let inner = encode_udp_req(i as u64, "127.0.0.1", 59999, b"q").unwrap();
            let sealed = seal_c2s(crypto, &inner);
            client_ws
                .send(Message::Binary(Bytes::from(sealed)))
                .await
                .unwrap();
        }
    }

    async fn wait_for_server_workers_inflight() {
        for _ in 0..1000 {
            if test_hooks::server_session_tasks() >= UDP_MUX_SERVER_MAX_INFLIGHT {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            test_hooks::server_session_tasks() >= UDP_MUX_SERVER_MAX_INFLIGHT,
            "expected {} inflight workers, got {}",
            UDP_MUX_SERVER_MAX_INFLIGHT,
            test_hooks::server_session_tasks()
        );
    }

    async fn wait_for_server_sem() -> Arc<Semaphore> {
        for _ in 0..200 {
            let mut g = test_hooks::SERVER_INFLIGHT_SEM.lock().await;
            if let Some(sem) = g.take() {
                return sem;
            }
            drop(g);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("server inflight semaphore was not registered");
    }

    async fn wait_for_sem_available(sem: &Semaphore, expected_available: usize) {
        for _ in 0..500 {
            if sem.available_permits() == expected_available {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(sem.available_permits(), expected_available);
    }

    async fn run_server_bridge(
        server_ws: WebSocketStream<DuplexStream>,
        crypto: SharedCrypto,
        recv_timeout: Duration,
        pool: Option<Arc<UdpSocketPool>>,
        ws_ping_secs: u64,
    ) -> anyhow::Result<()> {
        bridge_ws_udp_mux_server(
            server_ws,
            8,
            4,
            crypto,
            65_536,
            ws_ping_secs,
            0,
            0,
            0,
            0,
            recv_timeout,
            PadMode::Random,
            ServerWsOutTiming::default(),
            pool,
        )
        .await
    }

    #[tokio::test]
    async fn server_session_abort_drains_inflight_during_recv() {
        let _guard = test_hooks::server_stress_lock().await;
        for _ in 0..2 {
            let (mut client_ws, server_ws) = ws_duplex_pair().await;
            let crypto = test_session_crypto();
            let crypto_srv = crypto.clone();
            let server = tokio::spawn(async move {
                run_server_bridge(server_ws, crypto_srv, Duration::from_secs(120), None, 0).await
            });
            let sem = wait_for_server_sem().await;

            flood_server_udp_reqs(&mut client_ws, crypto.as_ref(), UDP_MUX_SERVER_MAX_INFLIGHT)
                .await;
            wait_for_server_workers_inflight().await;
            wait_for_sem_available(&sem, 0).await;

            client_ws.close(None).await.ok();
            assert!(tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .is_ok());
            wait_for_sem_available(&sem, UDP_MUX_SERVER_MAX_INFLIGHT).await;
            assert_eq!(test_hooks::server_session_tasks(), 0);
            assert_eq!(
                test_hooks::DRAIN_REMAINING.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
        }
    }

    #[tokio::test]
    async fn server_session_abort_drains_inflight_during_blocked_ws_send() {
        let _guard = test_hooks::server_stress_lock().await;
        test_hooks::BLOCK_WS_SEND.store(true, std::sync::atomic::Ordering::SeqCst);
        for use_pool in [false, true] {
            let pool = use_pool.then(|| UdpSocketPool::new(2));
            let (mut client_ws, server_ws) = ws_duplex_pair().await;
            let crypto = test_session_crypto();
            let crypto_srv = crypto.clone();
            let server = tokio::spawn(async move {
                run_server_bridge(server_ws, crypto_srv, Duration::from_millis(5), pool, 0).await
            });
            let sem = wait_for_server_sem().await;

            flood_server_udp_reqs(&mut client_ws, crypto.as_ref(), UDP_MUX_SERVER_MAX_INFLIGHT)
                .await;
            wait_for_server_workers_inflight().await;
            wait_for_sem_available(&sem, 0).await;
            wait_for_blocked_send().await;

            server.abort();
            assert!(timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled());
            wait_for_sem_available(&sem, UDP_MUX_SERVER_MAX_INFLIGHT).await;
            assert_eq!(test_hooks::server_session_tasks(), 0);
            assert_eq!(
                test_hooks::WS_SEND_BLOCKED_WAITERS.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
        }
        test_hooks::BLOCK_WS_SEND.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    #[tokio::test]
    async fn server_session_pool_abort_drains_and_preserves_idle_baseline() {
        let _guard = test_hooks::server_stress_lock().await;
        for _ in 0..2 {
            let pool = UdpSocketPool::new(2);
            let pool_srv = pool.clone();
            let (mut client_ws, server_ws) = ws_duplex_pair().await;
            let crypto = test_session_crypto();
            let crypto_srv = crypto.clone();
            let server = tokio::spawn(async move {
                run_server_bridge(
                    server_ws,
                    crypto_srv,
                    Duration::from_secs(120),
                    Some(pool_srv),
                    0,
                )
                .await
            });
            let sem = wait_for_server_sem().await;

            flood_server_udp_reqs(&mut client_ws, crypto.as_ref(), UDP_MUX_SERVER_MAX_INFLIGHT)
                .await;
            wait_for_server_workers_inflight().await;
            wait_for_sem_available(&sem, 0).await;
            client_ws.close(None).await.ok();
            assert!(tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .is_ok());
            wait_for_sem_available(&sem, UDP_MUX_SERVER_MAX_INFLIGHT).await;
            assert_eq!(test_hooks::server_session_tasks(), 0);
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(pool.idle_count(false).await, 0);
        }
    }

    #[tokio::test]
    async fn server_ping_does_not_outlive_session_close() {
        let _guard = test_hooks::server_stress_lock().await;
        let (mut client_ws, server_ws) = ws_duplex_pair().await;
        let crypto = test_session_crypto();
        let server = tokio::spawn(async move {
            run_server_bridge(server_ws, crypto, Duration::from_millis(5), None, 1).await
        });
        client_ws.close(None).await.ok();
        assert!(tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .is_ok());
        assert_ping_tasks_gone().await;
    }

    #[tokio::test]
    async fn server_ping_aborted_while_send_blocked() {
        let _guard = test_hooks::server_stress_lock().await;
        test_hooks::BLOCK_WS_SEND.store(true, std::sync::atomic::Ordering::SeqCst);
        let (mut client_ws, server_ws) = ws_duplex_pair().await;
        let _drain = spawn_peer_ws_drain(client_ws);
        let crypto = test_session_crypto();
        let server = tokio::spawn(async move {
            run_server_bridge(server_ws, crypto, Duration::from_millis(5), None, 1).await
        });
        wait_for_blocked_send().await;
        server.abort();
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
        test_hooks::BLOCK_WS_SEND.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_ping_tasks_gone().await;
    }

    #[tokio::test]
    async fn abandoned_pooled_lease_not_recycled_after_send() {
        let _guard = test_hooks::server_stress_lock().await;
        let pool = UdpSocketPool::new(2);
        let pool_srv = pool.clone();
        let (mut client_ws, server_ws) = ws_duplex_pair().await;
        let crypto = test_session_crypto();
        let crypto_srv = crypto.clone();
        let server = tokio::spawn(async move {
            run_server_bridge(
                server_ws,
                crypto_srv,
                Duration::from_secs(60),
                Some(pool_srv),
                0,
            )
            .await
        });

        let inner = encode_udp_req(1, "1.1.1.1", 53, b"q").unwrap();
        let sealed = seal_c2s(crypto.as_ref(), &inner);
        client_ws
            .send(Message::Binary(Bytes::from(sealed)))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        client_ws.close(None).await.ok();
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(pool.idle_count(false).await, 0);
    }

    #[tokio::test]
    async fn discarded_pool_lease_does_not_recv_queued_datagram_on_next_lease() {
        let _guard = test_hooks::server_stress_lock().await;
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..n], peer).await.unwrap();
            }
        });

        let pool = UdpSocketPool::new(1);
        let mut lease = pool.lease(false).await.unwrap();
        let local = lease.sock_mut().local_addr().unwrap();
        lease.sock_mut().send_to(b"ping", echo_addr).await.unwrap();
        lease.mark_sent_awaiting_reply();
        drop(lease);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut lease2 = pool.lease(false).await.unwrap();
        assert_ne!(lease2.sock_mut().local_addr().unwrap(), local);
        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(
            Duration::from_millis(100),
            lease2.sock_mut().recv_from(&mut buf),
        )
        .await;
        assert!(res.is_err(), "next lease must not inherit queued reply");
        drop(lease2);
        echo_task.abort();
    }

    #[test]
    fn closed_then_reuse_xid_delivers_only_to_active_receiver() {
        let mut pending: HashMap<u64, PendingUdpEntry> = HashMap::new();
        let (tx_old, rx_old) = tokio::sync::oneshot::channel();
        drop(rx_old);
        pending.insert(
            5,
            PendingUdpEntry {
                reply: tx_old,
                dns_expect: None,
            },
        );
        reclaim_closed_pending(&mut pending);
        assert!(pending.remove(&5).is_none());

        let (tx_new, mut rx_new) = tokio::sync::oneshot::channel();
        pending.insert(
            5,
            PendingUdpEntry {
                reply: tx_new,
                dns_expect: None,
            },
        );
        let entry = pending.remove(&5).unwrap();
        let body = crate::protocol::build_socks5_udp_datagram("8.8.8.8", 53, b"a").unwrap();
        entry.reply.send(Ok(body.clone())).unwrap();
        assert_eq!(rx_new.try_recv().unwrap().unwrap(), body);
    }
}
