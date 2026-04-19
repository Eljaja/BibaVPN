//! UDP datagram relay inside the same TLS + WebSocket transport as TCP tunnels (DPI profile).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use rustls::pki_types::ServerName;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, trace, warn};

use crate::crypto_layer::{self, SessionCrypto};
use crate::frame::PadMode;
use crate::protocol::{
    decode_udp_rep, decode_udp_req, encode_auth, encode_udp_mux_open, encode_udp_rep,
    encode_udp_req, encode_v3_auth, encode_v3_udp_mux_open,
};
use crate::retry::{maybe_ws_binary_send_jitter, sleep_outbound_backoff, sleep_ws_ping_period};
use crate::stealth::{build_websocket_request, WsHandshakeParams};
use crate::tls_util::TlsClientProfile;
use crate::ws_bridge::SharedCrypto;
use crate::{read_padded_frame, write_padded_frame_with_mode};

/// Max concurrent server-side UDP request tasks per mux session.
const UDP_MUX_SERVER_MAX_INFLIGHT: usize = 512;

/// Max outstanding client replies per mux session (bounded map growth).
const UDP_MUX_CLIENT_PENDING_CAP: usize = 2048;

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
    pub tls_profile: TlsClientProfile,
    pub ws_path: String,
    pub pad_mode: PadMode,
    pub proto: u8,
    pub proto_domain: String,
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
    tx: mpsc::UnboundedSender<ClientUdpCmd>,
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
            .send(ClientUdpCmd::Forward {
                xid,
                dst_host,
                dst_port,
                payload,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("udp mux driver stopped"))?;
        Ok(())
    }
}

/// Start background driver; returns handle for submitting UDP requests.
pub fn spawn_udp_mux_driver(cfg: UdpMuxConfig) -> UdpMuxHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run_udp_mux_driver_forever(cfg, rx).await {
            error!("udp mux client: {e:#}");
        }
    });
    UdpMuxHandle { tx }
}

async fn run_udp_mux_driver_forever(
    cfg: UdpMuxConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<ClientUdpCmd>,
) -> anyhow::Result<()> {
    loop {
        let (ws, crypto) = connect_udp_mux_ws_resilient(&cfg).await?;
        let shutdown = run_udp_mux_one_session(ws, crypto, &cfg, &mut cmd_rx).await?;
        if shutdown {
            return Ok(());
        }
    }
}

async fn connect_udp_mux_ws_resilient(
    cfg: &UdpMuxConfig,
) -> anyhow::Result<(
    WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    Option<SharedCrypto>,
)> {
    let mut streak = 0u32;
    loop {
        match connect_udp_mux_ws(cfg).await {
            Ok(x) => return Ok(x),
            Err(e) => {
                warn!("udp mux connect failed (streak {streak}): {e:#}");
                sleep_outbound_backoff(streak.min(10)).await;
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

async fn v2_client_preamble<S>(
    ws: &mut WebSocketStream<S>,
    psk: &str,
    decoy_max: u8,
) -> anyhow::Result<SessionCrypto>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (c_rand, hello) = crypto_layer::build_hello();
    ws.send(Message::Binary(Bytes::from(hello)))
        .await
        .context("send HELLO")?;

    loop {
        let m = ws.next().await.context("eof before ACK")??;
        match m {
            Message::Binary(b) => {
                let s_rand = crypto_layer::parse_ack(psk, None, b.as_ref(), &c_rand)?;
                return Ok(SessionCrypto::new(
                    psk,
                    None,
                    &c_rand,
                    &s_rand,
                    decoy_max,
                ));
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

fn effective_udp_proto_domain(cfg: &UdpMuxConfig) -> String {
    let t = cfg.proto_domain.trim();
    if t.is_empty() {
        cfg.sni.clone()
    } else {
        t.to_string()
    }
}

async fn connect_udp_mux_ws(
    cfg: &UdpMuxConfig,
) -> anyhow::Result<(
    WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    Option<SharedCrypto>,
)> {
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

    send_noise_binaries(&mut ws, u32::from(cfg.early_ws_frames), cfg.max_ws_binary).await?;
    send_noise_binaries(&mut ws, cfg.junk_frames, cfg.max_ws_binary)
        .await
        .context("junk frames")?;

    let is_v3 = cfg.proto >= 3;
    if is_v3 {
        anyhow::ensure!(cfg.psk.is_some(), "Biba v3 UDP mux requires PSK");
        let secret = cfg.psk.as_ref().expect("psk");
        let dom = effective_udp_proto_domain(cfg);
        let (c_rand, hello) = crypto_layer::build_hello_v3();
        ws.send(Message::Binary(Bytes::from(hello)))
            .await
            .context("send v3 HELLO (udp mux)")?;
        loop {
            let m = ws.next().await.context("eof before ACK (udp mux)")??;
            match m {
                Message::Binary(b) => {
                    let s_rand =
                        crypto_layer::parse_ack(secret, Some(dom.as_str()), b.as_ref(), &c_rand)?;
                    let crypto = Arc::new(SessionCrypto::new(
                        secret,
                        Some(dom.as_str()),
                        &c_rand,
                        &s_rand,
                        cfg.decoy_max,
                    ));
                    let auth_inner =
                        encode_v3_auth(&cfg.token).context("encode v3 AUTH (udp mux)")?;
                    let mut wire = Vec::new();
                    write_padded_frame_with_mode(&mut wire, &auth_inner, cfg.max_pad, cfg.pad_mode)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let blob = crypto
                        .seal_client_to_server(&wire)
                        .await
                        .context("seal v3 AUTH (udp mux)")?;
                    ws.send(Message::Binary(Bytes::from(blob)))
                        .await
                        .context("send v3 AUTH (udp mux)")?;
                    let open = encode_v3_udp_mux_open();
                    let mut w2 = Vec::new();
                    write_padded_frame_with_mode(&mut w2, &open, cfg.max_pad, cfg.pad_mode)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let ob = crypto
                        .seal_client_to_server(&w2)
                        .await
                        .context("seal UDP_MUX v3")?;
                    if ob.len() > cfg.max_ws_binary {
                        anyhow::bail!("sealed UDP_MUX_OPEN exceeds cap");
                    }
                    ws.send(Message::Binary(Bytes::from(ob)))
                        .await
                        .context("send UDP_MUX_OPEN v3")?;
                    return Ok((ws, Some(crypto)));
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

    let auth = encode_auth(&cfg.token).context("encode AUTH (udp mux)")?;
    if auth.len() > cfg.max_ws_binary {
        anyhow::bail!("AUTH frame larger than --max-ws-binary");
    }
    ws.send(Message::Binary(Bytes::from(auth)))
        .await
        .context("send AUTH (udp mux)")?;

    let crypto: Option<SharedCrypto> = if let Some(ref secret) = cfg.psk {
        Some(Arc::new(
            v2_client_preamble(&mut ws, secret, cfg.decoy_max).await?,
        ))
    } else {
        None
    };

    let open = encode_udp_mux_open();
    if open.len() > cfg.max_ws_binary {
        anyhow::bail!("UDP mux OPEN larger than --max-ws-binary");
    }
    ws.send(Message::Binary(Bytes::from(open)))
        .await
        .context("send UDP_MUX_OPEN")?;

    Ok((ws, crypto))
}

async fn pack_tunnel_out(
    crypto: &Option<SharedCrypto>,
    max_pad: u8,
    pad_mode: PadMode,
    max_ws_binary: usize,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut wire = Vec::new();
    write_padded_frame_with_mode(&mut wire, body, max_pad, pad_mode).context("pack frame")?;
    let blob: Vec<u8> = match crypto {
        Some(c) => c
            .seal_client_to_server(&wire)
            .await
            .context("v2 seal c2s (udp mux)")?,
        None => wire,
    };
    if blob.len() > max_ws_binary {
        anyhow::bail!(
            "WS binary {} exceeds max_ws_binary {}",
            blob.len(),
            max_ws_binary
        );
    }
    Ok(blob)
}

async fn unpack_tunnel_in(crypto: &Option<SharedCrypto>, b: &[u8]) -> anyhow::Result<Vec<u8>> {
    let raw = match crypto {
        None => b.to_vec(),
        Some(c) => c
            .open_server_to_client(b)
            .await
            .context("v2 open s2c (udp mux)")?,
    };
    read_padded_frame(&raw).map_err(|e| anyhow::anyhow!("{e}"))
}

/// One WSS session. Returns `Ok(true)` if the command channel closed (shutdown). `Ok(false)` = reconnect.
async fn run_udp_mux_one_session(
    ws: WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    crypto: Option<SharedCrypto>,
    cfg: &UdpMuxConfig,
    cmd_rx: &mut mpsc::UnboundedReceiver<ClientUdpCmd>,
) -> anyhow::Result<bool> {
    let mut pending: HashMap<u64, tokio::sync::oneshot::Sender<anyhow::Result<Vec<u8>>>> =
        HashMap::new();
    let (ws_tx, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));

    let _ping = if cfg.ws_ping_secs > 0 {
        let w = ws_tx.clone();
        let secs = cfg.ws_ping_secs;
        let jit = cfg.ws_ping_jitter_percent;
        Some(tokio::spawn(async move {
            loop {
                sleep_ws_ping_period(secs, jit).await;
                let mut g = w.lock().await;
                if g.send(Message::Ping(Bytes::new())).await.is_err() {
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
                        pending.insert(xid, reply);
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
                        )
                        .await
                        {
                            Ok(b) => b,
                            Err(e) => {
                                if let Some(tx) = pending.remove(&xid) {
                                    let _ = tx.send(Err(e));
                                }
                                continue;
                            }
                        };
                        maybe_ws_binary_send_jitter(cfg.ws_binary_send_jitter_ms).await;
                        let mut g = ws_tx.lock().await;
                        if let Err(e) = g.send(Message::Binary(Bytes::from(blob))).await {
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
                    Message::Binary(b) => {
                        let inner = match unpack_tunnel_in(&crypto, b.as_ref()).await {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("udp mux: drop bad frame: {e:#}");
                                continue;
                            }
                        };
                        let rep = match decode_udp_rep(&inner) {
                            Ok(x) => x,
                            Err(e) => {
                                warn!("udp mux: bad UDP_REP: {e:#}");
                                continue;
                            }
                        };
                        let (xid, sh, sp, pl) = rep;
                        if let Some(tx) = pending.remove(&xid) {
                            match crate::protocol::build_socks5_udp_datagram(&sh, sp, &pl) {
                                Ok(body) => { let _ = tx.send(Ok(body)); }
                                Err(e) => { let _ = tx.send(Err(e)); }
                            }
                        } else {
                            trace!("udp mux: reply for unknown xid {xid} (likely timed out client-side)");
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
    ws: WebSocketStream<S>,
    max_pad: u8,
    _decoy_max: u8,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    recv_timeout: Duration,
    pad_mode: PadMode,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let sem = Arc::new(Semaphore::new(UDP_MUX_SERVER_MAX_INFLIGHT));
    let (ws_sink, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_sink));

    let _ping = if ws_ping_secs > 0 {
        let w = ws_tx.clone();
        Some(tokio::spawn(async move {
            loop {
                sleep_ws_ping_period(ws_ping_secs, ws_ping_jitter_percent).await;
                let mut g = w.lock().await;
                if g.send(Message::Ping(Bytes::new())).await.is_err() {
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
            Message::Binary(b) => {
                if b.len() > max_ws_binary.saturating_mul(4) {
                    anyhow::bail!("oversized WS binary");
                }
                let raw = match &crypto {
                    Some(c) => c
                        .open_client_to_server(b.as_ref())
                        .await
                        .context("v2 open c2s (udp mux)")?,
                    None => b.to_vec(),
                };
                let plain = match read_padded_frame(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("udp mux server: skip bad padded frame: {e}");
                        continue;
                    }
                };
                let (xid, host, port, payload) = match decode_udp_req(&plain) {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("udp mux server: bad UDP_REQ: {e:#}");
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
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = (async {
                        let sock = UdpSocket::bind("0.0.0.0:0")
                            .await
                            .context("udp mux bind ephemeral")?;
                        sock.set_broadcast(true).ok();
                        let mut dest_iter = tokio::net::lookup_host((host.as_str(), port))
                            .await
                            .with_context(|| format!("lookup {host}:{port}"))?;
                        let dest = dest_iter
                            .next()
                            .with_context(|| format!("no addr for {host}:{port}"))?;
                        sock.send_to(&payload, dest).await.context("udp send")?;
                        let mut rbuf = vec![0u8; 65535];
                        let (n, src) = match timeout(recv_timeout, sock.recv_from(&mut rbuf)).await
                        {
                            Ok(Ok(v)) => v,
                            Ok(Err(e)) => return Err(e.into()),
                            Err(_) => return Ok(()),
                        };
                        let rep_plain =
                            encode_udp_rep(xid, &src.ip().to_string(), src.port(), &rbuf[..n])?;
                        let mut wire = Vec::new();
                        write_padded_frame_with_mode(&mut wire, &rep_plain, max_pad, pad_mode)
                            .context("pad rep")?;
                        let blob: Vec<u8> = match &crypto {
                            Some(c) => c
                                .seal_server_to_client(&wire)
                                .await
                                .context("v2 seal s2c (udp mux)")?,
                            None => wire,
                        };
                        if blob.len() > max_ws_binary {
                            anyhow::bail!("udp rep ws frame too large");
                        }
                        maybe_ws_binary_send_jitter(ws_binary_send_jitter_ms).await;
                        let mut g = ws_tx.lock().await;
                        g.send(Message::Binary(Bytes::from(blob)))
                            .await
                            .context("ws send udp rep")?;
                        Ok::<_, anyhow::Error>(())
                    })
                    .await
                    {
                        error!("udp mux server outbound: {e:#}");
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

    Ok(())
}
