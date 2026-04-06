//! UDP datagram relay inside the same TLS + WebSocket transport as TCP tunnels (DPI profile).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::pki_types::ServerName;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Interval, MissedTickBehavior, interval};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::crypto_layer::{self, SessionCrypto};
use crate::protocol::{
    decode_udp_rep, decode_udp_req, encode_udp_mux_open, encode_udp_rep, encode_udp_req,
};
use crate::stealth::{WsHandshakeParams, build_websocket_request};
use crate::ws_bridge::SharedCrypto;
use crate::{read_padded_frame, write_padded_frame};

/// Config snapshot for opening a UDP-mux WebSocket (mirrors `local_client::ClientCfg`).
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
        if let Err(e) = run_udp_mux_client_loop(cfg, rx).await {
            tracing::error!("udp mux client: {e:#}");
        }
    });
    UdpMuxHandle { tx }
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
                let s_rand = crypto_layer::parse_ack(psk, b.as_ref(), &c_rand)?;
                return Ok(SessionCrypto::new(psk, &c_rand, &s_rand, decoy_max));
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

async fn connect_udp_mux_ws(
    cfg: &UdpMuxConfig,
) -> anyhow::Result<(WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, Option<SharedCrypto>)>
{
    let tcp = tokio::net::TcpStream::connect((cfg.server_host.as_str(), cfg.server_port))
        .await
        .context("connect server")?;
    let domain = ServerName::try_from(cfg.sni.clone())?;
    let connector = tokio_rustls::TlsConnector::from(cfg.tls.clone());
    let tls = connector.connect(domain, tcp).await.context("tls")?;
    let path = format!("/b/{}", cfg.token);
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
    });
    let (mut ws, _) = tokio_tungstenite::client_async(req, tls)
        .await
        .context("websocket")?;

    send_noise_binaries(&mut ws, u32::from(cfg.early_ws_frames), cfg.max_ws_binary).await?;
    send_noise_binaries(&mut ws, cfg.junk_frames, cfg.max_ws_binary)
        .await
        .context("junk frames")?;

    let crypto: Option<SharedCrypto> = if let Some(ref secret) = cfg.psk {
        Some(Arc::new(Mutex::new(
            v2_client_preamble(&mut ws, secret, cfg.decoy_max).await?,
        )))
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
    _decoy_max: u8,
    max_ws_binary: usize,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut wire = Vec::new();
    write_padded_frame(&mut wire, body, max_pad).context("pack frame")?;
    let blob: Vec<u8> = match crypto {
        Some(c) => c
            .lock()
            .await
            .seal_client_to_server(&wire)
            .context("v2 seal c2s (udp mux)")?,
        None => wire,
    };
    if blob.len() > max_ws_binary {
        anyhow::bail!("WS binary {} exceeds max_ws_binary {}", blob.len(), max_ws_binary);
    }
    Ok(blob)
}

async fn unpack_tunnel_in(
    crypto: &Option<SharedCrypto>,
    b: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let raw = match crypto {
        None => b.to_vec(),
        Some(c) => c
            .lock()
            .await
            .open_server_to_client(b)
            .context("v2 open s2c (udp mux)")?,
    };
    read_padded_frame(&raw).map_err(|e| anyhow::anyhow!("{e}"))
}

async fn run_udp_mux_client_loop(
    cfg: UdpMuxConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<ClientUdpCmd>,
) -> anyhow::Result<()> {
    let (ws, crypto) = connect_udp_mux_ws(&cfg).await?;
    let mut pending: HashMap<u64, tokio::sync::oneshot::Sender<anyhow::Result<Vec<u8>>>> =
        HashMap::new();
    let (ws_tx, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let ws_ping_secs = cfg.ws_ping_secs;

    let mut ping_tok: Option<Interval> = if ws_ping_secs > 0 {
        let mut i = interval(Duration::from_secs(ws_ping_secs));
        i.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Some(i)
    } else {
        None
    };

    loop {
        if ping_tok.is_some() {
            tokio::select! {
                biased;
                _ = async {
                    match &mut ping_tok {
                        Some(t) => t.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let mut g = ws_tx.lock().await;
                    g.send(Message::Ping(Bytes::new())).await.context("ws ping udp mux")?;
                }
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        ClientUdpCmd::Forward { xid, dst_host, dst_port, payload, reply } => {
                            pending.insert(xid, reply);
                            let req = encode_udp_req(xid, &dst_host, dst_port, &payload)?;
                            let blob = pack_tunnel_out(
                                &crypto,
                                cfg.max_pad,
                                cfg.decoy_max,
                                cfg.max_ws_binary,
                                &req,
                            )
                            .await?;
                            let mut g = ws_tx.lock().await;
                            g.send(Message::Binary(Bytes::from(blob)))
                                .await
                                .context("ws send udp req")?;
                        }
                    }
                }
                msg = ws_rx.next() => {
                    let Some(msg) = msg else { break };
                    match msg.context("ws read")? {
                        Message::Binary(b) => {
                            let inner = unpack_tunnel_in(&crypto, b.as_ref()).await?;
                            let (xid, sh, sp, pl) = decode_udp_rep(&inner)?;
                            if let Some(tx) = pending.remove(&xid) {
                                let rep = crate::protocol::build_socks5_udp_datagram(&sh, sp, &pl)?;
                                let _ = tx.send(Ok(rep));
                            }
                        }
                        Message::Ping(p) => {
                            let mut g = ws_tx.lock().await;
                            g.send(Message::Pong(p)).await?;
                        }
                        Message::Pong(_) => {}
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            }
        } else {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        ClientUdpCmd::Forward { xid, dst_host, dst_port, payload, reply } => {
                            pending.insert(xid, reply);
                            let req = encode_udp_req(xid, &dst_host, dst_port, &payload)?;
                            let blob = pack_tunnel_out(
                                &crypto,
                                cfg.max_pad,
                                cfg.decoy_max,
                                cfg.max_ws_binary,
                                &req,
                            )
                            .await?;
                            let mut g = ws_tx.lock().await;
                            g.send(Message::Binary(Bytes::from(blob))).await?;
                        }
                    }
                }
                msg = ws_rx.next() => {
                    let Some(msg) = msg else { break };
                    match msg.context("ws read")? {
                        Message::Binary(b) => {
                            let inner = unpack_tunnel_in(&crypto, b.as_ref()).await?;
                            let (xid, sh, sp, pl) = decode_udp_rep(&inner)?;
                            if let Some(tx) = pending.remove(&xid) {
                                let rep = crate::protocol::build_socks5_udp_datagram(&sh, sp, &pl)?;
                                let _ = tx.send(Ok(rep));
                            }
                        }
                        Message::Ping(p) => {
                            let mut g = ws_tx.lock().await;
                            g.send(Message::Pong(p)).await?;
                        }
                        Message::Pong(_) => {}
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            }
        }
    }

    for (_, tx) in pending.drain() {
        let _ = tx.send(Err(anyhow::anyhow!("udp mux closed")));
    }
    Ok(())
}

/// Server side: one UDP socket, paired with this WebSocket after `UDP_MUX_OPEN`.
pub async fn bridge_ws_udp_mux_server<S>(
    ws: WebSocketStream<S>,
    max_pad: u8,
    _decoy_max: u8,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    ws_ping_secs: u64,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await.context("udp bind server mux")?);
    sock.set_broadcast(true).ok();

    let pending: Arc<Mutex<HashMap<SocketAddr, VecDeque<u64>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let (ws_tx, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let ws_tx_up = ws_tx.clone();
    let crypto_up = crypto.clone();
    let pending_up = pending.clone();
    let sock_up = sock.clone();

    let up = async move {
        while let Some(m) = ws_rx.next().await {
            let m = m.context("websocket read")?;
            match m {
                Message::Binary(b) => {
                    if b.len() > max_ws_binary.saturating_mul(4) {
                        anyhow::bail!("oversized WS binary");
                    }
                    let raw = match &crypto_up {
                        Some(c) => c
                            .lock()
                            .await
                            .open_client_to_server(b.as_ref())
                            .context("v2 open c2s (udp mux)")?,
                        None => b.to_vec(),
                    };
                    let plain = read_padded_frame(&raw).map_err(|e| anyhow::anyhow!("{e}"))?;
                    let (xid, host, port, payload) = decode_udp_req(&plain)?;
                    let mut dest_iter = tokio::net::lookup_host((host.as_str(), port))
                        .await
                        .with_context(|| format!("lookup {host}:{port}"))?;
                    let dest = dest_iter
                        .next()
                        .with_context(|| format!("no addr for {host}:{port}"))?;
                    sock_up.send_to(&payload, dest).await?;
                    pending_up
                        .lock()
                        .await
                        .entry(dest)
                        .or_default()
                        .push_back(xid);
                }
                Message::Ping(p) => {
                    let mut g = ws_tx_up.lock().await;
                    g.send(Message::Pong(p)).await.context("ws pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let crypto_dn = crypto.clone();
    let ws_tx_dn = ws_tx.clone();
    let pending_dn = pending.clone();
    let mut ping_tok: Option<Interval> = if ws_ping_secs > 0 {
        let mut i = interval(Duration::from_secs(ws_ping_secs));
        i.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Some(i)
    } else {
        None
    };

    let mut buf = vec![0u8; 65535];
    let down = async move {
        loop {
            if let Some(ref mut ticker) = ping_tok {
                tokio::select! {
                    biased;
                    _ = ticker.tick() => {
                        let mut g = ws_tx_dn.lock().await;
                        g.send(Message::Ping(Bytes::new())).await.context("ws ping")?;
                    }
                    r = sock.as_ref().recv_from(&mut buf) => {
                        let (n, src) = r.context("recv_from udp")?;
                        let xid = {
                            let mut g = pending_dn.lock().await;
                            let q = g.entry(src).or_default();
                            q.pop_front().context("stray udp reply")?
                        };
                        let rep_plain = encode_udp_rep(
                            xid,
                            &src.ip().to_string(),
                            src.port(),
                            &buf[..n],
                        )?;
                        let mut wire = Vec::new();
                        write_padded_frame(&mut wire, &rep_plain, max_pad)?;
                        let blob: Vec<u8> = match &crypto_dn {
                            Some(c) => c
                                .lock()
                                .await
                                .seal_server_to_client(&wire)
                                .context("v2 seal s2c (udp mux)")?,
                            None => wire,
                        };
                        if blob.len() > max_ws_binary {
                            anyhow::bail!("udp rep ws frame too large");
                        }
                        let mut g = ws_tx_dn.lock().await;
                        g.send(Message::Binary(Bytes::from(blob)))
                            .await
                            .context("ws send udp rep")?;
                    }
                }
            } else {
                let (n, src) = sock
                    .as_ref()
                    .recv_from(&mut buf)
                    .await
                    .context("recv_from udp")?;
                let xid = {
                    let mut g = pending_dn.lock().await;
                    let q = g.entry(src).or_default();
                    q.pop_front().context("stray udp reply")?
                };
                let rep_plain = encode_udp_rep(xid, &src.ip().to_string(), src.port(), &buf[..n])?;
                let mut wire = Vec::new();
                write_padded_frame(&mut wire, &rep_plain, max_pad)?;
                let blob: Vec<u8> = match &crypto_dn {
                    Some(c) => c
                        .lock()
                        .await
                        .seal_server_to_client(&wire)
                        .context("v2 seal s2c (udp mux)")?,
                    None => wire,
                };
                if blob.len() > max_ws_binary {
                    anyhow::bail!("udp rep ws frame too large");
                }
                let mut g = ws_tx_dn.lock().await;
                g.send(Message::Binary(Bytes::from(blob))).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(up, down)?;
    Ok(())
}
