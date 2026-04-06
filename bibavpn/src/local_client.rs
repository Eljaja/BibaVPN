//! Shared SOCKS5 / HTTP CONNECT front-end for desktop binary and Android JNI.

use std::sync::Arc;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info};

use crate::crypto_layer::{self, SessionCrypto};
use crate::frame::DEFAULT_MAX_WS_BINARY;
use crate::http_connect;
use crate::protocol::encode_open;
use crate::stealth::{WsHandshakeParams, build_websocket_request};
use crate::tls_util::{client_config_insecure, client_config_system_roots};
use crate::ws_bridge::{self, TunnelEnd};
use crate::{socks5, socks5::socks5_handshake};
use bytes::Bytes;

/// User-facing options (CLI, JSON over JNI, etc.).
#[derive(Clone, Debug)]
pub struct LocalClientOptions {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    pub token: String,
    pub socks_bind: String,
    pub http_proxy_bind: Option<String>,
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
}

#[derive(Clone)]
struct ClientCfg {
    server_host: String,
    server_port: u16,
    sni: String,
    token: String,
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
}

type SharedCrypto = Arc<Mutex<SessionCrypto>>;

/// Build TLS config and run SOCKS5 (+ optional HTTP CONNECT) until `shutdown` becomes `true`.
///
/// `socks_ready`: if set, `()` is sent once `socks_bind` is listening (before any `accept`).
pub async fn run_local_client(
    opts: LocalClientOptions,
    mut shutdown: watch::Receiver<bool>,
    socks_ready: Option<std::sync::mpsc::Sender<()>>,
) -> anyhow::Result<()> {
    let tls = if opts.insecure_tls {
        info!("TLS: certificate verification disabled (lab only)");
        client_config_insecure()
    } else {
        client_config_system_roots()?
    };

    if opts.psk.is_some() {
        info!(
            "BibaV2/v2.1 PSK mode, decoy_max={}, max_ws_binary={}, ws_ping_secs={}",
            opts.decoy_max, opts.max_ws_binary, opts.ws_ping_secs
        );
    }

    let cfg = Arc::new(ClientCfg {
        server_host: opts.server_host.clone(),
        server_port: opts.server_port,
        sni: opts.sni,
        token: opts.token,
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
    });

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
        info!("HTTP CONNECT on {http_bind}");
        let cfg_http = cfg.clone();
        tokio::spawn(async move {
            loop {
                let (sock, peer) = match http_listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        error!("http accept: {e:#}");
                        continue;
                    }
                };
                let c = cfg_http.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_http_peer(sock, c).await {
                        error!("http {peer}: {e:#}");
                    }
                });
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
                tokio::spawn(async move {
                    if let Err(e) = handle_socks_peer(sock, c).await {
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

async fn handle_socks_peer(mut local: TcpStream, cfg: Arc<ClientCfg>) -> anyhow::Result<()> {
    let (host, port) = socks5_handshake(&mut local).await?;
    socks5::socks5_reply_ok(&mut local).await?;
    tunnel_to_biba(local, host, port, cfg, Vec::new()).await
}

async fn handle_http_peer(mut local: TcpStream, cfg: Arc<ClientCfg>) -> anyhow::Result<()> {
    let (host, port, prefetch) = match http_connect::http_connect_handshake(&mut local).await {
        Ok(x) => x,
        Err(e) => {
            let _ = http_connect::reply_connect_error(&mut local, 400, "Bad Request").await;
            return Err(e);
        }
    };
    http_connect::reply_connect_ok(&mut local).await?;
    tunnel_to_biba(local, host, port, cfg, prefetch).await
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
    let tcp = TcpStream::connect((cfg.server_host.as_str(), cfg.server_port))
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

    let open = encode_open(&host, port)?;
    if open.len() > cfg.max_ws_binary {
        anyhow::bail!("OPEN frame larger than --max-ws-binary");
    }
    ws.send(Message::Binary(Bytes::from(open)))
        .await
        .context("send OPEN")?;

    ws_bridge::bridge_ws_tcp_padded(
        ws,
        local,
        tcp_uplink_prefix,
        cfg.max_pad,
        cfg.decoy_max,
        crypto,
        cfg.max_ws_binary,
        cfg.ws_ping_secs,
        TunnelEnd::Client,
    )
    .await?;
    Ok(())
}

async fn v2_client_preamble<S>(
    ws: &mut WebSocketStream<S>,
    psk: &str,
    decoy_max: u8,
) -> anyhow::Result<SessionCrypto>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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

/// Default `max_ws_binary` for clients (BibaV2.1 MTU cap).
pub const DEFAULT_CLIENT_MAX_WS_BINARY: usize = DEFAULT_MAX_WS_BINARY;
