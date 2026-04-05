//! Local SOCKS5 and optional HTTP CONNECT -> BibaVPN (WSS with padded payloads).
//! BibaV2 + BibaV2.1: PSK AEAD, WS ping, MTU-capped frames, custom WS headers, early noise.

use std::sync::Arc;

use anyhow::Context;
use bibavpn::crypto_layer::{self, SessionCrypto};
use bibavpn::frame::DEFAULT_MAX_WS_BINARY;
use bibavpn::http_connect;
use bibavpn::protocol::encode_open;
use bibavpn::stealth::{WsHandshakeParams, build_websocket_request};
use bibavpn::tls_util::{client_config_insecure, client_config_system_roots, install_ring_crypto};
use bibavpn::ws_bridge::{self, TunnelEnd};
use bibavpn::{socks5, socks5::socks5_handshake};
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "bibavpn-client",
    about = "SOCKS5 / HTTP CONNECT front for BibaVPN (v2.1: WS ping, MTU cap, custom WS headers)"
)]
struct Args {
    #[arg(long)]
    server: String,

    #[arg(long, default_value = "change-me")]
    token: String,

    #[arg(long)]
    sni: Option<String>,

    #[arg(long, default_value = "127.0.0.1:1080")]
    socks5: String,

    /// HTTP CONNECT proxy bind (e.g. 127.0.0.1:8080). Omit to disable.
    #[arg(long)]
    http_proxy: Option<String>,

    #[arg(long)]
    insecure: bool,

    #[arg(long, default_value = "64")]
    max_pad: u8,

    #[arg(long, default_value = "0")]
    junk_frames: u32,

    /// Random binary WebSocket frames right after upgrade (before junk / HELLO). Shapes startup.
    #[arg(long, default_value = "0")]
    early_ws_frames: u8,

    #[arg(long)]
    psk: Option<String>,

    #[arg(long, default_value = "0")]
    decoy_max: u8,

    /// Override WebSocket `Host` header (default: SNI or SNI:port).
    #[arg(long)]
    ws_host: Option<String>,

    #[arg(long)]
    ws_origin: Option<String>,

    #[arg(long)]
    ws_user_agent: Option<String>,

    #[arg(long)]
    ws_accept_language: Option<String>,

    /// Extra header `Name: value` (repeatable). BibaV2.1.
    #[arg(long = "ws-header")]
    ws_headers: Vec<String>,

    #[arg(long, default_value_t = DEFAULT_MAX_WS_BINARY)]
    max_ws_binary: usize,

    /// WebSocket ping interval seconds (0 = off). Keeps NAT / middleboxes warm.
    #[arg(long, default_value_t = 25)]
    ws_ping_secs: u64,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    install_ring_crypto();
    let args = Args::parse();

    let tls = if args.insecure {
        info!("TLS: certificate verification disabled (lab only)");
        client_config_insecure()
    } else {
        client_config_system_roots()?
    };

    let (server_host, server_port) = parse_host_port(&args.server)?;
    let sni_owned = args.sni.clone().unwrap_or_else(|| server_host.clone());
    if args.psk.is_some() {
        info!(
            "BibaV2/v2.1 PSK mode, decoy_max={}, max_ws_binary={}, ws_ping_secs={}",
            args.decoy_max, args.max_ws_binary, args.ws_ping_secs
        );
    }

    let mut extra = Vec::new();
    for line in &args.ws_headers {
        extra.push(parse_ws_header(line)?);
    }

    let cfg = Arc::new(ClientCfg {
        server_host: server_host.clone(),
        server_port,
        sni: sni_owned,
        token: args.token.clone(),
        tls,
        max_pad: args.max_pad,
        junk_frames: args.junk_frames,
        early_ws_frames: args.early_ws_frames,
        psk: args.psk.clone(),
        decoy_max: args.decoy_max,
        ws_host: args.ws_host.clone(),
        ws_origin: args.ws_origin.clone(),
        ws_user_agent: args.ws_user_agent.clone(),
        ws_accept_language: args.ws_accept_language.clone(),
        ws_extra_headers: Arc::new(extra),
        max_ws_binary: args.max_ws_binary,
        ws_ping_secs: args.ws_ping_secs,
    });

    let socks_listener = TcpListener::bind(&args.socks5)
        .await
        .with_context(|| format!("bind socks {}", args.socks5))?;
    info!("SOCKS5 on {}", args.socks5);

    if let Some(ref http_bind) = args.http_proxy {
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
        let (sock, peer) = socks_listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks_peer(sock, cfg).await {
                error!("socks {peer}: {e:#}");
            }
        });
    }
}

fn parse_ws_header(line: &str) -> anyhow::Result<(String, String)> {
    let (k, v) = line
        .split_once(':')
        .with_context(|| format!("--ws-header must be 'Name: value', got {line:?}"))?;
    Ok((k.trim().to_string(), v.trim().to_string()))
}

fn parse_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    let s = s.trim();
    if let Some(i) = s.rfind(':') {
        let (h, p) = s.split_at(i);
        let p = p.trim_start_matches(':').parse::<u16>()?;
        return Ok((h.to_string(), p));
    }
    anyhow::bail!("expected host:port, got {s}");
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
    send_noise_binaries(&mut ws, cfg.junk_frames, cfg.max_ws_binary).await.context("junk frames")?;

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
        let m = ws
            .next()
            .await
            .context("eof before ACK")?
            .context("ws")?;
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
