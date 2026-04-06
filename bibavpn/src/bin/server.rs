use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bibavpn::crypto_layer::{self, SessionCrypto};
use bibavpn::frame::DEFAULT_MAX_WS_BINARY;
use bibavpn::protocol::{decode_open, is_udp_mux_open};
use bibavpn::tls_util::{install_ring_crypto, server_config_from_pem, server_self_signed};
use bibavpn::ws_bridge::TunnelEnd;
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "bibavpn-server", about = "BibaVPN WSS entrypoint (use behind a real TLS proxy in production).")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,

    #[arg(long, default_value = "change-me")]
    token: String,

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
}

type SharedCrypto = Arc<SessionCrypto>;

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

    let token = args.token.clone();
    let max_pad = args.max_pad;
    let psk = args.psk.clone();
    let decoy_max = args.decoy_max;
    let max_ws_binary = args.max_ws_binary;
    let ws_ping_secs = args.ws_ping_secs;

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let token = token.clone();
        let psk = psk.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_one(
                stream,
                acceptor,
                token,
                max_pad,
                psk,
                decoy_max,
                max_ws_binary,
                ws_ping_secs,
            )
            .await
            {
                error!("from {peer}: {e:#}");
            }
        });
    }
}

async fn handle_one(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    token: String,
    max_pad: u8,
    psk: Option<String>,
    decoy_max: u8,
    max_ws_binary: usize,
    ws_ping_secs: u64,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(tcp).await.context("tls accept")?;
    let path_ok = format!("/b/{token}");
    let ws = tokio_tungstenite::accept_hdr_async(tls, |req: &Request, response: Response| {
        if req.uri().path() != path_ok.as_str() {
            let err: ErrorResponse = http::Response::builder()
                .status(404)
                .body(Some("not found".to_string()))
                .unwrap();
            return Err(err);
        }
        Ok(response)
    })
    .await
    .context("ws accept")?;

    let mut ws = ws;
    let crypto: Option<SharedCrypto> = if let Some(ref secret) = psk {
        info!("BibaV2 PSK mode, decoy_max={decoy_max}");
        Some(Arc::new(
            v2_server_preamble(&mut ws, secret, decoy_max).await?,
        ))
    } else {
        None
    };

    match wait_first_channel(ws).await? {
        FirstChannel::Tcp { host, port, ws } => {
            info!("OPEN {host}:{port}");
            let remote = TcpStream::connect((host.as_str(), port))
                .await
                .with_context(|| format!("connect {host}:{port}"))?;
            bibavpn::ws_bridge::bridge_ws_tcp_padded(
                ws,
                remote,
                Vec::new(),
                max_pad,
                decoy_max,
                crypto,
                max_ws_binary,
                ws_ping_secs,
                TunnelEnd::Server,
            )
            .await?;
        }
        FirstChannel::UdpMux { ws } => {
            info!("UDP mux (same WSS/TLS envelope as TCP)");
            bibavpn::udp_mux::bridge_ws_udp_mux_server(
                ws,
                max_pad,
                decoy_max,
                crypto,
                max_ws_binary,
                ws_ping_secs,
            )
            .await?;
        }
    }
    Ok(())
}

enum FirstChannel<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    Tcp {
        host: String,
        port: u16,
        ws: WebSocketStream<S>,
    },
    UdpMux { ws: WebSocketStream<S> },
}

async fn wait_first_channel<S>(mut ws: WebSocketStream<S>) -> anyhow::Result<FirstChannel<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    while let Some(m) = ws.next().await {
        let m = m.context("ws read")?;
        match m {
            Message::Binary(b) => {
                if let Ok((h, p)) = decode_open(b.as_ref()) {
                    return Ok(FirstChannel::Tcp { host: h, port: p, ws });
                }
                if is_udp_mux_open(b.as_ref()) {
                    return Ok(FirstChannel::UdpMux { ws });
                }
            }
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.context("pong during OPEN wait")?;
            }
            Message::Close(_) => anyhow::bail!("closed before channel open"),
            _ => {}
        }
    }
    anyhow::bail!("eof before OPEN / UDP_MUX")
}

async fn v2_server_preamble<S>(
    ws: &mut WebSocketStream<S>,
    psk: &str,
    decoy_max: u8,
) -> anyhow::Result<SessionCrypto>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let m = ws
            .next()
            .await
            .context("ws closed before BibaV2 HELLO")?
            .context("ws read")?;
        let b = match m {
            Message::Binary(b) => b,
            Message::Ping(p) => {
                ws.send(Message::Pong(p)).await.context("pong during HELLO")?;
                continue;
            }
            Message::Pong(_) => continue,
            Message::Close(_) => anyhow::bail!("closed before HELLO"),
            _ => continue,
        };
        if b.len() == crypto_layer::HELLO_LEN && b.as_ref().starts_with(crypto_layer::HELLO_MAGIC) {
            let c = crypto_layer::parse_hello(b.as_ref())?;
            let (ack, s_rand) = crypto_layer::build_ack(psk, &c)?;
            ws.send(Message::Binary(Bytes::from(ack)))
                .await
                .context("send ACK")?;
            return Ok(SessionCrypto::new(psk, &c, &s_rand, decoy_max));
        }
    }
}

