use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bibavpn::crypto_layer::{self, SessionCrypto};
use bibavpn::frame::{PadMode, DEFAULT_MAX_WS_BINARY};
use bibavpn::incoming::{accept_websocket_or_camouflage, CamouflageServeConfig};
use bibavpn::invite_uri::{encode_invite_v1, InviteV1};
use bibavpn::local_client::{
    normalize_ws_path, parse_host_port, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use bibavpn::protocol::{
    decode_v3_auth, decode_v3_open_with_flags, encode_v3_open_err, encode_v3_open_ok, is_v3_mux_open,
    is_v3_udp_mux_open, OPEN_FLAG_STATUS,
};
use bibavpn::{read_padded_frame_into, write_padded_frame_with_mode};
use bibavpn::tls_util::{install_ring_crypto, server_config_from_pem, server_self_signed};
use bibavpn::ws_bridge::TunnelEnd;
use bibavpn::reality::{bridge_reality_server, extract_sni, RealityServerConfig};
use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustls::ServerConfig;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "bibavpn-server",
    about = "BibaVPN WSS entrypoint (use behind a real TLS proxy in production)."
)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,

    #[arg(long, default_value = "change-me")]
    token: String,

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

    /// Inner frame padding mode: `random` or `http-buckets`.
    #[arg(long, default_value = "random")]
    pad_mode: String,

    /// Send idle padded empty frames on TCP tunnels (0 = off). Matches client `--dummy-interval-secs`.
    #[arg(long, default_value_t = 0)]
    dummy_interval_secs: u64,

    /// Biba v3 domain string for PSK key separation (must match client / invite). Default `default`.
    #[arg(long, default_value = "default")]
    proto_domain: String,

    /// REALITY mode: target to steal TLS from (e.g., vk.com:443)
    #[arg(long)]
    reality_target: Option<String>,

    /// REALITY mode: server private key (base64 encoded X25519)
    #[arg(long)]
    reality_private_key: Option<String>,

    /// REALITY mode: allowed short IDs (hex, comma-separated). Empty = any.
    #[arg(long)]
    reality_short_ids: Option<String>,

    /// REALITY mode: server names for SNI (comma-separated). Default: extracted from target.
    #[arg(long)]
    reality_server_names: Option<String>,
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
        let passphrase = args
            .invite_passphrase
            .as_deref()
            .expect("clap requires invite_passphrase");
        let invite = InviteV1 {
            v: 1,
            server: public.clone(),
            sni,
            token: args.token.clone(),
            proto: 3,
            proto_domain: None,
            psk: args.psk.clone(),
            decoy_max: args.decoy_max,
            max_pad: args.max_pad,
            max_ws_binary: args.max_ws_binary,
            ws_ping_secs: args.ws_ping_secs,
            ws_ping_jitter_percent: args.ws_ping_jitter_percent,
            ws_binary_send_jitter_ms: args.ws_binary_send_jitter_ms,
            udp_max_pad: args.udp_max_pad,
            udp_max_ws_binary: args.udp_max_ws_binary,
            udp_mux_reply_timeout_secs: DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
            insecure: lab_insecure,
            tls_profile: "default".into(),
            ws_path: Some(ws_path.clone()),
            pad_mode: Some(match pad_mode {
                PadMode::Random => "random".into(),
                PadMode::HttpBuckets => "http-buckets".into(),
            }),
            dummy_interval_secs: Some(args.dummy_interval_secs).filter(|&x| x > 0),
        };
        let uri = encode_invite_v1(&invite, passphrase).context("build invite URI")?;
        println!("{}", uri);
        eprintln!("bibavpn-server: invite URI on stdout; keep --invite-passphrase secret (not in log aggregation).");
    }

    let token = args.token.clone();
    let max_pad = args.max_pad;
    let psk = args.psk.clone();
    let decoy_max = args.decoy_max;
    let max_ws_binary = args.max_ws_binary;
    let ws_ping_secs = args.ws_ping_secs;
    let ws_ping_jitter_percent = args.ws_ping_jitter_percent;
    let ws_binary_send_jitter_ms = args.ws_binary_send_jitter_ms;
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
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(|| vec![extract_sni(target)]);

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

    loop {
        let (stream, peer) = listener.accept().await?;
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
        tokio::spawn(async move {
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
                udp_mux_pad,
                udp_mux_ws,
                udp_mux_recv,
                pad_mode,
                dummy_interval_secs,
                camo,
                proto_domain,
                reality_cfg,
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
    ws_path: String,
    legacy_path_auth: bool,
    max_pad: u8,
    psk: Option<String>,
    decoy_max: u8,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    udp_mux_max_pad: u8,
    udp_mux_max_ws_binary: usize,
    udp_mux_recv_timeout: Duration,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
    camo: CamouflageServeConfig,
    proto_domain: String,
    reality_config: Option<RealityServerConfig>,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(tcp).await.context("tls accept")?;

    let Some((mut ws, _ws_kind)) =
        accept_websocket_or_camouflage(tls, &ws_path, legacy_path_auth, &token, camo).await?
    else {
        return Ok(());
    };

    if let Some(ref reality_cfg) = reality_config {
        info!("REALITY mode: forwarding to {}", reality_cfg.target);
        return bridge_reality_server(
            ws,
            reality_cfg.clone(),
            max_pad,
            decoy_max,
            pad_mode,
            ws_ping_secs,
            ws_ping_jitter_percent,
        )
        .await
        .context("REALITY bridge");
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
    )
    .await
    .context("handshake")?;

    match wait_first_channel(ws, &crypto).await? {
        FirstChannel::Tcp {
            host,
            port,
            mut ws,
            supports_open_status,
        } => {
            info!("OPEN {host}:{port}");
            let remote = match TcpStream::connect((host.as_str(), port)).await {
                Ok(remote) => remote,
                Err(e) => {
                    if supports_open_status {
                        if let Ok(inner) =
                            encode_v3_open_err(&format!("connect {host}:{port}: {e:#}"))
                        {
                            let mut wire = Vec::new();
                            if write_padded_frame_with_mode(&mut wire, &inner, max_pad, pad_mode)
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
                write_padded_frame_with_mode(&mut wire, &inner, max_pad, pad_mode)
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
                Vec::new(),
                remote,
                Vec::new(),
                max_pad,
                decoy_max,
                Some(crypto.clone()),
                max_ws_binary,
                ws_ping_secs,
                ws_ping_jitter_percent,
                ws_binary_send_jitter_ms,
                TunnelEnd::Server,
                pad_mode,
                dummy_interval_secs,
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
                udp_mux_recv_timeout,
                pad_mode,
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
                pad_mode,
                dummy_interval_secs,
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

async fn wait_first_channel<S>(
    mut ws: WebSocketStream<S>,
    crypto: &SharedCrypto,
) -> anyhow::Result<FirstChannel<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    while let Some(m) = ws.next().await {
        let m = m.context("ws read")?;
        match m {
            Message::Binary(b) => {
                let raw = crypto
                    .open_client_to_server(b.as_ref())
                    .context("decrypt v3 control")?;
                let inner = read_padded_frame_into(raw).context("padded v3 control")?;
                if let Ok((h, p, flags)) = decode_v3_open_with_flags(&inner) {
                    return Ok(FirstChannel::Tcp {
                        host: h,
                        port: p,
                        supports_open_status: (flags & OPEN_FLAG_STATUS) != 0,
                        ws,
                    });
                }
                if is_v3_udp_mux_open(&inner) {
                    return Ok(FirstChannel::UdpMux { ws });
                }
                if is_v3_mux_open(&inner) {
                    return Ok(FirstChannel::Mux { ws });
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
) -> anyhow::Result<SharedCrypto>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let domain = proto_domain.to_string();
    let fut = async {
        loop {
            let m = ws
                .next()
                .await
                .context("eof during handshake")?
                .context("ws error")?;
            match m {
                Message::Binary(b) => {
                    if b.is_empty() || b.as_ref()[0] != crypto_layer::V3_HELLO_TAG {
                        continue;
                    }
                    let c = match crypto_layer::parse_hello_v3(b.as_ref()) {
                        Ok(x) => x,
                        Err(_) => continue,
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
                    server_wait_v3_auth(ws, &crypto, token).await?;
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
    timeout(Duration::from_secs(15), fut)
        .await
        .map_err(|_| anyhow::anyhow!("handshake timeout"))?
}

async fn server_wait_v3_auth<S>(
    ws: &mut WebSocketStream<S>,
    crypto: &SharedCrypto,
    expected_token: &str,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let m = ws
            .next()
            .await
            .context("eof before v3 AUTH")?
            .context("ws read")?;
        match m {
            Message::Binary(b) => {
                let raw = crypto
                    .open_client_to_server(b.as_ref())
                    .context("v3 open auth")?;
                let inner = read_padded_frame_into(raw).context("v3 auth frame")?;
                let tok = decode_v3_auth(&inner).context("decode v3 auth")?;
                if tok != expected_token {
                    anyhow::bail!("v3 auth token mismatch");
                }
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

