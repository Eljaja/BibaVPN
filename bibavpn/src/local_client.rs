//! Shared SOCKS5 / HTTP CONNECT front-end for desktop binary and Android JNI.

use std::sync::Arc;

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
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info};

use crate::crypto_layer::{self, SessionCrypto};
use crate::decoy_traffic::{spawn_decoy_gets, DecoyConfig};
use crate::frame::{PadMode, DEFAULT_MAX_WS_BINARY};
use crate::http_connect;
use crate::protocol::{
    decode_open_err, decode_v3_open_err, encode_auth, encode_open, encode_v3_auth,
    encode_v3_mux_open, encode_v3_open_with_flags, is_open_ok, is_v3_open_ok, OPEN_FLAG_STATUS,
};
use crate::retry::{sleep_outbound_backoff, OUTBOUND_CONNECT_ATTEMPTS};
use crate::stealth::{build_websocket_request, default_user_agent_for_profile, WsHandshakeParams};
use crate::tcp_mux::{self, MuxClientConfig, MuxOpenStreamDropped, TcpMuxClientHandle};
use crate::tls_util::{client_tls_config, ClientTlsParams, TlsClientProfile};
use crate::udp_mux::{spawn_udp_mux_driver, UdpMuxConfig, UdpMuxHandle};
use crate::ws_bridge::{self, TunnelEnd};
use crate::{read_padded_frame, write_padded_frame_with_mode, socks5, socks5::SocksCommand};
use bytes::Bytes;

/// SOCKS UDP: limit concurrent in-flight mux requests per datagram worker pool.
const SOCKS_UDP_WORKERS: usize = 256;

/// After the shared mux WSS dies, reopen quickly without the full outbound backoff ladder.
const TCP_MUX_SLOT_RETRIES: u32 = 8;
const OPEN_STATUS_WAIT: Duration = Duration::from_millis(350);

async fn sleep_mux_slot_retry(attempt: u32) {
    let ms = (50u64 * (attempt as u64 + 1)).min(800);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

fn tcp_mux_writer_gone(e: &anyhow::Error) -> bool {
    format!("{e:#}").contains("tcp mux writer stopped")
}

type TcpMuxSlot = Arc<Mutex<Option<(u64, TcpMuxClientHandle)>>>;

async fn tcp_mux_open_stream_with_retry(
    mut local: TcpStream,
    host: String,
    port: u16,
    tcp_uplink_prefix: Vec<u8>,
    cfg: Arc<ClientCfg>,
    tcp_mux_slot: TcpMuxSlot,
) -> anyhow::Result<()> {
    for attempt in 0..TCP_MUX_SLOT_RETRIES {
        let h = {
            let mut slot = tcp_mux_slot.lock().await;
            if slot.is_none() {
                drop(slot);
                connect_tcp_mux_handle(&cfg, &tcp_mux_slot).await?;
                slot = tcp_mux_slot.lock().await;
            }
            slot.as_ref().expect("mux set").1.clone()
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
    unreachable!()
}

/// User-facing options (CLI, JSON over JNI, etc.).
#[derive(Clone, Debug)]
pub struct LocalClientOptions {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    pub token: String,
    pub socks_bind: String,
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
    /// Wire protocol: `2` default; `3` = opaque PSK + sealed control (requires PSK).
    pub proto: u8,
    /// Domain label for v3 PSK KDF; empty = use `sni`.
    pub proto_domain: String,
    /// REALITY: front domain / SNI (e.g. wikipedia.org).
    pub reality_target: Option<String>,
    /// REALITY: server's public key (32 bytes).
    pub reality_public_key: Option<[u8; 32]>,
    /// REALITY: short ID (8 bytes).
    pub reality_short_id: Option<[u8; 8]>,
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
            tls_profile: self.tls_profile,
            ws_path: self.ws_path.clone(),
            pad_mode: self.pad_mode,
            proto: self.proto,
            proto_domain: self.proto_domain.clone(),
        }
    }
}

fn effective_proto_domain(cfg: &ClientCfg) -> String {
    let t = cfg.proto_domain.trim();
    if t.is_empty() {
        cfg.sni.clone()
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
async fn reality_client_handshake(
    ws: &mut ClientWs,
    cfg: &ClientCfg,
) -> anyhow::Result<([u8; 32], [u8; 8])> {
    use crate::reality::encode_client_hello;
    use crate::reality::decode_server_hello;
    use x25519_dalek::{PublicKey, EphemeralSecret};
    use rand::rngs::OsRng;

    // Get server's expected public key from config
    let server_expected_pubkey = cfg.reality_public_key
        .ok_or_else(|| anyhow::anyhow!("REALITY: no server public key configured"))?;

    // Generate ephemeral keypair for this session
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let short_id = cfg.reality_short_id.unwrap_or_else(|| {
        let mut id = [0u8; 8];
        let bytes = rand::random::<[u8; 8]>();
        id.copy_from_slice(&bytes);
        id
    });

    // Build client HELLO: [version:1][pubkey:32][short_id:8]
    let client_hello = encode_client_hello(&short_id, ephemeral_public.as_bytes());

    // Send client hello
    ws.send(Message::Binary(bytes::Bytes::from(client_hello)))
        .await
        .context("send REALITY client hello")?;

    // Wait for server hello
    let msg = ws
        .next()
        .await
        .context("server closed during REALITY handshake")??
        .into_binary()
        .context("expected binary server hello")?;

    let server_pubkey = decode_server_hello(&msg)?;

    // Verify server's public key matches expected
    if server_pubkey != server_expected_pubkey {
        anyhow::bail!("REALITY: server public key mismatch - possible MITM attack!");
    }

    // Compute shared secret
    let server_public = PublicKey::from(server_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&server_public);
    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(shared_secret.as_bytes());

    info!(
        "REALITY handshake complete, session key derived, server verified"
    );

    Ok((session_key, short_id))
}

type SharedCrypto = Arc<SessionCrypto>;

type ClientWs = WebSocketStream<TlsStream<TcpStream>>;

/// One attempt: TCP + TLS + WS + noise + AUTH (v2) or v3 hello + sealed AUTH + optional BibaV2 preamble.
async fn one_try_wss_session(cfg: &ClientCfg) -> anyhow::Result<(ClientWs, Option<SharedCrypto>, bool)> {
    let is_v3 = cfg.proto >= 3;
    if is_v3 {
        anyhow::ensure!(cfg.psk.is_some(), "Biba v3 requires --psk (or invite psk)");
    }

    let domain = ServerName::try_from(cfg.sni.clone())?;
    let connector = tokio_rustls::TlsConnector::from(cfg.tls.clone());
    let path = cfg.ws_path.clone();

    let tcp =
        crate::outbound_protect::tcp_connect_host_protected(&cfg.server_host, cfg.server_port)
            .await
            .with_context(|| format!("connect server {}:{}", cfg.server_host, cfg.server_port))?;
    let _ = tcp.set_nodelay(true);
    let tls = connector.connect(domain, tcp).await.context("tls")?;

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

    let mut ws = tokio_tungstenite::client_async(req, tls)
        .await
        .map_err(|e| anyhow::anyhow!(e))
        .context("websocket")?
        .0;

    info!(
        target: "bibavpn_client",
        server = %cfg.server_host,
        port = cfg.server_port,
        sni = %cfg.sni,
        path = %path,
        proto = cfg.proto,
        "WSS handshake OK, sending noise + auth / v3 hello"
    );

    send_noise_binaries(&mut ws, u32::from(cfg.early_ws_frames), cfg.max_ws_binary).await?;
    send_noise_binaries(&mut ws, cfg.junk_frames, cfg.max_ws_binary)
        .await
        .context("junk frames")?;

    if is_v3 {
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
                        crypto_layer::parse_ack(secret, Some(dom.as_str()), b.as_ref(), &c_rand)?;
                    let crypto = Arc::new(SessionCrypto::new(
                        secret,
                        Some(dom.as_str()),
                        &c_rand,
                        &s_rand,
                        cfg.decoy_max,
                    ));
                    let auth_inner = encode_v3_auth(&cfg.token).context("encode v3 AUTH")?;
                    let mut wire = Vec::new();
                    write_padded_frame_with_mode(&mut wire, &auth_inner, cfg.max_pad, cfg.pad_mode)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let blob = crypto
                        .seal_client_to_server(&wire)
                        .await
                        .context("seal v3 AUTH")?;
                    ws.send(Message::Binary(Bytes::from(blob)))
                        .await
                        .context("send v3 AUTH")?;
                    return Ok((ws, Some(crypto), true));
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

    let auth = encode_auth(&cfg.token).context("encode AUTH")?;
    if auth.len() > cfg.max_ws_binary {
        anyhow::bail!("AUTH frame larger than --max-ws-binary");
    }
    ws.send(Message::Binary(Bytes::from(auth)))
        .await
        .context("send AUTH")?;

    let crypto: Option<SharedCrypto> = if let Some(ref secret) = cfg.psk {
        Some(Arc::new(
            v2_client_preamble(&mut ws, secret, cfg.decoy_max).await?,
        ))
    } else {
        None
    };

    Ok((ws, crypto, false))
}

async fn wait_open_status_or_payload<S>(
    ws: &mut WebSocketStream<S>,
    crypto: Option<&SharedCrypto>,
    proto_v3: bool,
) -> anyhow::Result<Vec<Message>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let m = ws.next().await.context("eof before OPEN result")??;
        match m {
            Message::Binary(b) => {
                if proto_v3 {
                    let c = crypto.context("v3 OPEN status")?;
                    let raw = c
                        .open_server_to_client(b.as_ref())
                        .await
                        .context("decrypt OPEN status")?;
                    let inner = read_padded_frame(&raw).context("padded OPEN status")?;
                    if is_v3_open_ok(&inner) {
                        return Ok(Vec::new());
                    }
                    if let Ok(err) = decode_v3_open_err(&inner) {
                        anyhow::bail!("remote OPEN failed: {err}");
                    }
                    return Ok(vec![Message::Binary(Bytes::from(inner))]);
                }
                if is_open_ok(b.as_ref()) {
                    return Ok(Vec::new());
                }
                if let Ok(err) = decode_open_err(b.as_ref()) {
                    anyhow::bail!("remote OPEN failed: {err}");
                }
                return Ok(vec![Message::Binary(b)]);
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
) -> anyhow::Result<(ClientWs, Option<SharedCrypto>, Vec<Message>)> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..OUTBOUND_CONNECT_ATTEMPTS {
        match one_try_wss_session(cfg).await {
            Ok((mut ws, crypto, proto_v3)) => {
                let open = if proto_v3 {
                    encode_v3_open_with_flags(host, port, OPEN_FLAG_STATUS)?
                } else {
                    encode_open(host, port)?
                };
                if open.len() > cfg.max_ws_binary && !proto_v3 {
                    anyhow::bail!("OPEN frame larger than --max-ws-binary");
                }
                if let Some(ref c) = crypto {
                    if proto_v3 {
                        let mut wire = Vec::new();
                        write_padded_frame_with_mode(&mut wire, &open, cfg.max_pad, cfg.pad_mode)
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        let blob = c
                            .seal_client_to_server(&wire)
                            .await
                            .context("seal OPEN v3")?;
                        if blob.len() > cfg.max_ws_binary {
                            anyhow::bail!("sealed OPEN exceeds --max-ws-binary");
                        }
                        ws.send(Message::Binary(Bytes::from(blob)))
                            .await
                            .context("send OPEN v3")?;
                    } else {
                        ws.send(Message::Binary(Bytes::from(open)))
                            .await
                            .context("send OPEN")?;
                    }
                } else {
                    ws.send(Message::Binary(Bytes::from(open)))
                        .await
                        .context("send OPEN")?;
                }
                let prefetched = match timeout(
                    OPEN_STATUS_WAIT,
                    wait_open_status_or_payload(&mut ws, crypto.as_ref(), proto_v3),
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

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..OUTBOUND_CONNECT_ATTEMPTS {
        let res: anyhow::Result<()> = async {
            let (mut ws, crypto, proto_v3) = one_try_wss_session(cfg).await?;
            let mo = if proto_v3 {
                encode_v3_mux_open()
            } else {
                tcp_mux::encode_mux_open()
            };
            if mo.len() > cfg.max_ws_binary && !proto_v3 {
                anyhow::bail!("MUX_OPEN larger than --max-ws-binary");
            }
            if let Some(ref c) = crypto {
                if proto_v3 {
                    let mut wire = Vec::new();
                    write_padded_frame_with_mode(&mut wire, &mo, cfg.max_pad, cfg.pad_mode)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let blob = c
                        .seal_client_to_server(&wire)
                        .await
                        .context("seal MUX_OPEN v3")?;
                    if blob.len() > cfg.max_ws_binary {
                        anyhow::bail!("sealed MUX_OPEN exceeds --max-ws-binary");
                    }
                    ws.send(Message::Binary(Bytes::from(blob)))
                        .await
                        .context("send MUX_OPEN v3")?;
                } else {
                    ws.send(Message::Binary(Bytes::from(mo)))
                        .await
                        .context("send MUX_OPEN")?;
                }
            } else {
                ws.send(Message::Binary(Bytes::from(mo)))
                    .await
                    .context("send MUX_OPEN")?;
            }
            let mcfg = MuxClientConfig {
                max_pad: cfg.max_pad,
                decoy_max: cfg.decoy_max,
                max_ws_binary: cfg.max_ws_binary,
                ws_ping_secs: cfg.ws_ping_secs,
                ws_ping_jitter_percent: cfg.ws_ping_jitter_percent,
                ws_binary_send_jitter_ms: cfg.ws_binary_send_jitter_ms,
                transport_v2: crypto.is_some(),
                pad_mode: cfg.pad_mode,
                dummy_interval_secs: cfg.dummy_interval_secs,
            };
            let (sid, h) = tcp_mux::spawn_tcp_mux_client(ws, crypto, mcfg, tcp_mux_slot.clone());
            info!(
                target: "bibavpn_client",
                session_id = sid,
                server = %cfg.server_host,
                port = cfg.server_port,
                "TCP mux tunnel ready"
            );
            *tcp_mux_slot.lock().await = Some((sid, h));
            Ok(())
        }
        .await;
        match res {
            Ok(()) => return Ok(()),
            Err(e) => {
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

/// REALITY mode: connect to server and perform REALITY handshake
async fn connect_reality_tcp_mux_handle(
    cfg: &Arc<ClientCfg>,
    tcp_mux_slot: &TcpMuxSlot,
) -> anyhow::Result<()> {
    use rustls::pki_types::ServerName;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::client_async;

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..OUTBOUND_CONNECT_ATTEMPTS {
        let res: anyhow::Result<()> = async {
            let _target = cfg.reality_target.as_ref().expect("reality target");
            let domain = ServerName::try_from(cfg.sni.clone())?;
            let connector = tokio_rustls::TlsConnector::from(cfg.tls.clone());
            let tcp = crate::outbound_protect::tcp_connect_host_protected(
                &cfg.server_host,
                cfg.server_port,
            )
            .await
            .context("connect server")?;
            let _ = tcp.set_nodelay(true);
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

            let mut ws = client_async(req, tls)
                .await
                .map_err(|e| anyhow::anyhow!(e))
                .context("websocket")?
                .0;

            info!(
                target: "bibavpn_client",
                server = %cfg.server_host,
                port = cfg.server_port,
                "REALITY: WSS up, key exchange"
            );

            let (_session_key, short_id) = reality_client_handshake(&mut ws, cfg).await?;

            info!(
                "REALITY: handshake complete, short_id={:02x?}",
                &short_id[..4]
            );

            let open = tcp_mux::encode_mux_open();
            ws.send(Message::Binary(Bytes::from(open)))
                .await
                .context("send MUX_OPEN")?;

            let mcfg = MuxClientConfig {
                max_pad: cfg.max_pad,
                decoy_max: cfg.decoy_max,
                max_ws_binary: cfg.max_ws_binary,
                ws_ping_secs: cfg.ws_ping_secs,
                ws_ping_jitter_percent: cfg.ws_ping_jitter_percent,
                ws_binary_send_jitter_ms: cfg.ws_binary_send_jitter_ms,
                transport_v2: false,
                pad_mode: cfg.pad_mode,
                dummy_interval_secs: cfg.dummy_interval_secs,
            };

            let (sid, h) = tcp_mux::spawn_tcp_mux_client(ws, None, mcfg, tcp_mux_slot.clone());

            info!(
                target: "bibavpn_client",
                session_id = sid,
                server = %cfg.server_host,
                "REALITY tunnel ready"
            );
            *tcp_mux_slot.lock().await = Some((sid, h));
            Ok(())
        }
        .await;

        match res {
            Ok(()) => return Ok(()),
            Err(e) => {
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
    let tls = client_tls_config(&ClientTlsParams {
        insecure: opts.insecure_tls,
        profile: opts.tls_profile,
        pinned_certs_pem: opts.pinned_certs_pem.clone(),
    })?;

    let udp_mux_max_pad = opts.udp_max_pad.unwrap_or(opts.max_pad);
    let udp_mux_max_ws_binary = opts.udp_max_ws_binary.unwrap_or(opts.max_ws_binary);

    if opts.psk.is_some() {
        info!(
            "BibaV2/v2.1 PSK mode, decoy_max={}, max_ws_binary={}, ws_ping_secs={}",
            opts.decoy_max, opts.max_ws_binary, opts.ws_ping_secs
        );
    }
    if opts.use_tcp_mux {
        info!("TCP mode: multiplexed WSS (one outer connection)");
    } else {
        info!("TCP mode: legacy per-connection WSS (--no-mux)");
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
        sni: opts.sni,
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
    });

    if cfg.decoy_gets {
        let ua = default_user_agent_for_profile(cfg.tls_profile).to_string();
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
            },
            shutdown.clone(),
        );
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
    match socks5::socks5_read_command(&mut local).await? {
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
                    crypto,
                    cfg.max_ws_binary,
                    cfg.ws_ping_secs,
                    cfg.ws_ping_jitter_percent,
                    cfg.ws_binary_send_jitter_ms,
                    TunnelEnd::Client,
                    cfg.pad_mode,
                    cfg.dummy_interval_secs,
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
    let reply_timeout = if cfg.udp_mux_reply_timeout_secs > 0 {
        Some(Duration::from_secs(cfg.udp_mux_reply_timeout_secs))
    } else {
        None
    };

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
                        let xid: u64 = rand::random();
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        handle.forward(xid, dst_host, dst_port, payload, tx)?;
                        let reply = match reply_timeout {
                            Some(d) => match timeout(d, rx).await {
                                Ok(inner) => inner,
                                Err(_) => {
                                    error!("udp mux: reply timeout for xid {xid}");
                                    return Ok(());
                                }
                            },
                            None => rx.await,
                        };
                        match reply {
                            Ok(Ok(socks_body)) => {
                                udp.send_to(&socks_body, peer).await?;
                            }
                            Ok(Err(e)) => error!("udp mux: {e:#}"),
                            Err(_) => error!("udp mux driver dropped channel"),
                        }
                        Ok(())
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
                    crypto,
                    cfg.max_ws_binary,
                    cfg.ws_ping_secs,
                    cfg.ws_ping_jitter_percent,
                    cfg.ws_binary_send_jitter_ms,
                    TunnelEnd::Client,
                    cfg.pad_mode,
                    cfg.dummy_interval_secs,
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
        crypto,
        cfg.max_ws_binary,
        cfg.ws_ping_secs,
        cfg.ws_ping_jitter_percent,
        cfg.ws_binary_send_jitter_ms,
        TunnelEnd::Client,
        cfg.pad_mode,
        cfg.dummy_interval_secs,
    )
    .await
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

/// Default `max_ws_binary` for clients (BibaV2.1 MTU cap).
pub const DEFAULT_CLIENT_MAX_WS_BINARY: usize = DEFAULT_MAX_WS_BINARY;

/// Default SOCKS UDP-mux reply wait (seconds). Server embeds this in `biba://` invites for clients.
pub const DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS: u64 = 130;
