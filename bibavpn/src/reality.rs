//! REALITY-style front authentication for BibaVPN (WSS path).
//!
//! BibaVPN runs REALITY **after** the outer TLS + WebSocket upgrade (unlike Xray, which hooks
//! TLS ClientHello). Flow:
//!
//! 1. Client opens TLS to the VPS with **SNI = front domain** (`reality_target`, e.g. `vk.com`).
//! 2. Standard WSS upgrade on `--ws-path`.
//! 3. Binary REALITY frames: X25519 ephemeral + short ID → server long-term pubkey (pinned in invite).
//! 4. Plaintext mux (`MUX_OPEN`) or v3 PSK tunnel follows.
//!
//! SpiderX background fetches keep server-side camouflage warm against the REALITY target.

use std::sync::Arc;

use anyhow::{bail, Context};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// REALITY protocol magic bytes (reserved for future wire extensions).
pub const REALITY_MAGIC: &[u8] = b"REAL1";
pub const REALITY_VERSION: u8 = 1;

/// Max Ping/Pong frames tolerated during the REALITY handshake before the peer
/// is rejected. Stops a pre-auth peer from holding the loop open indefinitely or
/// forcing unbounded Pong replies (amplification).
const MAX_HANDSHAKE_CONTROL_FRAMES: u32 = 16;

/// REALITY server configuration
#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    /// Target website for SpiderX / operator reference (e.g., "vk.com:443")
    pub target: String,
    /// Accepted TLS SNI / Host values for REALITY clients
    pub server_names: Vec<String>,
    /// Server's private key (X25519)
    pub private_key: [u8; 32],
    /// Short IDs for client identification (8 bytes each); empty = any; all-zero entry = wildcard
    pub short_ids: Vec<[u8; 8]>,
    pub min_client_ver: Option<String>,
    pub max_client_ver: Option<String>,
    pub max_time_diff: u64,
}

impl RealityServerConfig {
    /// Generate new X25519 keypair `(private, public)`.
    pub fn generate_keys() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    /// Long-term public key bytes for client invite pinning.
    pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(*private_key);
        PublicKey::from(&secret).to_bytes()
    }

    /// Get public key as hex string (for client config)
    pub fn public_key_hex(&self) -> String {
        hex::encode(Self::public_key_from_private(&self.private_key))
    }

    /// Default short ID: first 8 bytes of public key (Xray-style convenience).
    pub fn generate_short_id(&self) -> [u8; 8] {
        let pub_key = Self::public_key_from_private(&self.private_key);
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&pub_key[..8]);
        sid
    }
}

/// REALITY client configuration
#[derive(Debug, Clone)]
pub struct RealityClientConfig {
    pub server_public_key: [u8; 32],
    pub server_name: String,
    pub short_id: [u8; 8],
    pub spider_path: String,
    pub fingerprint: TlsFingerprint,
}

/// TLS fingerprint to use (outer WSS path; Boring/rustls profile elsewhere).
#[derive(Debug, Clone, Copy, Default)]
pub enum TlsFingerprint {
    #[default]
    Chrome,
    Firefox,
    Safari,
    Randomized,
}

impl TlsFingerprint {
    pub fn as_str(&self) -> &str {
        match self {
            TlsFingerprint::Chrome => "chrome",
            TlsFingerprint::Firefox => "firefox",
            TlsFingerprint::Safari => "safari",
            TlsFingerprint::Randomized => "randomized",
        }
    }
}

/// SNI for the outer TLS layer when REALITY is enabled: front domain from `target`.
pub fn effective_tls_sni(configured_sni: &str, reality_target: Option<&str>) -> String {
    reality_target
        .map(extract_sni)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| configured_sni.to_string())
}

/// Parse target string like "vk.com:443" into host and port
pub fn parse_target(target: &str) -> anyhow::Result<(String, u16)> {
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        bail!("invalid target format: {}", target);
    }
    let port: u16 = parts[0].parse().context("parse port")?;
    let host = parts[1].to_string();
    Ok((host, port))
}

/// Create TLS connector for outbound SpiderX fetches (verification disabled; lab fetch only).
pub fn create_tls_connector(_server_name: &str) -> anyhow::Result<TlsConnector> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpiderxInsecureVerifier))
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

#[derive(Debug)]
struct SpiderxInsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for SpiderxInsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Wire bytes for REALITY SERVER_HELLO: `[version][server_x25519_pubkey:32]`.
pub fn server_hello_from_private(private_key: &[u8; 32]) -> Vec<u8> {
    let server_pub = RealityServerConfig::public_key_from_private(private_key);
    let mut response = Vec::with_capacity(1 + 32);
    response.push(REALITY_VERSION);
    response.extend_from_slice(&server_pub);
    response
}

fn validate_short_id(short_id: &[u8; 8], cfg: &RealityServerConfig) -> anyhow::Result<()> {
    if is_short_id_allowed(short_id, &cfg.short_ids) {
        return Ok(());
    }
    bail!(
        "REALITY: short ID {:02x?} not in server allowlist (configure --reality-short-id / invite reality_short_id)",
        &short_id[..4]
    );
}

/// Server-side REALITY X25519 exchange: validate client HELLO, reply with pinned pubkey from `cfg.private_key`.
pub async fn server_handshake_reality<S>(
    ws: &mut WebSocketStream<S>,
    cfg: &RealityServerConfig,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut control_frames: u32 = 0;
    loop {
        let msg = match ws.next().await {
            Some(Ok(Message::Binary(b))) => b,
            Some(Ok(Message::Ping(p))) => {
                control_frames += 1;
                if control_frames > MAX_HANDSHAKE_CONTROL_FRAMES {
                    bail!("too many control frames during REALITY handshake");
                }
                ws.send(Message::Pong(p)).await.context("REALITY pong")?;
                continue;
            }
            Some(Ok(Message::Pong(_))) => {
                control_frames += 1;
                if control_frames > MAX_HANDSHAKE_CONTROL_FRAMES {
                    bail!("too many control frames during REALITY handshake");
                }
                continue;
            }
            Some(Ok(_)) => bail!("expected binary REALITY HELLO"),
            Some(Err(e)) => Err(e).context("websocket recv")?,
            None => bail!("ws closed before REALITY HELLO"),
        };

        if msg.len() < 1 + 32 + 8 {
            bail!("short REALITY HELLO");
        }
        if msg[0] != REALITY_VERSION {
            bail!("unsupported REALITY version: {}", msg[0]);
        }

        let client_pubkey: [u8; 32] = msg[1..33].try_into().unwrap();
        let mut short_id = [0u8; 8];
        short_id.copy_from_slice(&msg[33..41]);

        validate_short_id(&short_id, cfg)?;

        let server_secret = StaticSecret::from(cfg.private_key);
        let client_public = PublicKey::try_from(client_pubkey)
            .map_err(|_| anyhow::anyhow!("invalid REALITY client public key"))?;
        let _shared = server_secret.diffie_hellman(&client_public);

        let response = server_hello_from_private(&cfg.private_key);
        ws.send(Message::Binary(Bytes::from(response)))
            .await
            .context("send REALITY SERVER_HELLO")?;
        return Ok(());
    }
}

/// REALITY client connection (standalone helper; main client uses `reality_client_exchange_verify`).
pub async fn connect_reality_client(
    server_addr: &str,
    config: &RealityClientConfig,
    _target: &str,
) -> anyhow::Result<WebSocketStream<TlsStream<TcpStream>>> {
    use crate::stealth::{build_websocket_request, WsHandshakeParams};
    use crate::tls_util::TlsClientProfile;

    let (host, port) = parse_target(server_addr)?;
    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .context("connect to server")?;
    let _ = tcp.set_nodelay(true);

    let connector = create_tls_connector(&config.server_name)?;
    let sn = ServerName::try_from(config.server_name.clone())?;
    let tls = connector.connect(sn, tcp).await.context("TLS handshake")?;

    let tls_profile = match config.fingerprint {
        TlsFingerprint::Firefox => TlsClientProfile::Firefox65,
        TlsFingerprint::Randomized => TlsClientProfile::Randomized,
        TlsFingerprint::Chrome | TlsFingerprint::Safari => TlsClientProfile::default(),
    };

    let path = if config.spider_path.starts_with('/') {
        config.spider_path.clone()
    } else {
        format!("/{}", config.spider_path)
    };

    let req = build_websocket_request(WsHandshakeParams {
        host_for_tcp: &host,
        port,
        path: &path,
        sni: &config.server_name,
        host_header: None,
        origin: None,
        user_agent: None,
        accept_language: None,
        extra_headers: &[],
        tls_profile,
    });

    let (ws, _) = tokio_tungstenite::client_async(req, tls)
        .await
        .map_err(|e| anyhow::anyhow!(e))
        .context("websocket upgrade")?;
    Ok(ws)
}

/// Encode REALITY client HELLO: `[version][ephemeral_pubkey:32][short_id:8]`.
pub fn encode_client_hello(short_id: &[u8; 8], client_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(1 + 32 + 8);
    msg.push(REALITY_VERSION);
    msg.extend_from_slice(client_pubkey);
    msg.extend_from_slice(short_id);
    msg
}

/// Client REALITY HELLO + verify server pubkey (X25519 ephemeral).
pub async fn reality_client_exchange_verify<S>(
    ws: &mut WebSocketStream<S>,
    expected_server_pubkey: &[u8; 32],
    short_id: &[u8; 8],
) -> anyhow::Result<[u8; 32]>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let client_hello = encode_client_hello(short_id, ephemeral_public.as_bytes());
    ws.send(Message::Binary(Bytes::from(client_hello)))
        .await
        .context("send REALITY client hello")?;

    let mut control_frames: u32 = 0;
    loop {
        let msg = match ws.next().await {
            Some(Ok(Message::Binary(b))) => b,
            Some(Ok(Message::Ping(p))) => {
                control_frames += 1;
                if control_frames > MAX_HANDSHAKE_CONTROL_FRAMES {
                    bail!("too many control frames during REALITY handshake");
                }
                ws.send(Message::Pong(p))
                    .await
                    .context("REALITY client pong")?;
                continue;
            }
            Some(Ok(Message::Pong(_))) => {
                control_frames += 1;
                if control_frames > MAX_HANDSHAKE_CONTROL_FRAMES {
                    bail!("too many control frames during REALITY handshake");
                }
                continue;
            }
            Some(Ok(_)) => bail!("expected binary server hello"),
            Some(Err(e)) => Err(e).context("websocket recv")?,
            None => bail!("server closed during REALITY handshake"),
        };
        let server_pubkey = decode_server_hello(&msg)?;
        if server_pubkey != *expected_server_pubkey {
            bail!("REALITY: server public key mismatch (possible MITM)");
        }
        let server_public = PublicKey::from(server_pubkey);
        let shared_secret = ephemeral_secret.diffie_hellman(&server_public);
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(shared_secret.as_bytes());
        return Ok(session_key);
    }
}

/// Decode REALITY SERVER_HELLO
pub fn decode_server_hello(data: &[u8]) -> anyhow::Result<[u8; 32]> {
    if data.len() < 1 + 32 {
        bail!("short SERVER_HELLO");
    }
    if data[0] != REALITY_VERSION {
        bail!("version mismatch");
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[1..33]);
    Ok(pubkey)
}

/// SpiderX: fetch a page from the REALITY target (server-side cache warm-up).
pub async fn spiderx_fetch(target: &str, paths: &[&str]) -> anyhow::Result<Vec<u8>> {
    let (host, port) = parse_target(target)?;
    let addr = format!("{}:{}", host, port);

    let connector = create_tls_connector(&host)?;
    let tcp = TcpStream::connect(&addr).await.context("connect to target")?;
    let sn = ServerName::try_from(host.clone())?;
    let tls = connector.connect(sn, tcp).await.context("TLS")?;

    let (mut read, mut write) = tokio::io::split(tls);

    let path = paths.first().unwrap_or(&"/");
    let accept_language = if is_vk_host(&host) {
        "ru-RU,ru;q=0.9,en-US;q=0.5,en;q=0.4"
    } else {
        "en-US,en;q=0.5"
    };
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path, host, accept_language
    );

    write.write_all(request.as_bytes()).await.context("send request")?;
    drop(write);

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    let mut collected = 0;
    let max_collect = 32 * 1024;

    while collected < max_collect {
        let n = read.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        collected += n;
    }

    Ok(response)
}

fn is_vk_host(host: &str) -> bool {
    host == "vk.com"
        || host.ends_with(".vk.com")
        || host == "vk.ru"
        || host.ends_with(".vk.ru")
        || host == "m.vk.com"
}

/// SpiderX background task: periodically fetch content from target
pub async fn spawn_spiderx(target: String, interval_secs: u64) {
    let sni = extract_sni(&target);
    let paths: &[&str] = if is_vk_host(&sni) {
        &["/", "/video", "/audio", "/clips"]
    } else {
        &["/"]
    };

    info!("SpiderX: starting background crawler for {}", target);

    loop {
        let path = paths[rand::thread_rng().gen_range(0..paths.len())];

        match spiderx_fetch(&target, &[path]).await {
            Ok(data) => {
                info!(
                    "SpiderX: fetched {} bytes from {}{}",
                    data.len(),
                    target,
                    path
                );
            }
            Err(e) => {
                warn!("SpiderX: fetch failed: {}", e);
            }
        }

        let jitter = rand::thread_rng().gen_range(0..30);
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs + jitter)).await;
    }
}

pub fn install_ring_crypto() {
    crate::tls_util::install_ring_crypto();
}

pub fn extract_sni(target: &str) -> String {
    target.split(':').next().unwrap_or(target).to_string()
}

pub fn is_short_id_allowed(id: &[u8; 8], allowed: &[[u8; 8]]) -> bool {
    allowed.is_empty()
        || allowed.iter().any(|a| a == id)
        || allowed.iter().any(|a| a.iter().all(|&b| b == 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_target() {
        let (host, port) = parse_target("vk.com:443").unwrap();
        assert_eq!(host, "vk.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_key_generation() {
        let (priv_key, pub_key) = RealityServerConfig::generate_keys();
        assert_eq!(priv_key.len(), 32);
        assert_eq!(pub_key.len(), 32);
        assert_eq!(
            RealityServerConfig::public_key_from_private(&priv_key),
            pub_key
        );
    }

    #[test]
    fn effective_tls_sni_uses_front_domain() {
        assert_eq!(
            effective_tls_sni("vps.example.com", Some("vk.com:443")),
            "vk.com"
        );
        assert_eq!(effective_tls_sni("vps.example.com", None), "vps.example.com");
    }

    #[test]
    fn short_id_allowed_empty_list_accepts_any() {
        let id = [1u8; 8];
        assert!(is_short_id_allowed(&id, &[]));
    }

    #[test]
    fn short_id_allowed_wildcard_zeros() {
        let id = [9u8; 8];
        let allowed = [[0u8; 8]];
        assert!(is_short_id_allowed(&id, &allowed));
    }

    #[test]
    fn short_id_rejects_unknown_when_listed() {
        let id = [1, 2, 3, 4, 5, 6, 7, 8];
        let allowed = [[8, 7, 6, 5, 4, 3, 2, 1]];
        assert!(!is_short_id_allowed(&id, &allowed));
        assert!(is_short_id_allowed(&allowed[0], &allowed));
    }

    #[test]
    fn reality_x25519_shared_secret_roundtrip() {
        let (priv_key, expected_pub) = RealityServerConfig::generate_keys();
        let server_hello = server_hello_from_private(&priv_key);
        let decoded_pub = decode_server_hello(&server_hello).unwrap();
        assert_eq!(decoded_pub, expected_pub);

        let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::from(priv_key);
        let server_public = PublicKey::from(expected_pub);

        let c_shared = client_secret.diffie_hellman(&server_public);
        let s_shared = server_secret.diffie_hellman(&client_public);
        assert_eq!(c_shared.as_bytes(), s_shared.as_bytes());
    }

    #[test]
    fn client_hello_wire_layout() {
        let sid = [7u8; 8];
        let pk = [3u8; 32];
        let wire = encode_client_hello(&sid, &pk);
        assert_eq!(wire.len(), 41);
        assert_eq!(wire[0], REALITY_VERSION);
        assert_eq!(&wire[1..33], &pk);
        assert_eq!(&wire[33..41], &sid);
    }
}
