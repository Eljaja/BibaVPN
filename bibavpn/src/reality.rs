//! REALITY protocol implementation for BibaVPN
//! Based on: https://github.com/XTLS/REALITY
//!
//! REALITY is a protocol that "steals" TLS from a target website.
//! The server relays TLS handshake to a target (e.g., vk.com:443)
//! and the client receives the REAL certificate from that target.
//! To DPI, the traffic looks like normal HTTPS to the target website.

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
use x25519_dalek::{PublicKey, StaticSecret};

use crate::frame::PadMode;

/// REALITY protocol magic bytes
pub const REALITY_MAGIC: &[u8] = b"REAL1";
pub const REALITY_VERSION: u8 = 1;

/// REALITY server configuration
#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    /// Target website to steal TLS from (e.g., "vk.com:443")
    pub target: String,
    /// Accepted server names (SNI) - must include target's SNI
    pub server_names: Vec<String>,
    /// Server's private key (X25519)
    pub private_key: [u8; 32],
    /// Short IDs for client identification (8 bytes each)
    pub short_ids: Vec<[u8; 8]>,
    /// Minimum client version (e.g., "1.0.0")
    pub min_client_ver: Option<String>,
    /// Maximum client version
    pub max_client_ver: Option<String>,
    /// Maximum time difference in milliseconds
    pub max_time_diff: u64,
}

impl RealityServerConfig {
    /// Generate new X25519 keypair
    pub fn generate_keys() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    /// Get public key as hex string (for client config)
    pub fn public_key_hex(&self) -> String {
        let secret = StaticSecret::from(self.private_key);
        let public = PublicKey::from(&secret);
        hex::encode(public.to_bytes())
    }

    /// Generate short ID from public key (first 8 bytes)
    pub fn generate_short_id(&self) -> [u8; 8] {
        let secret = StaticSecret::from(self.private_key);
        let public = PublicKey::from(&secret);
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&public.to_bytes()[..8]);
        sid
    }
}

/// REALITY client configuration
#[derive(Debug, Clone)]
pub struct RealityClientConfig {
    /// Server's public key (from server's private key)
    pub server_public_key: [u8; 32],
    /// One of server's allowed server names
    pub server_name: String,
    /// One of server's short IDs
    pub short_id: [u8; 8],
    /// Target website (for SpiderX crawler)
    pub spider_path: String,
    /// Client TLS fingerprint
    pub fingerprint: TlsFingerprint,
}

/// TLS fingerprint to use
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

/// Certificate verification result
#[derive(Debug)]
pub enum CertVerifyResult {
    /// Temporary trusted certificate (REALITY working)
    TemporaryTrusted,
    /// Real certificate from target (need SpiderX crawl)
    RealCertificate,
    /// Invalid certificate
    Invalid,
}

/// REALITY TLS server that forwards to target
#[allow(dead_code)]
pub struct RealityTlsServer {
    target: String,
    server_names: Vec<String>,
    private_key: [u8; 32],
    short_ids: Vec<[u8; 8]>,
}

impl RealityTlsServer {
    pub fn new(config: RealityServerConfig) -> Self {
        Self {
            target: config.target,
            server_names: config.server_names,
            private_key: config.private_key,
            short_ids: config.short_ids,
        }
    }

    /// Handle incoming TLS connection and forward to target
    pub async fn handle_connection<S>(&self, _stream: S) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Parse target address
        let (target_host, target_port) = parse_target(&self.target)?;
        
        // Connect to target
        let target_addr = format!("{}:{}", target_host, target_port);
        let target_stream = TcpStream::connect(&target_addr)
            .await
            .context("connect to target")?;

        // Create TLS connector to target
        let connector = create_tls_connector(&target_host)?;
        
        // Do TLS handshake with target
        let sn = ServerName::try_from(target_host.clone())?;
        let _target_tls = connector
            .connect(sn, target_stream)
            .await
            .context("TLS handshake with target")?;

        // Now we have a stream that looks like REAL TLS to target
        // The client will receive the REAL certificate from target
        
        // For now, just forward data
        // In full implementation, we'd bridge this to the client WebSocket
        Ok(())
    }
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

/// Create TLS connector for target
pub fn create_tls_connector(_server_name: &str) -> anyhow::Result<TlsConnector> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Insecure verifier - we verify based on REALITY logic, not standard TLS
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // In REALITY, we accept any certificate
        // The real verification happens at a different layer
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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// REALITY Session - holds state for one client connection
#[allow(dead_code)]
pub struct RealitySession {
    /// Server private key
    private_key: [u8; 32],
    /// Target to forward to (e.g., "vk.com:443")
    target: String,
    /// Allowed server names
    server_names: Vec<String>,
    /// Short IDs for clients
    short_ids: Vec<[u8; 8]>,
    /// Session key derived from key exchange
    session_key: Option<[u8; 32]>,
    /// Client's short ID
    client_short_id: Option<[u8; 8]>,
    /// Max padding
    max_pad: u8,
    /// Decoy max
    decoy_max: u8,
}

impl RealitySession {
    pub fn new(config: &RealityServerConfig, max_pad: u8, decoy_max: u8) -> Self {
        Self {
            private_key: config.private_key,
            target: config.target.clone(),
            server_names: config.server_names.clone(),
            short_ids: config.short_ids.clone(),
            session_key: None,
            client_short_id: None,
            max_pad,
            decoy_max,
        }
    }

    /// Perform REALITY key exchange with client
    pub async fn handshake<S>(
        &mut self,
        ws: &mut WebSocketStream<S>,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Wait for client HELLO with short ID and public key
        let msg = match ws.next().await {
            Some(Ok(Message::Binary(b))) => b,
            Some(Ok(_)) => bail!("expected binary REALITY HELLO"),
            Some(Err(e)) => Err(e).context("websocket recv")?,
            None => bail!("ws closed before REALITY HELLO"),
        };

        if msg.len() < 1 + 32 + 8 {
            bail!("short REALITY HELLO");
        }

        // Parse: [version:1][client_pubkey:32][short_id:8][...padding]
        let version = msg[0];
        if version != REALITY_VERSION {
            bail!("unsupported REALITY version: {}", version);
        }

        let client_pubkey: [u8; 32] = msg[1..33].try_into().unwrap();
        let mut short_id = [0u8; 8];
        short_id.copy_from_slice(&msg[33..41]);

        // Verify short_id is in allowed list
        if !self.short_ids.is_empty() 
            && !self.short_ids.iter().any(|s| s == &short_id)
            && !self.short_ids.iter().any(|s| s.iter().all(|&b| b == 0)) {
            bail!("invalid short ID");
        }

        self.client_short_id = Some(short_id);

        // Perform X25519 key exchange
        let server_secret = StaticSecret::from(self.private_key);
        let client_public = PublicKey::try_from(client_pubkey)
            .map_err(|_| anyhow::anyhow!("invalid REALITY client public key"))?;
        let shared_secret = server_secret.diffie_hellman(&client_public);
        
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(shared_secret.as_bytes());
        self.session_key = Some(session_key);

        // Send SERVER HELLO: [version:1][server_pubkey:32][...TLS cert from target...]
        let (server_priv, server_pub) = RealityServerConfig::generate_keys();
        self.private_key = server_priv; // Update for next session

        let mut response = Vec::with_capacity(1 + 32);
        response.push(REALITY_VERSION);
        response.extend_from_slice(&server_pub);

        ws.send(Message::Binary(Bytes::from(response)))
            .await
            .context("send REALITY SERVER_HELLO")?;

        Ok(())
    }
}

/// Bridge WebSocket to REALITY TLS target (server side)
pub async fn bridge_reality_server<S>(
    ws: WebSocketStream<S>,
    config: RealityServerConfig,
    _max_pad: u8,
    _decoy_max: u8,
    _pad_mode: PadMode,
    _ws_ping_secs: u64,
    _ws_ping_jitter_percent: u8,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (target_host, target_port) = parse_target(&config.target)?;
    let target_addr = format!("{}:{}", target_host, target_port);

    // Connect to target and do TLS handshake
    let target_tcp = TcpStream::connect(&target_addr)
        .await
        .context("connect to REALITY target")?;

    let connector = create_tls_connector(&target_host)?;
    let sn = ServerName::try_from(target_host.clone())?;
    let target_tls = connector
        .connect(sn, target_tcp)
        .await
        .context("TLS handshake with target")?;

    let (mut target_read, mut target_write) = tokio::io::split(target_tls);
    let (mut ws_sink, mut ws_stream) = ws.split();

    let mut buf = [0u8; 65536];
    loop {
        tokio::select! {
            msg = ws_stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(b))) => {
                        if target_write.write_all(&b).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = ws_sink.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            n = target_read.read(&mut buf) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        if ws_sink.send(Message::Binary(data)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    Ok(())
}

/// REALITY client connection
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

/// Encode REALITY client HELLO
pub fn encode_client_hello(short_id: &[u8; 8], client_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(1 + 32 + 8);
    msg.push(REALITY_VERSION);
    msg.extend_from_slice(client_pubkey);
    msg.extend_from_slice(short_id);
    msg
}

/// Decode REALITY SERVER HELLO
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

/// SpiderX: Fetch content from target to simulate real browser behavior
/// This makes traffic look more like normal HTTPS browsing
pub async fn spiderx_fetch(target: &str, paths: &[&str]) -> anyhow::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (host, port) = parse_target(target)?;
    let addr = format!("{}:{}", host, port);

    // Create simple TLS connector
    let connector = create_tls_connector(&host)?;
    let tcp = TcpStream::connect(&addr).await.context("connect to target")?;
    let sn = ServerName::try_from(host.clone())?;
    let tls = connector.connect(sn, tcp).await.context("TLS")?;

    let (mut read, mut write) = tokio::io::split(tls);

    // Build HTTP request for a common path
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

    // Read response (limited)
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    let mut collected = 0;
    let max_collect = 32 * 1024; // 32KB max

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
/// This simulates browser behavior and makes traffic pattern less suspicious
pub async fn spawn_spiderx(target: String, interval_secs: u64) {
    let sni = extract_sni(&target);
    // Wikipedia-specific paths break on other fronts; VK uses these entry points.
    let paths: &[&str] = if is_vk_host(&sni) {
        &["/", "/video", "/audio", "/clips"]
    } else {
        &["/"]
    };

    info!("SpiderX: starting background crawler for {}", target);

    loop {
        // Random path selection
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

        // Wait for next interval with some jitter
        let jitter = rand::thread_rng().gen_range(0..30);
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs + jitter)).await;
    }
}

/// Install ring crypto provider (delegates to shared rustls setup).
pub fn install_ring_crypto() {
    crate::tls_util::install_ring_crypto();
}

/// Helper: parse server name from target (e.g., "vk.com:443" -> "vk.com")
pub fn extract_sni(target: &str) -> String {
    target.split(':').next().unwrap_or(target).to_string()
}

/// Helper: is this short ID allowed?
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
    }
}