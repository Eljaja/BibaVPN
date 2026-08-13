//! REALITY-style front authentication for BibaVPN (WSS path).
//!
//! BibaVPN runs REALITY **after** the outer TLS + WebSocket upgrade (unlike Xray, which hooks
//! TLS ClientHello). Flow:
//!
//! 1. Client opens TLS to the VPS with **SNI = front domain** (`reality_target`, e.g. `vk.com`).
//! 2. Standard WSS upgrade on `--ws-path`.
//! 3. Binary REALITY frames: X25519 ephemeral + short ID → server long-term pubkey (pinned in invite).
//! 4. Mandatory client AUTH frame: MAC over the handshake transcript keyed by the
//!    X25519 shared secret **and** the session token. Without it the REALITY path
//!    would be an open proxy (the X25519 exchange only authenticates the server).
//! 5. Plaintext mux (`MUX_OPEN`) or v3 PSK tunnel follows.
//!
//! SpiderX background fetches keep server-side camouflage warm against the REALITY target.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::{Rng, RngCore};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use subtle::ConstantTimeEq;
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
/// Wire version. v2 adds a server confirmation MAC to SERVER_HELLO. v3 extends
/// client HELLO with a unix timestamp and nonce, binds both into the AUTH MAC,
/// and rejects replays within `max_time_diff`. Incompatible with v2 on both ends.
pub const REALITY_VERSION: u8 = 3;

/// Fixed wire size of client HELLO v3:
/// `[version][ephemeral:32][short_id:8][unix_secs:8 BE][nonce:16]`.
pub const REALITY_CLIENT_HELLO_LEN: usize = 1 + 32 + 8 + 8 + 16;

/// BLAKE3 derive-key context for the REALITY handshake confirmation MAC.
const REALITY_CONFIRM_CONTEXT: &str = "bibavpn reality server-confirm v2";

/// BLAKE3 derive-key context for the mandatory client AUTH MAC.
const REALITY_CLIENT_AUTH_CONTEXT: &str = "bibavpn reality client-auth v2";

/// Max seen nonces retained in the process-wide REALITY replay cache.
const REALITY_REPLAY_CACHE_CAP: usize = 65536;

/// Frame tag of the client AUTH frame (byte 1, after the version byte).
pub const REALITY_CLIENT_AUTH_TAG: u8 = 0xa1;

/// Wire size of the client AUTH frame: `[version][tag][mac:32]`.
pub const REALITY_CLIENT_AUTH_LEN: usize = 1 + 1 + 32;

/// Server confirmation MAC over the handshake transcript, keyed by the X25519
/// shared secret. Only a peer holding the REALITY private key (server) or the
/// client's ephemeral private key can derive `shared`, so a MITM that merely
/// knows the (public) server key cannot forge it. Returned as a `blake3::Hash`
/// whose `==` is constant-time.
pub fn reality_confirm_mac(
    shared: &[u8; 32],
    client_ephemeral_pub: &[u8; 32],
    server_static_pub: &[u8; 32],
) -> blake3::Hash {
    let mac_key = blake3::derive_key(REALITY_CONFIRM_CONTEXT, shared);
    let mut h = blake3::Hasher::new_keyed(&mac_key);
    h.update(client_ephemeral_pub);
    h.update(server_static_pub);
    h.finalize()
}

/// Client AUTH MAC over the handshake transcript, keyed by the X25519 shared
/// secret **and** the session token. The token never touches the wire. The MAC
/// binds both public keys plus the HELLO timestamp and nonce so a captured
/// handshake cannot be replayed within `max_time_diff`.
///
/// The X25519 exchange alone only authenticates the *server*
/// (see `reality_confirm_mac`); this MAC is what authenticates the *client*.
pub fn reality_client_auth_mac(
    shared: &[u8; 32],
    token: &str,
    client_ephemeral_pub: &[u8; 32],
    server_static_pub: &[u8; 32],
    unix_secs: u64,
    nonce: &[u8; 16],
) -> [u8; 32] {
    // Key material = shared secret || token. `shared` is fixed-width, so the
    // concatenation is unambiguous. Knowing only one of the two is not enough.
    let mut ikm = Vec::with_capacity(32 + token.len());
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(token.as_bytes());
    let mac_key = blake3::derive_key(REALITY_CLIENT_AUTH_CONTEXT, &ikm);
    let mut h = blake3::Hasher::new_keyed(&mac_key);
    h.update(client_ephemeral_pub);
    h.update(server_static_pub);
    h.update(&unix_secs.to_be_bytes());
    h.update(nonce);
    *h.finalize().as_bytes()
}

/// Parsed REALITY client HELLO v3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityClientHello {
    pub client_pubkey: [u8; 32],
    pub short_id: [u8; 8],
    pub unix_secs: u64,
    pub nonce: [u8; 16],
}

/// Returns true when `|now - unix_secs| <= max_time_diff`.
pub fn reality_timestamp_in_window(
    now: u64,
    unix_secs: u64,
    max_time_diff: u64,
) -> anyhow::Result<()> {
    let delta = now.abs_diff(unix_secs);
    if delta > max_time_diff {
        bail!(
            "REALITY: HELLO timestamp outside allowed window (skew {delta}s > max_time_diff {max_time_diff}s)"
        );
    }
    Ok(())
}

/// Process-wide sliding-window cache of authenticated HELLO nonces.
#[derive(Debug, Default)]
pub struct RealityReplayCache {
    inner: Mutex<RealityReplayCacheInner>,
}

#[derive(Debug, Default)]
struct RealityReplayCacheInner {
    entries: Vec<([u8; 16], u64)>,
}

impl RealityReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reject if `nonce` was already authenticated within the sliding window;
    /// otherwise insert. Expired entries are dropped first.
    pub fn check_and_insert(
        &self,
        nonce: &[u8; 16],
        hello_unix_secs: u64,
        now: u64,
        max_time_diff: u64,
    ) -> anyhow::Result<()> {
        let mut guard = self.inner.lock().expect("REALITY replay cache mutex");
        guard
            .entries
            .retain(|(_, ts)| ts.saturating_add(max_time_diff) >= now);

        if guard.entries.iter().any(|(seen, _)| seen == nonce) {
            bail!("REALITY: replay detected (HELLO nonce already seen)");
        }

        if guard.entries.len() >= REALITY_REPLAY_CACHE_CAP {
            if let Some(idx) = guard
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(i, _)| i)
            {
                guard.entries.remove(idx);
            }
        }

        guard.entries.push((*nonce, hello_unix_secs));
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().expect("REALITY replay cache mutex").entries.len()
    }
}

/// Wire bytes for the client AUTH frame: `[version][tag][mac:32]`.
pub fn encode_client_auth(mac: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(REALITY_CLIENT_AUTH_LEN);
    msg.push(REALITY_VERSION);
    msg.push(REALITY_CLIENT_AUTH_TAG);
    msg.extend_from_slice(mac);
    msg
}

/// Decode the client AUTH frame `[version][tag][mac:32]` into the MAC.
pub fn decode_client_auth(data: &[u8]) -> anyhow::Result<[u8; 32]> {
    if data.len() < REALITY_CLIENT_AUTH_LEN {
        bail!("short REALITY client AUTH");
    }
    if data[0] != REALITY_VERSION {
        bail!("unsupported REALITY version in client AUTH: {}", data[0]);
    }
    if data[1] != REALITY_CLIENT_AUTH_TAG {
        bail!(
            "expected REALITY client AUTH frame, got tag 0x{:02x}",
            data[1]
        );
    }
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&data[2..34]);
    Ok(mac)
}

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

/// Wire bytes for REALITY SERVER_HELLO:
/// `[version][server_x25519_pubkey:32][confirm_mac:32]`.
///
/// The MAC binds the X25519 shared secret to the transcript, proving the server
/// holds `private_key`. Errors if the client ephemeral public key is invalid.
pub fn server_hello_with_confirm(
    private_key: &[u8; 32],
    client_ephemeral_pub: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    server_hello_with_confirm_and_shared(private_key, client_ephemeral_pub).map(|(wire, _)| wire)
}

/// Same as `server_hello_with_confirm`, but also returns the X25519 shared
/// secret so the caller can verify the client AUTH MAC that follows.
pub fn server_hello_with_confirm_and_shared(
    private_key: &[u8; 32],
    client_ephemeral_pub: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let server_secret = StaticSecret::from(*private_key);
    let client_public = PublicKey::try_from(*client_ephemeral_pub)
        .map_err(|_| anyhow::anyhow!("invalid REALITY client public key"))?;
    let shared = server_secret.diffie_hellman(&client_public);
    let server_pub = RealityServerConfig::public_key_from_private(private_key);
    let mac = reality_confirm_mac(shared.as_bytes(), client_ephemeral_pub, &server_pub);

    let mut response = Vec::with_capacity(1 + 32 + 32);
    response.push(REALITY_VERSION);
    response.extend_from_slice(&server_pub);
    response.extend_from_slice(mac.as_bytes());
    Ok((response, *shared.as_bytes()))
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

/// Next binary frame during a REALITY handshake, answering Ping and skipping
/// Pong within `MAX_HANDSHAKE_CONTROL_FRAMES`. `what` names the expected frame
/// in error messages; `control_frames` is the budget shared by all handshake
/// phases so a pre-auth peer cannot reset it by advancing a phase.
async fn next_handshake_binary<S>(
    ws: &mut WebSocketStream<S>,
    control_frames: &mut u32,
    what: &str,
) -> anyhow::Result<Bytes>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Ok(b),
            Some(Ok(Message::Ping(p))) => {
                *control_frames += 1;
                if *control_frames > MAX_HANDSHAKE_CONTROL_FRAMES {
                    bail!("too many control frames during REALITY handshake");
                }
                ws.send(Message::Pong(p)).await.context("REALITY pong")?;
            }
            Some(Ok(Message::Pong(_))) => {
                *control_frames += 1;
                if *control_frames > MAX_HANDSHAKE_CONTROL_FRAMES {
                    bail!("too many control frames during REALITY handshake");
                }
            }
            Some(Ok(_)) => bail!("expected binary {what}"),
            Some(Err(e)) => Err(e).context("websocket recv")?,
            None => bail!("ws closed before {what}"),
        }
    }
}

/// Server-side REALITY handshake: validate client HELLO, reply with the pinned
/// pubkey from `cfg.private_key`, then **require** a client AUTH frame proving
/// knowledge of `token`. Returns the X25519 shared secret on success.
///
/// The AUTH step is mandatory: REALITY only authenticates the server, so without
/// it any peer that completes the WebSocket upgrade would get a working tunnel
/// (the short-id allowlist is permissive by default, see `is_short_id_allowed`).
pub async fn server_handshake_reality<S>(
    ws: &mut WebSocketStream<S>,
    cfg: &RealityServerConfig,
    token: &str,
    replay_cache: &RealityReplayCache,
) -> anyhow::Result<[u8; 32]>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before REALITY HELLO")?
        .as_secs();

    let mut control_frames: u32 = 0;
    let msg = next_handshake_binary(ws, &mut control_frames, "REALITY HELLO").await?;

    let hello = decode_client_hello(msg.as_ref())?;
    validate_short_id(&hello.short_id, cfg)?;
    reality_timestamp_in_window(now, hello.unix_secs, cfg.max_time_diff)?;

    // Reply with the pinned pubkey plus a MAC proving we hold the private
    // key (binds the X25519 shared secret to the transcript).
    let (response, shared) =
        server_hello_with_confirm_and_shared(&cfg.private_key, &hello.client_pubkey)?;
    ws.send(Message::Binary(Bytes::from(response)))
        .await
        .context("send REALITY SERVER_HELLO")?;

    let server_pub = RealityServerConfig::public_key_from_private(&cfg.private_key);
    let auth = next_handshake_binary(ws, &mut control_frames, "REALITY client AUTH").await?;
    let got = decode_client_auth(auth.as_ref())?;
    let expected = reality_client_auth_mac(
        &shared,
        token,
        &hello.client_pubkey,
        &server_pub,
        hello.unix_secs,
        &hello.nonce,
    );
    if !bool::from(got[..].ct_eq(&expected[..])) {
        bail!("REALITY: client AUTH MAC invalid (unknown token)");
    }

    replay_cache.check_and_insert(&hello.nonce, hello.unix_secs, now, cfg.max_time_diff)?;
    Ok(shared)
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

/// Encode REALITY client HELLO v3:
/// `[version][ephemeral_pubkey:32][short_id:8][unix_secs:8 BE][nonce:16]`.
pub fn encode_client_hello(
    short_id: &[u8; 8],
    client_pubkey: &[u8; 32],
    unix_secs: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(REALITY_CLIENT_HELLO_LEN);
    msg.push(REALITY_VERSION);
    msg.extend_from_slice(client_pubkey);
    msg.extend_from_slice(short_id);
    msg.extend_from_slice(&unix_secs.to_be_bytes());
    msg.extend_from_slice(nonce);
    msg
}

/// Decode REALITY client HELLO v3.
pub fn decode_client_hello(data: &[u8]) -> anyhow::Result<RealityClientHello> {
    if data.len() < REALITY_CLIENT_HELLO_LEN {
        bail!("short REALITY HELLO");
    }
    if data[0] != REALITY_VERSION {
        bail!("unsupported REALITY version: {}", data[0]);
    }
    let mut client_pubkey = [0u8; 32];
    client_pubkey.copy_from_slice(&data[1..33]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&data[33..41]);
    let unix_secs = u64::from_be_bytes(data[41..49].try_into().unwrap());
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&data[49..65]);
    Ok(RealityClientHello {
        client_pubkey,
        short_id,
        unix_secs,
        nonce,
    })
}

/// Client REALITY HELLO + verify server pubkey (X25519 ephemeral), then send the
/// mandatory AUTH frame proving knowledge of `token`. Returns the session key.
pub async fn reality_client_exchange_verify<S>(
    ws: &mut WebSocketStream<S>,
    expected_server_pubkey: &[u8; 32],
    short_id: &[u8; 8],
    token: &str,
) -> anyhow::Result<[u8; 32]>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before REALITY HELLO")?
        .as_secs();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let client_hello = encode_client_hello(
        short_id,
        ephemeral_public.as_bytes(),
        unix_secs,
        &nonce,
    );
    ws.send(Message::Binary(Bytes::from(client_hello)))
        .await
        .context("send REALITY client hello")?;

    let mut control_frames: u32 = 0;
    let msg = next_handshake_binary(ws, &mut control_frames, "server hello").await?;

    let (server_pubkey, server_mac) = decode_server_hello(&msg)?;
    if server_pubkey != *expected_server_pubkey {
        bail!("REALITY: server public key mismatch (possible MITM)");
    }
    let server_public = PublicKey::from(server_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&server_public);

    // Verify the server proved possession of the private key. A MITM that
    // only knows the pinned public key cannot derive the shared secret and
    // thus cannot forge this MAC. `blake3::Hash` compares in constant time.
    let expected_mac = reality_confirm_mac(
        shared_secret.as_bytes(),
        ephemeral_public.as_bytes(),
        &server_pubkey,
    );
    if expected_mac != blake3::Hash::from(server_mac) {
        bail!("REALITY: server confirmation MAC invalid (server lacks the private key; possible MITM)");
    }

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(shared_secret.as_bytes());

    // Prove we know the session token (bound to this handshake transcript).
    // The server drops the connection before any application frame otherwise.
    let auth_mac = reality_client_auth_mac(
        &session_key,
        token,
        ephemeral_public.as_bytes(),
        &server_pubkey,
        unix_secs,
        &nonce,
    );
    ws.send(Message::Binary(Bytes::from(encode_client_auth(&auth_mac))))
        .await
        .context("send REALITY client AUTH")?;

    Ok(session_key)
}

/// Decode REALITY SERVER_HELLO `[version][pubkey:32][confirm_mac:32]`.
/// Returns `(server_pubkey, confirm_mac)`.
pub fn decode_server_hello(data: &[u8]) -> anyhow::Result<([u8; 32], [u8; 32])> {
    if data.len() < 1 + 32 + 32 {
        bail!("short SERVER_HELLO");
    }
    if data[0] != REALITY_VERSION {
        bail!("version mismatch");
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[1..33]);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&data[33..65]);
    Ok((pubkey, mac))
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
    fn reality_server_hello_confirm_roundtrip() {
        let (priv_key, expected_pub) = RealityServerConfig::generate_keys();

        let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let client_public = PublicKey::from(&client_secret);

        let hello = server_hello_with_confirm(&priv_key, client_public.as_bytes()).unwrap();
        assert_eq!(hello.len(), 1 + 32 + 32);
        let (decoded_pub, server_mac) = decode_server_hello(&hello).unwrap();
        assert_eq!(decoded_pub, expected_pub);

        // Client side: recompute the shared secret against the pinned key and
        // confirm the MAC matches what the server sent.
        let server_public = PublicKey::from(expected_pub);
        let shared = client_secret.diffie_hellman(&server_public);
        let expected_mac =
            reality_confirm_mac(shared.as_bytes(), client_public.as_bytes(), &expected_pub);
        assert_eq!(expected_mac, blake3::Hash::from(server_mac));
    }

    #[test]
    fn reality_confirm_mac_rejects_wrong_server_key() {
        // A MITM knows the real (public) server key but not its private key.
        // It echoes the pinned pubkey but can only MAC with a shared secret
        // derived from its own private key, so the client's recomputed MAC
        // (against the real pinned key) will not match.
        let (_real_priv, real_pub) = RealityServerConfig::generate_keys();
        let (mitm_priv, _mitm_pub) = RealityServerConfig::generate_keys();

        let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let client_public = PublicKey::from(&client_secret);

        let mitm_secret = StaticSecret::from(mitm_priv);
        let mitm_shared = mitm_secret.diffie_hellman(&client_public);
        let forged_mac =
            reality_confirm_mac(mitm_shared.as_bytes(), client_public.as_bytes(), &real_pub);

        let real_server_public = PublicKey::from(real_pub);
        let client_shared = client_secret.diffie_hellman(&real_server_public);
        let expected_mac =
            reality_confirm_mac(client_shared.as_bytes(), client_public.as_bytes(), &real_pub);

        assert_ne!(expected_mac, forged_mac);
    }

    /// The client AUTH MAC is reproducible by both sides from the shared secret
    /// plus the token, and the token itself never appears on the wire.
    #[test]
    fn client_auth_mac_matches_for_same_token() {
        let (priv_key, server_pub) = RealityServerConfig::generate_keys();
        let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let client_public = PublicKey::from(&client_secret);
        let unix_secs = 1_700_000_000;
        let nonce = [9u8; 16];

        let (_hello, server_shared) =
            server_hello_with_confirm_and_shared(&priv_key, client_public.as_bytes()).unwrap();
        let client_shared = client_secret.diffie_hellman(&PublicKey::from(server_pub));
        assert_eq!(&server_shared, client_shared.as_bytes());

        let sent = reality_client_auth_mac(
            client_shared.as_bytes(),
            "s3cret-token",
            client_public.as_bytes(),
            &server_pub,
            unix_secs,
            &nonce,
        );
        let expected = reality_client_auth_mac(
            &server_shared,
            "s3cret-token",
            client_public.as_bytes(),
            &server_pub,
            unix_secs,
            &nonce,
        );
        assert_eq!(sent, expected);

        let wire = encode_client_auth(&sent);
        let token_bytes = b"s3cret-token";
        assert!(!wire
            .windows(token_bytes.len())
            .any(|w| w == &token_bytes[..]));
        assert_eq!(decode_client_auth(&wire).unwrap(), expected);
    }

    #[test]
    fn client_auth_mac_rejects_wrong_token() {
        let (priv_key, server_pub) = RealityServerConfig::generate_keys();
        let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let client_public = PublicKey::from(&client_secret);
        let unix_secs = 1_700_000_000;
        let nonce = [4u8; 16];
        let (_hello, shared) =
            server_hello_with_confirm_and_shared(&priv_key, client_public.as_bytes()).unwrap();

        let forged = reality_client_auth_mac(
            &shared,
            "guessed",
            client_public.as_bytes(),
            &server_pub,
            unix_secs,
            &nonce,
        );
        let expected = reality_client_auth_mac(
            &shared,
            "real-token",
            client_public.as_bytes(),
            &server_pub,
            unix_secs,
            &nonce,
        );
        assert_ne!(forged, expected);
    }

    #[test]
    fn client_auth_mac_differs_when_timestamp_or_nonce_changes() {
        let (priv_key, server_pub) = RealityServerConfig::generate_keys();
        let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let client_public = PublicKey::from(&client_secret);
        let (_hello, shared) =
            server_hello_with_confirm_and_shared(&priv_key, client_public.as_bytes()).unwrap();
        let base = reality_client_auth_mac(
            &shared,
            "token",
            client_public.as_bytes(),
            &server_pub,
            100,
            &[1u8; 16],
        );
        assert_ne!(
            base,
            reality_client_auth_mac(
                &shared,
                "token",
                client_public.as_bytes(),
                &server_pub,
                101,
                &[1u8; 16],
            )
        );
        assert_ne!(
            base,
            reality_client_auth_mac(
                &shared,
                "token",
                client_public.as_bytes(),
                &server_pub,
                100,
                &[2u8; 16],
            )
        );
    }

    /// Replaying a captured AUTH frame into another session fails: the MAC is
    /// keyed by that session's X25519 shared secret.
    #[test]
    fn client_auth_mac_rejects_other_session_key() {
        let (priv_key, server_pub) = RealityServerConfig::generate_keys();
        let token = "real-token";
        let unix_secs = 1_700_000_000;
        let nonce = [6u8; 16];

        let first_client = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let first_pub = PublicKey::from(&first_client);
        let (_h1, first_shared) =
            server_hello_with_confirm_and_shared(&priv_key, first_pub.as_bytes()).unwrap();
        let captured = reality_client_auth_mac(
            &first_shared,
            token,
            first_pub.as_bytes(),
            &server_pub,
            unix_secs,
            &nonce,
        );

        let second_client = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let second_pub = PublicKey::from(&second_client);
        let (_h2, second_shared) =
            server_hello_with_confirm_and_shared(&priv_key, second_pub.as_bytes()).unwrap();
        let expected = reality_client_auth_mac(
            &second_shared,
            token,
            second_pub.as_bytes(),
            &server_pub,
            unix_secs,
            &nonce,
        );

        assert_ne!(captured, expected);
    }

    #[test]
    fn client_auth_wire_layout() {
        let mac = [5u8; 32];
        let wire = encode_client_auth(&mac);
        assert_eq!(wire.len(), REALITY_CLIENT_AUTH_LEN);
        assert_eq!(wire[0], REALITY_VERSION);
        assert_eq!(wire[1], REALITY_CLIENT_AUTH_TAG);
        assert_eq!(decode_client_auth(&wire).unwrap(), mac);

        assert!(decode_client_auth(&wire[..33]).is_err());
        let mut bad_tag = wire.clone();
        bad_tag[1] = 0x00;
        assert!(decode_client_auth(&bad_tag).is_err());
        let mut bad_ver = wire.clone();
        bad_ver[0] = REALITY_VERSION.wrapping_add(1);
        assert!(decode_client_auth(&bad_ver).is_err());
    }

    #[test]
    fn client_hello_wire_layout() {
        let sid = [7u8; 8];
        let pk = [3u8; 32];
        let unix_secs = 1_700_000_123u64;
        let nonce = [8u8; 16];
        let wire = encode_client_hello(&sid, &pk, unix_secs, &nonce);
        assert_eq!(wire.len(), REALITY_CLIENT_HELLO_LEN);
        assert_eq!(wire[0], REALITY_VERSION);
        assert_eq!(&wire[1..33], &pk);
        assert_eq!(&wire[33..41], &sid);
        assert_eq!(u64::from_be_bytes(wire[41..49].try_into().unwrap()), unix_secs);
        assert_eq!(&wire[49..65], &nonce);

        let decoded = decode_client_hello(&wire).unwrap();
        assert_eq!(decoded.client_pubkey, pk);
        assert_eq!(decoded.short_id, sid);
        assert_eq!(decoded.unix_secs, unix_secs);
        assert_eq!(decoded.nonce, nonce);

        assert!(decode_client_hello(&wire[..64]).is_err());
        let mut bad_ver = wire.clone();
        bad_ver[0] = REALITY_VERSION.wrapping_sub(1);
        assert!(decode_client_hello(&bad_ver).is_err());
    }

    #[test]
    fn reality_timestamp_in_window_accepts_and_rejects() {
        let max = 90u64;
        let now = 1_000_000u64;
        reality_timestamp_in_window(now, now, max).unwrap();
        reality_timestamp_in_window(now, now - max, max).unwrap();
        reality_timestamp_in_window(now, now + max, max).unwrap();
        assert!(reality_timestamp_in_window(now, now - max - 1, max).is_err());
        assert!(reality_timestamp_in_window(now, now + max + 1, max).is_err());
    }

    #[test]
    fn replay_cache_rejects_duplicate_and_expires() {
        let cache = RealityReplayCache::new();
        let max = 90u64;
        let hello_ts = 1_000u64;
        let nonce = [1u8; 16];

        cache
            .check_and_insert(&nonce, hello_ts, hello_ts, max)
            .unwrap();
        assert!(cache
            .check_and_insert(&nonce, hello_ts, hello_ts, max)
            .is_err());

        let after_window = hello_ts + max + 1;
        cache
            .check_and_insert(&nonce, hello_ts, after_window, max)
            .unwrap();
    }

    #[test]
    fn replay_cache_cap_does_not_grow_unbounded() {
        let cache = RealityReplayCache::new();
        let max = 3600u64;
        let now = 10_000u64;
        for i in 0..=REALITY_REPLAY_CACHE_CAP {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            cache
                .check_and_insert(&nonce, now, now, max)
                .unwrap();
        }
        assert!(cache.len() <= REALITY_REPLAY_CACHE_CAP);
    }
}
