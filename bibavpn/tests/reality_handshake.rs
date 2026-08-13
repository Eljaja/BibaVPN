//! REALITY X25519 exchange + mandatory client AUTH over a live TLS + WebSocket
//! server (no full mux).

use bibavpn::incoming::{accept_websocket_or_camouflage, CamouflageServeConfig};
use bibavpn::reality::{
    encode_client_auth, encode_client_hello, reality_client_auth_mac,
    reality_client_exchange_verify, server_handshake_reality, RealityReplayCache,
    RealityServerConfig, REALITY_VERSION,
};
use bibavpn::stealth::{build_websocket_request, WsHandshakeParams};
use bibavpn::tls_util::{install_ring_crypto, server_self_signed, TlsClientProfile};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey};

const MAX_TIME_DIFF: u64 = 90;

fn reality_cfg_for(priv_key: [u8; 32], short_ids: Vec<[u8; 8]>) -> RealityServerConfig {
    RealityServerConfig {
        target: "front.example:443".into(),
        server_names: vec!["front.example".into()],
        private_key: priv_key,
        short_ids,
        min_client_ver: None,
        max_client_ver: None,
        max_time_diff: MAX_TIME_DIFF,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// Accept one TLS + WSS connection and run the server side of the REALITY
/// handshake (including AUTH verification against `token`).
async fn spawn_reality_server(
    cfg: RealityServerConfig,
    ws_path: &str,
    token: &str,
    replay_cache: Arc<RealityReplayCache>,
) -> (SocketAddr, JoinHandle<anyhow::Result<[u8; 32]>>) {
    let tls_cfg = server_self_signed("127.0.0.1").expect("self-signed");
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let ws_path = ws_path.to_string();
    let token = token.to_string();
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        let (mut ws, _) = accept_websocket_or_camouflage(
            tls,
            &ws_path,
            false,
            &token,
            CamouflageServeConfig::default(),
            None,
        )
        .await
        .expect("ws")
        .expect("ws some");
        let res = server_handshake_reality(&mut ws, &cfg, &token, &replay_cache).await;
        let _ = ws.close(None).await;
        res
    });
    (addr, handle)
}

async fn spawn_reality_server_loop(
    cfg: RealityServerConfig,
    ws_path: &str,
    token: &str,
    replay_cache: Arc<RealityReplayCache>,
    connections: usize,
) -> (
    SocketAddr,
    JoinHandle<Vec<anyhow::Result<[u8; 32]>>>,
) {
    let tls_cfg = server_self_signed("127.0.0.1").expect("self-signed");
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let ws_path = ws_path.to_string();
    let token = token.to_string();
    let handle = tokio::spawn(async move {
        let mut results = Vec::with_capacity(connections);
        for _ in 0..connections {
            let (tcp, _) = listener.accept().await.expect("accept");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut ws, _) = accept_websocket_or_camouflage(
                tls,
                &ws_path,
                false,
                &token,
                CamouflageServeConfig::default(),
                None,
            )
            .await
            .expect("ws")
            .expect("ws some");
            let res = server_handshake_reality(&mut ws, &cfg, &token, &replay_cache).await;
            let _ = ws.close(None).await;
            results.push(res);
        }
        results
    });
    (addr, handle)
}

async fn client_ws(
    addr: SocketAddr,
    ws_path: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let connector = tokio_rustls::TlsConnector::from(bibavpn::tls_util::client_config_insecure());
    let sn = ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let tls = connector.connect(sn, tcp).await.expect("client tls");

    let req = build_websocket_request(WsHandshakeParams {
        host_for_tcp: "127.0.0.1",
        port: addr.port(),
        path: ws_path,
        sni: "127.0.0.1",
        host_header: None,
        origin: None,
        user_agent: None,
        accept_language: None,
        extra_headers: &[],
        tls_profile: TlsClientProfile::Default,
    });
    let (ws, _) = client_async(req, tls).await.expect("ws client");
    ws
}

#[tokio::test]
async fn reality_handshake_over_wss() {
    install_ring_crypto();

    let (priv_key, pub_key) = RealityServerConfig::generate_keys();
    let short_id = reality_cfg_for(priv_key, vec![]).generate_short_id();
    let token = "test-token";
    let replay_cache = Arc::new(RealityReplayCache::new());

    let (addr, server) = spawn_reality_server(
        reality_cfg_for(priv_key, vec![short_id]),
        "/ws",
        token,
        Arc::clone(&replay_cache),
    )
    .await;
    let mut ws = client_ws(addr, "/ws").await;

    let session_key = reality_client_exchange_verify(&mut ws, &pub_key, &short_id, token)
        .await
        .expect("client REALITY");
    assert_eq!(session_key.len(), 32);

    let server_shared = server
        .await
        .expect("join")
        .expect("server REALITY (correct token must be accepted)");
    assert_eq!(server_shared, session_key);
    let _ = ws.close(None).await;
}

/// A client that completes the X25519 exchange but does not know the session
/// token must be rejected before any application frame: the REALITY path would
/// otherwise be an open proxy.
#[tokio::test]
async fn reality_handshake_rejects_wrong_token() {
    install_ring_crypto();

    let (priv_key, pub_key) = RealityServerConfig::generate_keys();
    let short_id = [0u8; 8];
    let replay_cache = Arc::new(RealityReplayCache::new());

    let (addr, server) = spawn_reality_server(
        reality_cfg_for(priv_key, vec![short_id]),
        "/ws",
        "right-token",
        replay_cache,
    )
    .await;
    let mut ws = client_ws(addr, "/ws").await;

    // The server is authentic, so the client side of the exchange succeeds; the
    // AUTH frame it sends is keyed by the wrong token.
    let _ = reality_client_exchange_verify(&mut ws, &pub_key, &short_id, "wrong-token").await;

    let res = server.await.expect("join");
    assert!(
        res.is_err(),
        "server must reject a client AUTH with a wrong token"
    );
    let _ = ws.close(None).await;
}

/// A client that skips the AUTH frame and jumps straight to an application
/// frame (the pre-fix behaviour: plaintext `MUX_OPEN`) must be rejected.
#[tokio::test]
async fn reality_handshake_rejects_missing_auth() {
    install_ring_crypto();

    let (priv_key, _pub_key) = RealityServerConfig::generate_keys();
    let short_id = [0u8; 8];
    let replay_cache = Arc::new(RealityReplayCache::new());

    let (addr, server) = spawn_reality_server(
        reality_cfg_for(priv_key, vec![short_id]),
        "/ws",
        "test-token",
        replay_cache,
    )
    .await;
    let mut ws = client_ws(addr, "/ws").await;

    let now = unix_now();
    let nonce = [7u8; 16];
    let hello = encode_client_hello(&short_id, &[7u8; 32], now, &nonce);
    ws.send(Message::Binary(hello.into())).await.expect("hello");
    let _server_hello = ws.next().await;
    ws.send(Message::Binary(
        bibavpn::protocol::encode_v3_mux_open().into(),
    ))
    .await
    .expect("mux open");

    let res = server.await.expect("join");
    assert!(
        res.is_err(),
        "server must reject an application frame in place of REALITY AUTH"
    );
    let _ = ws.close(None).await;
}

/// Resending captured HELLO + AUTH bytes on a second connection must fail.
#[tokio::test]
async fn reality_handshake_rejects_replayed_bytes() {
    install_ring_crypto();

    let (priv_key, pub_key) = RealityServerConfig::generate_keys();
    let short_id = [0u8; 8];
    let token = "replay-token";
    let replay_cache = Arc::new(RealityReplayCache::new());
    let cfg = reality_cfg_for(priv_key, vec![short_id]);

    let now = unix_now();
    let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let client_public = PublicKey::from(&client_secret);
    let nonce = [0xab; 16];
    let hello = encode_client_hello(&short_id, client_public.as_bytes(), now, &nonce);

    let server_public = PublicKey::from(pub_key);
    let shared = client_secret.diffie_hellman(&server_public);
    let auth_mac = reality_client_auth_mac(
        shared.as_bytes(),
        token,
        client_public.as_bytes(),
        &pub_key,
        now,
        &nonce,
    );
    let auth = encode_client_auth(&auth_mac);

    let (addr, server) =
        spawn_reality_server_loop(cfg, "/ws", token, Arc::clone(&replay_cache), 2).await;

    let mut ws1 = client_ws(addr, "/ws").await;
    ws1.send(Message::Binary(hello.clone().into()))
        .await
        .expect("hello");
    let _ = ws1.next().await;
    ws1.send(Message::Binary(auth.clone().into()))
        .await
        .expect("auth");
    let _ = ws1.close(None).await;

    let mut ws2 = client_ws(addr, "/ws").await;
    ws2.send(Message::Binary(hello.into())).await.expect("replay hello");
    let _ = ws2.next().await;
    ws2.send(Message::Binary(auth.into()))
        .await
        .expect("replay auth");
    let _ = ws2.close(None).await;

    let results = server.await.expect("join");
    assert!(results[0].is_ok(), "first handshake must succeed");
    assert!(
        results[1].is_err(),
        "replayed HELLO + AUTH must be rejected: {:?}",
        results[1]
    );
    let err = results[1].as_ref().unwrap_err().to_string();
    assert!(
        err.contains("replay") || err.contains("nonce"),
        "expected replay error, got: {err}"
    );
}

#[tokio::test]
async fn reality_handshake_rejects_stale_timestamp() {
    install_ring_crypto();

    let (priv_key, _pub_key) = RealityServerConfig::generate_keys();
    let short_id = [0u8; 8];
    let replay_cache = Arc::new(RealityReplayCache::new());

    let (addr, server) = spawn_reality_server(
        reality_cfg_for(priv_key, vec![short_id]),
        "/ws",
        "test-token",
        replay_cache,
    )
    .await;
    let mut ws = client_ws(addr, "/ws").await;

    let stale = unix_now().saturating_sub(MAX_TIME_DIFF + 1);
    let hello = encode_client_hello(&short_id, &[1u8; 32], stale, &[2u8; 16]);
    ws.send(Message::Binary(hello.into())).await.expect("hello");

    let res = server.await.expect("join");
    assert!(res.is_err(), "stale HELLO must be rejected");
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("timestamp") || err.contains("window") || err.contains("skew"),
        "expected timestamp/window error, got: {err}"
    );
    let _ = ws.close(None).await;
}

#[tokio::test]
async fn reality_handshake_accepts_timestamp_within_window() {
    install_ring_crypto();

    let (priv_key, pub_key) = RealityServerConfig::generate_keys();
    let short_id = [0u8; 8];
    let token = "skew-token";
    let replay_cache = Arc::new(RealityReplayCache::new());

    let (addr, server) = spawn_reality_server(
        reality_cfg_for(priv_key, vec![short_id]),
        "/ws",
        token,
        Arc::clone(&replay_cache),
    )
    .await;
    let mut ws = client_ws(addr, "/ws").await;

    let skewed = unix_now().saturating_sub(MAX_TIME_DIFF);
    let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let client_public = PublicKey::from(&client_secret);
    let nonce = [3u8; 16];
    let hello = encode_client_hello(&short_id, client_public.as_bytes(), skewed, &nonce);
    ws.send(Message::Binary(hello.into())).await.expect("hello");

    let _server_msg = ws.next().await.expect("server hello").expect("binary");
    let server_public = PublicKey::from(pub_key);
    let shared = client_secret.diffie_hellman(&server_public);
    let auth_mac = reality_client_auth_mac(
        shared.as_bytes(),
        token,
        client_public.as_bytes(),
        &pub_key,
        skewed,
        &nonce,
    );
    ws.send(Message::Binary(encode_client_auth(&auth_mac).into()))
        .await
        .expect("auth");

    let res = server.await.expect("join");
    assert!(
        res.is_ok(),
        "HELLO within max_time_diff must succeed: {:?}",
        res
    );
    let _ = ws.close(None).await;
}

/// A MITM that knows the pinned public key but not the private key cannot
/// produce a valid confirmation MAC, so the client must reject it.
#[tokio::test]
async fn reality_handshake_rejects_forged_server() {
    install_ring_crypto();

    // The pinned key the client trusts. The malicious server knows `pub_key`
    // (it is public) but not the matching private key.
    let (_priv_key, pub_key) = RealityServerConfig::generate_keys();
    let short_id = [0u8; 8];

    let tls_cfg = server_self_signed("127.0.0.1").expect("self-signed");
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let ws_path = "/ws".to_string();
    let token = "test-token".to_string();

    let ws_path_s = ws_path.clone();
    let token_s = token.clone();
    let echoed_pub = pub_key;
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        let (mut ws, _) = accept_websocket_or_camouflage(
            tls,
            &ws_path_s,
            false,
            &token_s,
            CamouflageServeConfig::default(),
            None,
        )
        .await
        .expect("ws")
        .expect("ws some");
        // Consume the client HELLO, then forge a SERVER_HELLO: echo the pinned
        // pubkey but attach a bogus MAC (the MITM cannot compute the real one).
        let _client_hello = ws.next().await;
        let mut forged = vec![REALITY_VERSION];
        forged.extend_from_slice(&echoed_pub);
        forged.extend_from_slice(&[0u8; 32]);
        let _ = ws.send(Message::Binary(forged.into())).await;
        let _ = ws.close(None).await;
    });

    let mut ws = client_ws(addr, &ws_path).await;

    let res = reality_client_exchange_verify(&mut ws, &pub_key, &short_id, &token).await;
    assert!(res.is_err(), "client must reject a forged confirmation MAC");
    let _ = ws.close(None).await;
}
