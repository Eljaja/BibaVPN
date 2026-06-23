//! REALITY X25519 exchange over a live TLS + WebSocket server (no full mux).

use bibavpn::incoming::{accept_websocket_or_camouflage, CamouflageServeConfig};
use bibavpn::reality::{
    reality_client_exchange_verify, server_handshake_reality, RealityServerConfig, REALITY_VERSION,
};
use bibavpn::stealth::{build_websocket_request, WsHandshakeParams};
use bibavpn::tls_util::{install_ring_crypto, server_self_signed, TlsClientProfile};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::client_async;

#[tokio::test]
async fn reality_handshake_over_wss() {
    install_ring_crypto();

    let (priv_key, pub_key) = RealityServerConfig::generate_keys();
    let short_id = {
        let tmp = RealityServerConfig {
            target: "front.example:443".into(),
            server_names: vec!["front.example".into()],
            private_key: priv_key,
            short_ids: vec![],
            min_client_ver: None,
            max_client_ver: None,
            max_time_diff: 0,
        };
        tmp.generate_short_id()
    };

    let reality_cfg = RealityServerConfig {
        target: "front.example:443".into(),
        server_names: vec!["front.example".into()],
        private_key: priv_key,
        short_ids: vec![short_id],
        min_client_ver: None,
        max_client_ver: None,
        max_time_diff: 0,
    };

    let tls_cfg = server_self_signed("127.0.0.1").expect("self-signed");
    let acceptor = TlsAcceptor::from(tls_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let ws_path = "/ws".to_string();
    let token = "test-token".to_string();

    let server_cfg = reality_cfg.clone();
    let ws_path_s = ws_path.clone();
    let token_s = token.clone();
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
        server_handshake_reality(&mut ws, &server_cfg)
            .await
            .expect("server REALITY");
        let _ = ws.close(None).await;
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let connector = tokio_rustls::TlsConnector::from(
        bibavpn::tls_util::client_config_insecure(),
    );
    let sn = ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let tls = connector.connect(sn, tcp).await.expect("client tls");

    let req = build_websocket_request(WsHandshakeParams {
        host_for_tcp: "127.0.0.1",
        port: addr.port(),
        path: &ws_path,
        sni: "127.0.0.1",
        host_header: None,
        origin: None,
        user_agent: None,
        accept_language: None,
        extra_headers: &[],
        tls_profile: TlsClientProfile::Default,
    });
    let (mut ws, _) = client_async(req, tls).await.expect("ws client");

    let session_key = reality_client_exchange_verify(&mut ws, &pub_key, &short_id)
        .await
        .expect("client REALITY");
    assert_eq!(session_key.len(), 32);
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

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let connector =
        tokio_rustls::TlsConnector::from(bibavpn::tls_util::client_config_insecure());
    let sn = ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let tls = connector.connect(sn, tcp).await.expect("client tls");

    let req = build_websocket_request(WsHandshakeParams {
        host_for_tcp: "127.0.0.1",
        port: addr.port(),
        path: &ws_path,
        sni: "127.0.0.1",
        host_header: None,
        origin: None,
        user_agent: None,
        accept_language: None,
        extra_headers: &[],
        tls_profile: TlsClientProfile::Default,
    });
    let (mut ws, _) = client_async(req, tls).await.expect("ws client");

    let res = reality_client_exchange_verify(&mut ws, &pub_key, &short_id).await;
    assert!(res.is_err(), "client must reject a forged confirmation MAC");
    let _ = ws.close(None).await;
}
