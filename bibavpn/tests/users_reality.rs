use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use bibavpn::reality::{reality_client_exchange_verify, RealityServerConfig};
use bibavpn::tls_util::install_ring_crypto;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_tungstenite::{client_async, tungstenite::Message};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn reality_registry_enforces_live_users_and_session_limits() {
    install_ring_crypto();
    let dir = std::env::temp_dir().join(format!("biba-reality-users-{}", rand::random::<u64>()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("users.json");
    let write = |enabled| {
        std::fs::write(&path, format!(r#"{{"users":[{{"label":"alice","token":"alice-secret","enabled":{enabled},"max_concurrent":1}}]}}"#)).unwrap()
    };
    write(true);
    let (private, public) = RealityServerConfig::generate_keys();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_bibavpn-server"))
            .args([
                "--listen",
                &addr.to_string(),
                "--self-signed-san",
                "127.0.0.1",
                "--users-file",
            ])
            .arg(&path)
            .args([
                "--psk",
                "example-psk",
                "--no-auth-rate-limit",
                "--reality-target",
                "127.0.0.1:443",
                "--reality-private-key",
                &base64::engine::general_purpose::STANDARD.encode(private),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let connect = |token: &'static str| async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(bibavpn::tls_util::client_config_insecure())
            .connect(ServerName::try_from("127.0.0.1".to_string()).unwrap(), tcp)
            .await
            .unwrap();
        let (mut ws, _) = client_async(format!("wss://127.0.0.1:{}/ws", addr.port()), tls)
            .await
            .unwrap();
        reality_client_exchange_verify(&mut ws, &public, &[0; 8], token)
            .await
            .unwrap();
        ws.send(Message::Binary(
            bibavpn::protocol::encode_v3_mux_open().into(),
        ))
        .await
        .unwrap();
        let _ = ws.send(Message::Ping(Vec::new().into())).await;
        ws
    };
    let mut first = connect("alice-secret").await;
    let pong = tokio::time::timeout(Duration::from_secs(3), first.next())
        .await
        .unwrap();
    assert!(matches!(pong, Some(Ok(Message::Pong(_)))));
    let mut over_limit = connect("alice-secret").await;
    let closed = tokio::time::timeout(Duration::from_secs(3), over_limit.next())
        .await
        .unwrap();
    assert!(!matches!(closed, Some(Ok(Message::Pong(_)))));
    write(false);
    let mut disabled = connect("alice-secret").await;
    let closed = tokio::time::timeout(Duration::from_secs(3), disabled.next())
        .await
        .unwrap();
    assert!(!matches!(closed, Some(Ok(Message::Pong(_)))));
    first.send(Message::Ping(Vec::new().into())).await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), first.next())
            .await
            .unwrap(),
        Some(Ok(Message::Pong(_)))
    ));
    drop(first);
    std::fs::remove_dir_all(dir).unwrap();
}
