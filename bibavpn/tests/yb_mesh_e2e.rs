//! Real Biba SOCKS tunnel through two local mesh nodes; the configured public IP is unreachable.
use std::{net::TcpListener as StdListener, process::{Child, Command, Stdio}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, time::{sleep, timeout}};

struct Process(Child);
impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
fn unused_port() -> u16 { StdListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }

async fn run_mesh_tunnel(no_mux: bool) {
    assert!(!bibavpn::domain_route::should_bypass("127.1"));
    let peer_port = unused_port();
    let server_port = unused_port();
    let socks_port = unused_port();
    let node = bibavpn::yb_mesh::MeshNode::start(vec![], vec![format!("tcp://127.0.0.1:{peer_port}")]).await.unwrap();
    let listener = node.netstack.listen_tcp(18443).unwrap();
    let forward = tokio::spawn(async move {
        loop {
            let mut incoming = listener.accept().await.unwrap();
            tokio::spawn(async move {
                if let Ok(mut outgoing) = TcpStream::connect(("127.0.0.1", server_port)).await {
                    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                }
            });
        }
    });
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let echo_task = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut b = [0; 4];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
    });
    let mut server = Process(Command::new(env!("CARGO_BIN_EXE_bibavpn-server"))
        .args(["--lab", "--listen", &format!("127.0.0.1:{server_port}"), "--self-signed-san", "localhost", "--psk", "0123456789abcdef0123456789abcdef"])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(("127.0.0.1", server_port)).await.is_ok() { break; }
            assert!(server.0.try_wait().unwrap().is_none(), "server exited during startup");
            sleep(Duration::from_millis(50)).await;
        }
    }).await.unwrap();
    let endpoint = format!("[{}]:18443", node.netstack.our_addr);
    let mut client_command = Command::new(env!("CARGO_BIN_EXE_bibavpn-client"));
    if no_mux { client_command.arg("--no-mux"); }
    let mut client = Process(client_command
        .env("BIBA_YB_MESH_PEERS", format!("tcp://127.0.0.1:{peer_port}"))
        .args(["--lab", "--server", "203.0.113.1:1", "--sni", "localhost", "--psk", "0123456789abcdef0123456789abcdef", "--insecure", "--yb-mesh", "--yb-mesh-endpoint", &endpoint, "--socks5", &format!("127.0.0.1:{socks_port}")])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    timeout(Duration::from_secs(30), async {
        let mut socks = loop {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", socks_port)).await { break s; }
            assert!(client.0.try_wait().unwrap().is_none(), "client exited during mesh startup");
            sleep(Duration::from_millis(100)).await;
        };
        socks.write_all(&[5, 1, 0]).await.unwrap();
        let mut hello = [0; 2]; socks.read_exact(&mut hello).await.unwrap(); assert_eq!(hello, [5, 0]);
        let port = echo_port.to_be_bytes();
        // A literal loopback IP is intentionally bypassed by the client.
        // The numeric hostname resolves locally on the server while still
        // exercising the mesh tunnel rather than the direct-bypass path.
        socks.write_all(&[5, 1, 0, 3, 5, b'1', b'2', b'7', b'.', b'1', port[0], port[1]]).await.unwrap();
        let mut reply = [0; 10]; socks.read_exact(&mut reply).await.unwrap(); assert_eq!(reply[1], 0);
        socks.write_all(b"mesh").await.unwrap();
        let mut result = [0; 4]; socks.read_exact(&mut result).await.unwrap(); assert_eq!(&result, b"mesh");
    }).await.expect("mesh SOCKS tunnel timed out");
    // UDP ASSOCIATE also opens its server-side WSS through the mesh.
    timeout(Duration::from_secs(20), async {
        let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp_echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut data = [0; 64];
            let (n, from) = udp_echo.recv_from(&mut data).await.unwrap();
            udp_echo.send_to(&data[..n], from).await.unwrap();
        });
        let mut control = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut hello = [0; 2]; control.read_exact(&mut hello).await.unwrap(); assert_eq!(hello, [5, 0]);
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut reply = [0; 10]; control.read_exact(&mut reply).await.unwrap(); assert_eq!(reply[1], 0);
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp_port.to_be_bytes();
        udp.send_to(&[0, 0, 0, 1, 127, 0, 0, 1, port[0], port[1], b'u', b'd', b'p'], ("127.0.0.1", relay_port)).await.unwrap();
        let mut data = [0; 64];
        let (n, _) = udp.recv_from(&mut data).await.unwrap();
        assert_eq!(&data[n-3..n], b"udp");
        echo_task.await.unwrap();
    }).await.expect("mesh UDP tunnel timed out");
    echo_task.await.unwrap();
    forward.abort();
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mux_socks_uses_mesh_with_an_unreachable_public_server() { run_mesh_tunnel(false).await; }

#[tokio::test(flavor = "multi_thread")]
async fn nonmux_socks_uses_mesh_with_an_unreachable_public_server() { run_mesh_tunnel(true).await; }
