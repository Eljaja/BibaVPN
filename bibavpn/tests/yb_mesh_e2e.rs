//! Real Biba SOCKS tunnel through two local mesh nodes; the configured public IP is unreachable.
use std::{net::TcpListener as StdListener, process::{Child, Command, Stdio}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, time::{sleep, timeout}};

struct Process(Child);
impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
fn unused_port() -> u16 { StdListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }

fn start_server(server_port: u16, metrics_port: Option<u16>) -> Process {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bibavpn-server"));
    command.args(["--lab", "--listen", &format!("127.0.0.1:{server_port}"), "--self-signed-san", "localhost", "--psk", "0123456789abcdef0123456789abcdef"]);
    if let Some(port) = metrics_port { command.args(["--metrics-listen", &format!("127.0.0.1:{port}")]); }
    Process(command.stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap())
}

fn start_client(peer_port: u16, endpoint: &str, socks_port: u16, no_mux: bool) -> Process {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bibavpn-client"));
    if no_mux { command.arg("--no-mux"); }
    Process(command
        .env("BIBA_YB_MESH_PEERS", format!("tcp://127.0.0.1:{peer_port}"))
        .args(["--lab", "--server", "203.0.113.1:1", "--sni", "localhost", "--psk", "0123456789abcdef0123456789abcdef", "--insecure", "--yb-mesh", "--yb-mesh-endpoint", endpoint, "--socks5", &format!("127.0.0.1:{socks_port}")])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap())
}

async fn connect_socks(client: &mut Process, socks_port: u16, destination_port: u16) -> TcpStream {
    let mut socks = loop {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", socks_port)).await { break s; }
        assert!(client.0.try_wait().unwrap().is_none(), "client exited during mesh startup");
        sleep(Duration::from_millis(100)).await;
    };
    socks.write_all(&[5, 1, 0]).await.unwrap();
    let mut hello = [0; 2]; socks.read_exact(&mut hello).await.unwrap(); assert_eq!(hello, [5, 0]);
    let port = destination_port.to_be_bytes();
    // This numeric hostname resolves locally at the server without taking
    // the client's literal-loopback bypass path.
    socks.write_all(&[5, 1, 0, 3, 5, b'1', b'2', b'7', b'.', b'1', port[0], port[1]]).await.unwrap();
    let mut reply = [0; 10]; socks.read_exact(&mut reply).await.unwrap(); assert_eq!(reply[1], 0);
    socks
}

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
    let mut server = start_server(server_port, None);
    timeout(Duration::from_secs(10), async {
        loop {
            if TcpStream::connect(("127.0.0.1", server_port)).await.is_ok() { break; }
            assert!(server.0.try_wait().unwrap().is_none(), "server exited during startup");
            sleep(Duration::from_millis(50)).await;
        }
    }).await.unwrap();
    let endpoint = format!("[{}]:18443", node.netstack.our_addr);
    let mut client = start_client(peer_port, &endpoint, socks_port, no_mux);
    timeout(Duration::from_secs(30), async {
        let mut socks = connect_socks(&mut client, socks_port, echo_port).await;
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

async fn active_server_sessions(metrics_port: u16) -> u64 {
    timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(("127.0.0.1", metrics_port)).await.unwrap();
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "metrics request failed: {response}");
        response.lines().find_map(|line| line.strip_prefix("bibavpn_active_sessions "))
            .expect("active session metric missing").parse().unwrap()
    }).await.expect("metrics request timed out")
}

#[tokio::test(flavor = "multi_thread")]
async fn vanished_authenticated_mesh_client_releases_sessions_without_harming_idle_client() {
    timeout(Duration::from_secs(180), async {
        let peer_port = unused_port();
        let server_port = unused_port();
        let metrics_port = unused_port();
        let socks_ports = [unused_port(), unused_port()];
        let node = bibavpn::yb_mesh::MeshNode::start(vec![], vec![format!("tcp://127.0.0.1:{peer_port}")]).await.unwrap();
        let listener = node.netstack.listen_tcp(18444).unwrap();
        let (forward_count, forwards) = tokio::sync::watch::channel(0usize);
        let forward = tokio::spawn(async move {
            // Owning the children also ensures cancelling this task tears down
            // every local forward, including when an assertion fails.
            let mut sessions = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let mut incoming = incoming.unwrap();
                        sessions.spawn(async move {
                            let mut outgoing = TcpStream::connect(("127.0.0.1", server_port)).await.unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                        });
                    }
                    result = sessions.join_next(), if !sessions.is_empty() => { result.unwrap().unwrap(); }
                }
                forward_count.send_replace(sessions.len());
            }
        });
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut sessions = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = echo.accept().await.unwrap();
                sessions.spawn(async move {
                    let mut data = [0; 1024];
                    loop {
                        let n = stream.read(&mut data).await.unwrap();
                        if n == 0 { break; }
                        stream.write_all(&data[..n]).await.unwrap();
                    }
                });
            }
            while let Some(result) = sessions.join_next().await { result.unwrap(); }
        });
        let mut server = start_server(server_port, Some(metrics_port));
        timeout(Duration::from_secs(10), async {
            loop {
                if TcpStream::connect(("127.0.0.1", server_port)).await.is_ok()
                    && TcpStream::connect(("127.0.0.1", metrics_port)).await.is_ok() { break; }
                assert!(server.0.try_wait().unwrap().is_none(), "server exited during startup");
                sleep(Duration::from_millis(50)).await;
            }
        }).await.expect("server did not start");
        let endpoint = format!("[{}]:18444", node.netstack.our_addr);
        let mut vanished = start_client(peer_port, &endpoint, socks_ports[0], true);
        let mut survivor = start_client(peer_port, &endpoint, socks_ports[1], true);
        let (vanished_socks, mut survivor_socks) = timeout(Duration::from_secs(30), async {
            let mut first = connect_socks(&mut vanished, socks_ports[0], echo_port).await;
            let mut second = connect_socks(&mut survivor, socks_ports[1], echo_port).await;
            for stream in [&mut first, &mut second] {
                stream.write_all(b"authenticated").await.unwrap();
                let mut reply = [0; 13];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"authenticated");
            }
            loop {
                let count = *forwards.borrow();
                if count == 2 && active_server_sessions(metrics_port).await == 2 { break; }
                sleep(Duration::from_millis(50)).await;
            }
            (first, second)
        }).await.expect("both clients did not authenticate and forward data");

        // SIGKILL drops the underlay connection without running the child's
        // userspace TCP shutdown, so the overlay receives no FIN.
        vanished.0.kill().unwrap();
        vanished.0.wait().unwrap();
        timeout(Duration::from_secs(125), async {
            loop {
                assert!(survivor.0.try_wait().unwrap().is_none(), "remaining client exited");
                let count = *forwards.borrow();
                if count == 1 && active_server_sessions(metrics_port).await == 1 { break; }
                sleep(Duration::from_millis(250)).await;
            }
        }).await.expect("vanished client's forward and server session survived the 120s liveness timeout plus 5s scheduling allowance");

        // Reuse the original idle session: a reconnect cannot hide accidental
        // retirement of the second client's established connection.
        timeout(Duration::from_secs(5), async {
            survivor_socks.write_all(b"still alive").await.unwrap();
            let mut reply = [0; 11];
            survivor_socks.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"still alive");
        }).await.expect("idle remaining client's established session stopped forwarding");
        assert_eq!(*forwards.borrow(), 1);
        assert_eq!(active_server_sessions(metrics_port).await, 1);
        drop(vanished_socks);
        drop(survivor_socks);
        timeout(Duration::from_secs(5), echo_task).await.expect("echo sessions were not released").unwrap();
        drop(survivor);
        forward.abort();
        let _ = forward.await;
        node.shutdown().await;
    }).await.expect("client disappearance regression exceeded its 180s deadline");
}
