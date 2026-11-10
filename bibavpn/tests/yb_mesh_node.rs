use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn mesh_tcp_can_queue_a_large_burst_in_both_directions() {
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_address = reserve.local_addr().unwrap();
    drop(reserve);
    let server = bibavpn::yb_mesh::MeshNode::start(vec![], vec![format!("tcp://{peer_address}")]).await.unwrap();
    let listener = server.netstack.listen_tcp(18182).unwrap();
    let client = bibavpn::yb_mesh::MeshNode::start(vec![format!("tcp://{peer_address}")], vec![]).await.unwrap();
    let address = std::net::SocketAddr::new(server.netstack.our_addr.into(), 18182);
    tokio::time::timeout(Duration::from_secs(20), async {
        while client.connected_peers().await == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut outgoing = client.netstack.dial_tcp(address).await.unwrap();
        let mut incoming = listener.accept().await.unwrap();
        let payload = vec![0x5a; 768 * 1024];
        let mut received = vec![0; payload.len()];

        let n = outgoing.write(&payload).await.unwrap();
        assert_eq!(n, payload.len(), "client could not queue a full burst before ACKs");
        incoming.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);

        let n = incoming.write(&payload).await.unwrap();
        assert_eq!(n, payload.len(), "server could not queue a full burst before ACKs");
        outgoing.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
    }).await.expect("mesh bulk transfer timed out");
    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn two_nodes_exchange_bytes_over_a_peer_link() {
    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_address = reserve.local_addr().unwrap();
    drop(reserve);
    let server = bibavpn::yb_mesh::MeshNode::start(vec![], vec![format!("tcp://{peer_address}")]).await.unwrap();
    let listener = server.netstack.listen_tcp(18181).unwrap();
    let client = std::sync::Arc::new(bibavpn::yb_mesh::MeshNode::start(vec![format!("tcp://{peer_address}")], vec![]).await.unwrap());
    let addr = std::net::SocketAddr::new(server.netstack.our_addr.into(), 18181);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client.connected_peers().await > 0 { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut outgoing = client.netstack.dial_tcp(addr).await.unwrap();
        let mut incoming = listener.accept().await.unwrap();
        outgoing.write_all(b"mesh").await.unwrap();
        let mut bytes = [0; 4];
        incoming.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"mesh");
    }).await.expect("mesh did not become ready");
    let _route = bibavpn::yb_mesh::ServerRoute::mesh(client.clone(), &addr.to_string()).unwrap();
    assert!(bibavpn::yb_mesh::active_mesh_rtt(&addr.to_string()).await.is_some());
    client.shutdown().await;
    server.shutdown().await;
}

#[tokio::test]
async fn ignores_unreachable_peer_and_recovers_after_working_peer_restarts() {
    fn port() -> u16 { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }
    let live = port();
    let dead = port();
    let url = format!("tcp://127.0.0.1:{live}");
    let server = bibavpn::yb_mesh::MeshNode::start(vec![], vec![url.clone()]).await.unwrap();
    let client = bibavpn::yb_mesh::MeshNode::start(vec![format!("tcp://127.0.0.1:{dead}"), url.clone()], vec![]).await.unwrap();
    async fn wait_for(client: &bibavpn::yb_mesh::MeshNode, count: bool) {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if (client.connected_peers().await > 0) == count { break; }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.expect("peer did not change state");
    }
    wait_for(&client, true).await;
    server.shutdown().await;
    drop(server);
    wait_for(&client, false).await;
    let replacement = bibavpn::yb_mesh::MeshNode::start(vec![], vec![url]).await.unwrap();
    wait_for(&client, true).await;
    client.shutdown().await;
    replacement.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn four_clients_each_exchange_four_simultaneous_tcp_sessions() {
    use std::sync::Arc;
    use tokio::{sync::Barrier, task::JoinSet};

    let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_address = reserve.local_addr().unwrap();
    drop(reserve);
    let server = bibavpn::yb_mesh::MeshNode::start(vec![], vec![format!("tcp://{peer_address}")]).await.unwrap();
    let listener = server.netstack.listen_tcp(18183).unwrap();
    let address = std::net::SocketAddr::new(server.netstack.our_addr.into(), 18183);
    let mut clients = Vec::new();
    for _ in 0..4 {
        clients.push(Arc::new(bibavpn::yb_mesh::MeshNode::start(vec![format!("tcp://{peer_address}")], vec![]).await.unwrap()));
    }

    tokio::time::timeout(Duration::from_secs(30), async {
        for client in &clients {
            while client.connected_peers().await == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        let start = Arc::new(Barrier::new(17));
        // No response is sent until every session has delivered its request:
        // all sixteen connections must coexist, rather than reuse capacity.
        let received = Arc::new(Barrier::new(16));
        let mut exchanges = JoinSet::new();
        for (client_id, client) in clients.iter().enumerate() {
            for session_id in 0..4 {
                let client = client.clone();
                let start = start.clone();
                exchanges.spawn(async move {
                    let id = (client_id * 4 + session_id) as u8;
                    let payload = vec![id; 32 * 1024];
                    start.wait().await;
                    let mut stream = client.netstack.dial_tcp(address).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                    let mut response = vec![0; payload.len()];
                    stream.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, vec![id ^ 0xff; payload.len()]);
                });
            }
        }
        start.wait().await;
        let mut responders = JoinSet::new();
        for _ in 0..16 {
            let mut stream = listener.accept().await.unwrap();
            let received = received.clone();
            responders.spawn(async move {
                let mut request = vec![0; 32 * 1024];
                stream.read_exact(&mut request).await.unwrap();
                let id = request[0];
                assert!(id < 16);
                assert!(request.iter().all(|byte| *byte == id));
                received.wait().await;
                request.iter_mut().for_each(|byte| *byte ^= 0xff);
                stream.write_all(&request).await.unwrap();
                id
            });
        }
        let mut ids = Vec::new();
        while let Some(result) = responders.join_next().await { ids.push(result.unwrap()); }
        ids.sort_unstable();
        assert_eq!(ids, (0..16).collect::<Vec<u8>>());
        while let Some(result) = exchanges.join_next().await { result.unwrap(); }
    }).await.expect("four-client simultaneous mesh exchanges timed out");

    for client in clients { client.shutdown().await; }
    server.shutdown().await;
}
