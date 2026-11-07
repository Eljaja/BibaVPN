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
