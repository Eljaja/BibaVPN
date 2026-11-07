#[tokio::test]
async fn unavailable_mesh_never_dials_the_direct_server() {
    use std::{sync::Arc, time::Duration};
    let direct = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node = Arc::new(bibavpn::yb_mesh::MeshNode::start(vec![], vec![]).await.unwrap());
    let route = bibavpn::yb_mesh::ServerRoute::mesh(node.clone(), "[201:db8::42]:8443").unwrap();
    let address = direct.local_addr().unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(300), route.connect("127.0.0.1", address.port())).await;
    assert!(tokio::time::timeout(Duration::from_millis(100), direct.accept()).await.is_err());
    node.shutdown().await;
}
