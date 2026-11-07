#[cfg(unix)]
#[tokio::test]
async fn rejected_peer_socket_never_connects() {
    use std::{io, sync::Arc};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    yggdrasil::socket_protect::set_hook(Some(Arc::new(|_| {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "protect failed"))
    })));
    let result = yggdrasil::socket_protect::connect(&addr).await;
    yggdrasil::socket_protect::set_hook(None);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert!(tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept()).await.is_err());
}
