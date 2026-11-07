/// TCP port forwarding.
///
/// * local-tcp  — accept on a local OS port, connect via netstack to a
///   remote Yggdrasil address.
/// * remote-tcp — accept on a smoltcp TCP socket bound to our Yggdrasil
///   address, connect via OS TCP to a local address.
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::mapping::TcpMapping;
use crate::netstack::YggNetstack;
use crate::stats::{counting_copy, ConnGuard, Dir, ListenerStats, ListenerStatsRegistry};

/// Stats/registry key for a local-tcp mapping ("ltcp:<listen>-><target>").
pub fn local_tcp_key(mapping: &TcpMapping) -> String {
    format!("ltcp:{}->{}", mapping.listen, mapping.target)
}

/// Stats/registry key for a remote-tcp mapping ("rtcp:<port>-><target>").
pub fn remote_tcp_key(mapping: &TcpMapping) -> String {
    format!("rtcp:{}->{}", mapping.listen.port(), mapping.target)
}

/// Start a local-tcp forwarder.
///
/// Listens on `mapping.listen` (OS) and forwards each connection to
/// `mapping.target` (Yggdrasil via netstack).
/// The task exits cleanly when `stop` receives a value or the sender is dropped.
/// Returns the listener stats key ("ltcp:<listen>-><target>") and the task handle.
pub fn spawn_local_tcp(
    netstack: Arc<YggNetstack>,
    mapping: TcpMapping,
    stop_tx: broadcast::Sender<()>,
    stats: Arc<ListenerStatsRegistry>,
) -> (String, tokio::task::JoinHandle<()>) {
    let key = local_tcp_key(&mapping);
    let entry = stats.entry(
        &key,
        "local-tcp",
        &mapping.listen.to_string(),
        &mapping.target.to_string(),
    );
    let task_key = key.clone();
    let handle = tokio::spawn(async move {
        let listener = match TcpListener::bind(mapping.listen).await {
            Ok(l) => {
                tracing::info!(
                    "local-tcp: {} → {}",
                    mapping.listen,
                    mapping.target
                );
                l
            }
            Err(e) => {
                tracing::error!("local-tcp bind {}: {}", mapping.listen, e);
                stats.remove(&task_key);
                return;
            }
        };
        let mut stop = stop_tx.subscribe();
        loop {
            tokio::select! {
                _ = stop.recv() => {
                    tracing::info!("local-tcp: stopped {} → {}", mapping.listen, mapping.target);
                    stats.remove(&task_key);
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((client, _peer)) => {
                            let ns = netstack.clone();
                            let target = mapping.target;
                            let stop_conn = stop_tx.subscribe();
                            let entry = entry.clone();
                            tokio::spawn(async move {
                                if let Err(e) = forward_local_tcp(client, ns, target, stop_conn, entry).await {
                                    tracing::debug!("local-tcp fwd: {}", e);
                                }
                            });
                        }
                        Err(e) => tracing::warn!("local-tcp accept: {}", e),
                    }
                }
            }
        }
    });
    (key, handle)
}

async fn forward_local_tcp(
    client: TcpStream,
    netstack: Arc<YggNetstack>,
    target: SocketAddr,
    mut stop: broadcast::Receiver<()>,
    entry: Arc<ListenerStats>,
) -> std::io::Result<()> {
    let _guard = ConnGuard::new(entry.clone());
    let ygg = netstack.dial_tcp(target).await?;
    let (cr, mut cw) = client.into_split();
    let (mut yr, mut yw) = tokio::io::split(ygg);
    tokio::select! {
        _ = stop.recv() => {}
        // client → ygg: written to the Yggdrasil leg, counts as TX
        _ = counting_copy(cr, &mut yw, entry.clone(), Dir::Tx) => {}
        // ygg → client: read from the Yggdrasil leg, counts as RX
        _ = counting_copy(&mut yr, &mut cw, entry, Dir::Rx) => {}
    }
    Ok(())
}

/// Start a remote-tcp forwarder.
///
/// Listens on our Yggdrasil address/port (netstack) and forwards each
/// incoming connection to `mapping.target` (OS TCP).
/// The task exits cleanly when `stop` receives a value or the sender is dropped.
/// Returns the listener stats key ("rtcp:<port>-><target>") and the task handle.
pub fn spawn_remote_tcp(
    netstack: Arc<YggNetstack>,
    mapping: TcpMapping,
    stop_tx: broadcast::Sender<()>,
    stats: Arc<ListenerStatsRegistry>,
) -> (String, tokio::task::JoinHandle<()>) {
    let port = mapping.listen.port();
    let target = mapping.target;
    let key = remote_tcp_key(&mapping);
    let entry = stats.entry(
        &key,
        "remote-tcp",
        &format!("ygg:{}", port),
        &target.to_string(),
    );
    let ns = netstack.clone();
    let task_key = key.clone();
    let handle = tokio::spawn(async move {
        let listener = match ns.listen_tcp(port) {
            Ok(l) => {
                tracing::info!("remote-tcp: ygg:{} → {}", port, target);
                l
            }
            Err(e) => {
                tracing::error!("remote-tcp listen ygg:{}: {}", port, e);
                stats.remove(&task_key);
                return;
            }
        };
        let mut stop = stop_tx.subscribe();
        loop {
            tokio::select! {
                _ = stop.recv() => {
                    tracing::info!("remote-tcp: stopped ygg:{} → {}", port, target);
                    stats.remove(&task_key);
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok(ygg_stream) => {
                            let stop_conn = stop_tx.subscribe();
                            let entry = entry.clone();
                            tokio::spawn(async move {
                                if let Err(e) = forward_remote_tcp(ygg_stream, target, stop_conn, entry).await {
                                    tracing::debug!("remote-tcp fwd: {}", e);
                                }
                            });
                        }
                        Err(e) => tracing::warn!("remote-tcp accept: {}", e),
                    }
                }
            }
        }
    });
    (key, handle)
}

async fn forward_remote_tcp(
    ygg_stream: crate::netstack::TcpStream,
    target: SocketAddr,
    mut stop: broadcast::Receiver<()>,
    entry: Arc<ListenerStats>,
) -> std::io::Result<()> {
    let _guard = ConnGuard::new(entry.clone());
    let local = tokio::time::timeout(
        crate::netstack::CONNECT_TIMEOUT,
        TcpStream::connect(target),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "local connect timed out")
    })??;
    let (lr, mut lw) = local.into_split();
    let (mut yr, mut yw) = tokio::io::split(ygg_stream);
    tracing::debug!("rtcp conn: relaying from ygg (local={})", target);
    tokio::select! {
        _ = stop.recv() => { tracing::debug!("rtcp conn: stop received"); }
        // ygg → local: read from the Yggdrasil leg, counts as RX
        r = counting_copy(&mut yr, &mut lw, entry.clone(), Dir::Rx) => { tracing::debug!("rtcp conn: ygg→local done {:?}", r); }
        // local → ygg: written to the Yggdrasil leg, counts as TX
        r = counting_copy(lr, &mut yw, entry, Dir::Tx) => { tracing::debug!("rtcp conn: local→ygg done {:?}", r); }
    }
    Ok(())
}
