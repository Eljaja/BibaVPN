/// UDP port forwarding.
///
/// * local-udp  — bind a local OS UDP socket, forward datagrams to a
///   remote Yggdrasil address via the netstack UDP socket.
/// * remote-udp — bind a netstack UDP socket on our Yggdrasil address,
///   forward datagrams to/from a local OS UDP address.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket as OsUdpSocket;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;

use crate::mapping::UdpMapping;
use crate::netstack::YggNetstack;
use crate::stats::{ConnGuard, ListenerStatsRegistry};

/// Session timeout: evict sessions idle for longer than this.
const SESSION_TTL_SECS: u64 = 30;
/// Timer-based eviction interval.
const EVICT_TIMER_SECS: u64 = 10;

struct UdpSession<S> {
    socket: Arc<S>,
    last_active: Instant,
    listener_handle: Option<JoinHandle<()>>,
}

/// Abort every session listener and drain the map, releasing all ports and
/// netstack sockets. Used on stop so a restarted node can rebind cleanly.
async fn abort_all_sessions<S>(sessions: &Mutex<HashMap<SocketAddr, UdpSession<S>>>) {
    let mut guard = sessions.lock().await;
    let mut aborted = 0;
    for (_, session) in guard.drain() {
        if let Some(handle) = session.listener_handle {
            handle.abort();
            aborted += 1;
        }
        // session.socket Arc drops here -> if refcount=0 -> smoltcp remove
    }
    if aborted > 0 {
        tracing::debug!("udp: aborted {} session listeners on stop", aborted);
    }
}

/// Spawn a periodic eviction task for a sessions map.
/// The task exits when `stop_tx` fires or the sender is dropped.
fn spawn_eviction_timer<S: Send + Sync + 'static>(
    sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession<S>>>>,
    label: &'static str,
    stop_tx: broadcast::Sender<()>,
) {
    tokio::spawn(async move {
        let mut stop = stop_tx.subscribe();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(EVICT_TIMER_SECS));
        loop {
            tokio::select! {
                _ = stop.recv() => { break; }
                _ = interval.tick() => {
                    let mut guard = sessions.lock().await;
                    let now = Instant::now();

                    // Collect stale session keys
                    let stale: Vec<SocketAddr> = guard
                        .iter()
                        .filter(|(_, s)| now.duration_since(s.last_active).as_secs() >= SESSION_TTL_SECS)
                        .map(|(k, _)| *k)
                        .collect();

                    let evicted = stale.len();
                    let mut aborted = 0;
                    for addr in stale {
                        if let Some(session) = guard.remove(&addr) {
                            if let Some(handle) = session.listener_handle {
                                handle.abort();
                                aborted += 1;
                            }
                            // session.socket Arc drops here -> if refcount=0 -> smoltcp remove
                        }
                    }
                    let remaining = guard.len();
                    drop(guard);

                    if evicted > 0 {
                        tracing::info!(
                            "[b{}] {}: evicted {} sessions (aborted {} listeners), {} remaining",
                            crate::BUILD_NUM, label, evicted, aborted, remaining
                        );
                    }
                }
            }
        }
    });
}

/// Stats/registry key for a local-udp mapping ("ludp:<listen>-><target>").
pub fn local_udp_key(mapping: &UdpMapping) -> String {
    format!("ludp:{}->{}", mapping.listen, mapping.target)
}

/// Stats/registry key for a remote-udp mapping ("rudp:<port>-><target>").
pub fn remote_udp_key(mapping: &UdpMapping) -> String {
    format!("rudp:{}->{}", mapping.listen.port(), mapping.target)
}

/// Start a local-udp forwarder.
/// The task exits cleanly when `stop` receives a value or the sender is dropped.
pub fn spawn_local_udp(
    netstack: Arc<YggNetstack>,
    mapping: UdpMapping,
    stop_tx: broadcast::Sender<()>,
    stats: Arc<ListenerStatsRegistry>,
) -> (String, tokio::task::JoinHandle<()>) {
    let key = local_udp_key(&mapping);
    let entry = stats.entry(
        &key,
        "local-udp",
        &mapping.listen.to_string(),
        &mapping.target.to_string(),
    );
    let task_key = key.clone();
    let handle = tokio::spawn(async move {
        let local_sock = match OsUdpSocket::bind(mapping.listen).await {
            Ok(s) => {
                tracing::info!(
                    "local-udp: {} -> {}",
                    mapping.listen,
                    mapping.target
                );
                Arc::new(s)
            }
            Err(e) => {
                tracing::error!("local-udp bind {}: {}", mapping.listen, e);
                stats.remove(&task_key);
                return;
            }
        };

        let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession<crate::netstack::UdpSocket>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Timer-based eviction with listener abort
        spawn_eviction_timer(sessions.clone(), "local-udp", stop_tx.clone());

        let mut stop = stop_tx.subscribe();
        let mut buf = vec![0u8; 65535];
        let target = mapping.target;
        loop {
            tokio::select! {
                _ = stop.recv() => {
                    tracing::info!("local-udp: stopped {} -> {}", mapping.listen, mapping.target);
                    stats.remove(&task_key);
                    break;
                }
                result = local_sock.recv_from(&mut buf) => {
                    match result {
                        Ok((n, from)) => {
                            let (udp_sock, need_listener) = {
                                let mut guard = sessions.lock().await;
                                let session = guard.entry(from).or_insert_with(|| {
                                    UdpSession {
                                        socket: Arc::new(netstack.open_udp().unwrap()),
                                        last_active: Instant::now(),
                                        listener_handle: None,
                                    }
                                });
                                session.last_active = Instant::now();
                                let need = session.listener_handle
                                    .as_ref()
                                    .is_none_or(|h| h.is_finished());
                                (session.socket.clone(), need)
                            };

                            if let Err(e) = udp_sock.send_to(&buf[..n], target).await {
                                tracing::debug!("local-udp send: {}", e);
                                continue;
                            }
                            entry.tx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);

                            if need_listener {
                                let udp_sock2 = udp_sock.clone();
                                let local_sock2 = local_sock.clone();
                                let from2 = from;
                                let entry2 = entry.clone();
                                let handle = tokio::spawn(async move {
                                    let _guard = ConnGuard::new(entry2.clone());
                                    let mut rbuf = vec![0u8; 65535];
                                    while let Ok((rn, _src)) = udp_sock2.recv_from(&mut rbuf).await {
                                        entry2.rx_bytes.fetch_add(rn as u64, std::sync::atomic::Ordering::Relaxed);
                                        let _ = local_sock2.send_to(&rbuf[..rn], from2).await;
                                    }
                                });
                                let mut guard = sessions.lock().await;
                                if let Some(session) = guard.get_mut(&from) {
                                    session.listener_handle = Some(handle);
                                }
                            }
                            // udp_sock Arc drops here — only listener holds a ref
                            drop(udp_sock);
                        }
                        Err(e) => tracing::warn!("local-udp recv: {}", e),
                    }
                }
            }
        }
        abort_all_sessions(&sessions).await;
    });
    (key, handle)
}

/// Start a remote-udp forwarder.
/// The task exits cleanly when `stop` receives a value or the sender is dropped.
pub fn spawn_remote_udp(
    netstack: Arc<YggNetstack>,
    mapping: UdpMapping,
    stop_tx: broadcast::Sender<()>,
    stats: Arc<ListenerStatsRegistry>,
) -> (String, tokio::task::JoinHandle<()>) {
    let port = mapping.listen.port();
    let target = mapping.target;
    let key = remote_udp_key(&mapping);
    let entry = stats.entry(
        &key,
        "remote-udp",
        &format!("ygg:{}", port),
        &target.to_string(),
    );
    let ns = netstack.clone();

    let task_key = key.clone();
    let handle = tokio::spawn(async move {
        let ygg_sock = match ns.bind_udp(port) {
            Ok(s) => {
                tracing::info!("remote-udp: ygg:{} -> {}", port, target);
                Arc::new(s)
            }
            Err(e) => {
                tracing::error!("remote-udp bind ygg:{}: {}", port, e);
                stats.remove(&task_key);
                return;
            }
        };

        let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession<OsUdpSocket>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Timer-based eviction with listener abort
        spawn_eviction_timer(sessions.clone(), "remote-udp", stop_tx.clone());

        let mut stop = stop_tx.subscribe();
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = stop.recv() => {
                    tracing::info!("remote-udp: stopped ygg:{} -> {}", port, target);
                    stats.remove(&task_key);
                    break;
                }
                result = ygg_sock.recv_from(&mut buf) => {
                    match result {
                        Ok((n, from_ygg)) => {
                            entry.rx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                            let (local_sock, need_listener) = {
                                let mut guard = sessions.lock().await;
                                // Ensure a session exists for this remote peer
                                if let std::collections::hash_map::Entry::Vacant(e) = guard.entry(from_ygg) {
                                    match OsUdpSocket::bind("0.0.0.0:0").await {
                                        Ok(s) => {
                                            e.insert(UdpSession {
                                                socket: Arc::new(s),
                                                last_active: Instant::now(),
                                                listener_handle: None,
                                            });
                                        }
                                        Err(e) => {
                                            tracing::warn!("remote-udp local bind: {}", e);
                                            continue;
                                        }
                                    }
                                }
                                let session = guard.get_mut(&from_ygg).unwrap();
                                session.last_active = Instant::now();
                                let need = session.listener_handle
                                    .as_ref()
                                    .is_none_or(|h| h.is_finished());
                                (session.socket.clone(), need)
                            };

                            if let Err(e) = local_sock.send_to(&buf[..n], target).await {
                                tracing::debug!("remote-udp local send: {}", e);
                            }

                            if need_listener {
                                let ygg_sock2 = ygg_sock.clone();
                                let entry2 = entry.clone();
                                let handle = tokio::spawn(async move {
                                    let _guard = ConnGuard::new(entry2.clone());
                                    let mut rbuf = vec![0u8; 65535];
                                    while let Ok((rn, _src)) = local_sock.recv_from(&mut rbuf).await {
                                        entry2.tx_bytes.fetch_add(rn as u64, std::sync::atomic::Ordering::Relaxed);
                                        let _ = ygg_sock2.send_to(&rbuf[..rn], from_ygg).await;
                                    }
                                });
                                let mut guard = sessions.lock().await;
                                if let Some(session) = guard.get_mut(&from_ygg) {
                                    session.listener_handle = Some(handle);
                                }
                            }
                        }
                        Err(e) => tracing::warn!("remote-udp recv: {}", e),
                    }
                }
            }
        }
        abort_all_sessions(&sessions).await;
    });
    (key, handle)
}
