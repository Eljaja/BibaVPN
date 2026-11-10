//! Yggdrasil transport for reaching a Biba server without its public IP.
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use yggdrasil::{core::Core, ipv6rwc::ReadWriteCloser};
use yggstack::{config, netstack::YggNetstack};

/// One measured candidate edge in the client→peer graph.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerQuality {
    pub uri: String,
    pub up: bool,
    pub latency_ms: Option<u32>,
    pub cost: u64,
    pub rx_rate: usize,
    pub tx_rate: usize,
    pub uptime_secs: u64,
    pub last_error: Option<String>,
}

/// Lower is better. Up links dominate; then measured RTT/cost; an active link
/// gets a small bonus so a warm peer wins a tie against an unproven one.
pub fn peer_score(peer: &PeerQuality) -> f64 {
    if !peer.up {
        return f64::INFINITY;
    }
    let latency = peer.latency_ms.unwrap_or(1000) as f64;
    let cost = peer.cost as f64;
    let activity = ((peer.rx_rate + peer.tx_rate) as f64 + 1.0).ln() * 5.0;
    latency + cost * 0.25 - activity
}

/// Order peers by [`peer_score`], preserving input order for equal scores.
pub fn rank_peer_quality(peers: Vec<PeerQuality>) -> Vec<PeerQuality> {
    let mut indexed: Vec<(usize, PeerQuality)> = peers.into_iter().enumerate().collect();
    indexed.sort_by(|(ia, a), (ib, b)| {
        peer_score(a)
            .partial_cmp(&peer_score(b))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| ia.cmp(ib))
    });
    indexed.into_iter().map(|(_, peer)| peer).collect()
}

/// Parse the authority of a Yggdrasil peer URI into (host, port).
fn peer_uri_host_port(uri: &str) -> Option<(String, u16)> {
    let authority = uri.split_once("://")?.1.split(['/', '?', '#']).next()?;
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?.parse::<u16>().ok()?;
        return (!host.is_empty() && port != 0).then(|| (host.to_string(), port));
    }
    let (host, port) = authority.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    (!host.is_empty() && port != 0).then(|| (host.to_string(), port))
}

/// Probe bootstrap peers and order reachable ones by TCP connect latency.
///
/// This is a cheap first edge weight (not overlay RTT): it removes dead peers
/// from the front of the list and puts geographically closer TLS peers first.
/// Disable with `BIBA_YB_MESH_RANK=0`.
pub async fn rank_bootstrap_peers(peers: Vec<String>) -> Vec<String> {
    if std::env::var("BIBA_YB_MESH_RANK").ok().as_deref() == Some("0") || peers.len() < 2 {
        return peers;
    }
    let probes = peers.iter().cloned().map(|uri| async move {
        let started = Instant::now();
        let reachable = match peer_uri_host_port(&uri) {
            Some((host, port)) => tokio::time::timeout(
                Duration::from_millis(750),
                crate::outbound_protect::tcp_connect_host_protected(&host, port),
            )
            .await
            .is_ok_and(|result| result.is_ok()),
            None => false,
        };
        (uri, reachable.then(|| started.elapsed()))
    });
    let mut ranked: Vec<(usize, String, Option<Duration>)> =
        futures_util::future::join_all(probes)
            .await
            .into_iter()
            .enumerate()
            .map(|(index, (uri, rtt))| (index, uri, rtt))
            .collect();
    ranked.sort_by(|(ia, _, a), (ib, _, b)| match (a, b) {
        (Some(a), Some(b)) => a.cmp(b).then_with(|| ia.cmp(ib)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => ia.cmp(ib),
    });
    let ranked: Vec<String> = ranked.into_iter().map(|(_, uri, _)| uri).collect();
    tracing::debug!(?ranked, "mesh bootstrap peers ranked");
    ranked
}

type ActiveMesh = Option<(std::sync::Weak<MeshNode>, SocketAddrV6)>;
static ACTIVE_MESH: std::sync::OnceLock<std::sync::Mutex<ActiveMesh>> = std::sync::OnceLock::new();

/// Measure a new TCP connection over the currently running mesh node.
pub async fn active_mesh_rtt(endpoint: &str) -> Option<u32> {
    let expected = parse_endpoint(endpoint).ok()?;
    let node = {
        let active = ACTIVE_MESH.get()?.lock().ok()?;
        let (node, address) = active.as_ref()?;
        if *address != expected { return None; }
        node.upgrade()?
    };
    let started = std::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(5), node.netstack.dial_tcp(expected.into())).await.ok()?.ok()?;
    Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// Small, geographically diverse bootstrap pool. The core reconnects peers and
/// only treats a peer as up after the Yggdrasil handshake succeeds.
pub fn bootstrap_peers() -> Vec<String> {
    if let Ok(configured) = std::env::var("BIBA_YB_MESH_PEERS") {
        let peers: Vec<_> = configured.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
        if !peers.is_empty() {
            return peers;
        }
    }
    [
        "tls://yggno.de:18227",
        "tls://mskaeza.i113d.ru:12632",
        "tls://37.205.14.171:993?key=0009e16b9e3afe7b13c3612560410434d3dfc70c8a8a0a63e51e0470cb8124f6",
        "tls://ygg1.mk16.de:1338?key=0000000087ee9949eeab56bd430ee8f324cad55abf3993ed9b9be63ce693e18a",
    ].into_iter().map(str::to_owned).collect()
}

/// Accept only a nonzero TCP port on the Yggdrasil 200::/7 address range.
pub fn parse_endpoint(value: &str) -> anyhow::Result<SocketAddrV6> {
    match value.parse::<SocketAddr>()? {
        SocketAddr::V6(addr) if addr.ip().octets()[0] & 0xfe == 0x02 && addr.port() != 0 && addr.scope_id() == 0 => Ok(addr),
        _ => anyhow::bail!("yb-mesh endpoint must be a Yggdrasil IPv6 address and nonzero port"),
    }
}

/// Full client-visible topology: direct peers, Ironwood tree edges, our
/// coordinates and cached paths. Keys are hex so the snapshot is printable.
#[derive(Clone, Debug)]
pub struct MeshTopology {
    pub peers: Vec<PeerQuality>,
    pub tree: Vec<(String, String, u64)>,
    pub coordinates: Vec<u64>,
    pub paths: Vec<(String, Vec<u64>, u64)>,
}

/// A userspace IPv6 stack backed by one Yggdrasil node.
pub struct MeshNode {
    core: Arc<Core>,
    pub netstack: Arc<YggNetstack>,
    peer_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    supervisor_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Generated mesh config with every implicit listener disabled.
///
/// The Yggdrasil template listens on all interfaces and enables an admin
/// socket; an outbound-only mesh client must not do either. Only URIs passed
/// explicitly to [`MeshNode::start`] are bound afterwards.
fn mesh_config() -> config::Config {
    let mut cfg = config::generate();
    cfg.peers.clear();
    cfg.multicast_interfaces.clear();
    cfg.listen.clear();
    cfg.admin_listen = "none".to_string();
    cfg
}

impl MeshNode {
    pub async fn start(peers: Vec<String>, listen: Vec<String>) -> anyhow::Result<Self> {
        let cfg = mesh_config();
        let signing_key = cfg.signing_key().map_err(anyhow::Error::msg)?;
        let address = config::addr_for_key(&signing_key.verifying_key().to_bytes());
        let core = Core::new(signing_key, cfg);
        core.init_links().await;
        core.start().await;
        for uri in listen {
            core.listen(&uri).await.map_err(anyhow::Error::msg)?;
        }
        let mtu = core.mtu();
        let rwc = ReadWriteCloser::new(core.clone(), mtu, None);
        core.set_path_notify(rwc.clone());
        let netstack = YggNetstack::new(rwc, address, mtu);

        // Speed graph: rank candidate bootstrap edges by measured TCP latency,
        // keep the best few, and retain the rest as supervisor fallbacks.
        let ranked = rank_bootstrap_peers(peers).await;
        let max_peers = std::env::var("BIBA_YB_MESH_MAX_PEERS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(3)
            .clamp(1, 32);
        let take = max_peers.min(ranked.len());
        let (selected, fallbacks) = ranked.split_at(take);
        let selected = selected.to_vec();
        let fallbacks = fallbacks.to_vec();
        tracing::debug!(?selected, ?fallbacks, "mesh peer graph selected");

        let peer_core = core.clone();
        let peer_task = tokio::spawn(async move {
            for peer in selected {
                if let Err(error) = peer_core.add_peer(&peer).await {
                    tracing::warn!(%peer, %error, "could not register mesh peer");
                }
            }
        });
        let supervisor_task =
            if fallbacks.is_empty() || std::env::var("BIBA_YB_MESH_SUPERVISOR").ok().as_deref() == Some("0") {
            None
        } else {
            let supervisor_core = core.clone();
            Some(tokio::spawn(peer_supervisor(
                supervisor_core,
                fallbacks,
                max_peers,
            )))
        };
        Ok(Self {
            core,
            netstack,
            peer_task: std::sync::Mutex::new(Some(peer_task)),
            supervisor_task: std::sync::Mutex::new(supervisor_task),
        })
    }

    pub async fn connected_peers(&self) -> usize {
        self.core.get_peers().await.into_iter().filter(|peer| peer.up).count()
    }

    /// Current client→peer graph snapshot, including disconnected configured
    /// peers, latency/cost and passive rates.
    pub async fn peer_quality(&self) -> Vec<PeerQuality> {
        self.core
            .get_peers()
            .await
            .into_iter()
            .map(|peer| PeerQuality {
                uri: peer.uri,
                up: peer.up,
                latency_ms: (peer.latency_ms > 0.0)
                    .then(|| peer.latency_ms.min(u32::MAX as f64) as u32),
                cost: peer.cost,
                rx_rate: peer.rx_rate,
                tx_rate: peer.tx_rate,
                uptime_secs: peer.uptime_secs.max(0.0) as u64,
                last_error: peer.last_error,
            })
            .collect()
    }

    /// Peers ordered by the speed-graph score (best first).
    pub async fn ranked_peers(&self) -> Vec<PeerQuality> {
        rank_peer_quality(self.peer_quality().await)
    }

    /// Snapshot of everything the client currently knows about the mesh graph.
    pub async fn topology(&self) -> MeshTopology {
        let peers = self.peer_quality().await;
        let tree = self
            .core
            .get_tree()
            .await
            .into_iter()
            .map(|entry| {
                (
                    hex::encode(entry.key),
                    hex::encode(entry.parent),
                    entry.sequence,
                )
            })
            .collect();
        let coordinates = self.core.tree_coordinates().await;
        let paths = self
            .core
            .get_paths()
            .await
            .into_iter()
            .map(|entry| (hex::encode(entry.key), entry.path, entry.sequence))
            .collect();
        MeshTopology {
            peers,
            tree,
            coordinates,
            paths,
        }
    }

    pub async fn shutdown(&self) {
        if let Some(task) = self.peer_task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        if let Some(task) = self.supervisor_task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        self.netstack.shutdown().await;
        let _ = self.core.close().await;
    }
}

/// Keep the selected peer graph populated and replace a consistently slow live
/// peer with the next ranked fallback. Replacement is deliberately damped:
/// only after 2 minutes of uptime, a 2x+50 ms gap, and at most one switch per
/// 5 minutes, so transient RTT samples cannot flap the Ironwood tree.
async fn peer_supervisor(core: Arc<Core>, fallbacks: Vec<String>, max_peers: usize) {
    let mut next_fallback = 0usize;
    let mut last_switch = Instant::now()
        .checked_sub(Duration::from_secs(300))
        .unwrap_or_else(Instant::now);
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let peers = core.get_peers().await;
        let mut up: Vec<_> = peers.iter().filter(|peer| peer.up).collect();
        up.sort_by(|a, b| a.latency_ms.total_cmp(&b.latency_ms));
        let up_count = up.len();

        if up_count < max_peers && next_fallback < fallbacks.len() {
            let uri = fallbacks[next_fallback].clone();
            next_fallback += 1;
            match core.add_peer(&uri).await {
                Ok(()) => tracing::info!(%uri, up_count, "mesh supervisor added fallback peer"),
                Err(error) => tracing::warn!(%uri, %error, "mesh supervisor fallback failed"),
            }
        } else if up_count >= max_peers
            && next_fallback < fallbacks.len()
            && last_switch.elapsed() >= Duration::from_secs(300)
        {
            let (best, worst) = (up[0], up[up_count - 1]);
            let best_latency = best.latency_ms;
            let worst_latency = worst.latency_ms;
            if best_latency > 0.0
                && worst_latency > best_latency * 2.0 + 50.0
                && worst.uptime_secs >= 120.0
                && worst.uri != best.uri
            {
                let bad_uri = worst.uri.clone();
                let fallback = fallbacks[next_fallback].clone();
                if core.remove_peer(&bad_uri).await.is_ok() {
                    next_fallback += 1;
                    match core.add_peer(&fallback).await {
                        Ok(()) => {
                            last_switch = Instant::now();
                            tracing::info!(
                                removed = %bad_uri,
                                added = %fallback,
                                best_latency_ms = best_latency,
                                worst_latency_ms = worst_latency,
                                "mesh supervisor replaced a slow peer"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(%fallback, %error, "mesh supervisor replacement failed")
                        }
                    }
                }
            }
        }

        if let Some(best) = up.first() {
            tracing::debug!(
                up = up_count,
                best_uri = %best.uri,
                best_latency_ms = best.latency_ms,
                "mesh peer graph health"
            );
        }
    }
}

impl Drop for MeshNode {
    fn drop(&mut self) {
        if let Some(task) = self.peer_task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        if let Some(task) = self.supervisor_task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let core = self.core.clone();
            let netstack = self.netstack.clone();
            runtime.spawn(async move {
                netstack.shutdown().await;
                let _ = core.close().await;
            });
        }
    }
}

#[derive(Clone)]
pub enum ServerRoute {
    Direct,
    Mesh { node: Arc<MeshNode>, endpoint: SocketAddrV6 },
}

impl ServerRoute {
    pub fn mesh(node: Arc<MeshNode>, endpoint: &str) -> anyhow::Result<Self> {
        let endpoint = parse_endpoint(endpoint)?;
        *ACTIVE_MESH.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap_or_else(|e| e.into_inner()) = Some((Arc::downgrade(&node), endpoint));
        Ok(Self::Mesh { node, endpoint })
    }

    pub async fn connect(&self, host: &str, port: u16) -> io::Result<ServerStream> {
        match self {
            Self::Direct => crate::outbound_protect::tcp_connect_host_protected(host, port).await.map(ServerStream::Direct),
            Self::Mesh { node, endpoint } => node.netstack.dial_tcp((*endpoint).into()).await.map(ServerStream::Mesh),
        }
    }
}

pub enum ServerStream {
    Direct(tokio::net::TcpStream),
    Mesh(yggstack::netstack::TcpStream),
}

impl AsyncRead for ServerStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_read(cx, buf),
            Self::Mesh(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_write(cx, buf),
            Self::Mesh(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_flush(cx),
            Self::Mesh(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Direct(s) => Pin::new(s).poll_shutdown(cx),
            Self::Mesh(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_mesh_config_has_no_default_listeners() {
        let cfg = mesh_config();
        assert!(cfg.listen.is_empty(), "mesh client must not bind implicit listeners: {:?}", cfg.listen);
        assert_eq!(cfg.admin_listen, "none", "mesh client must not expose an admin socket");
        assert!(cfg.peers.is_empty());
        assert!(cfg.multicast_interfaces.is_empty());
    }

    fn quality(uri: &str, up: bool, latency: Option<u32>, cost: u64) -> PeerQuality {
        PeerQuality {
            uri: uri.to_string(),
            up,
            latency_ms: latency,
            cost,
            rx_rate: 0,
            tx_rate: 0,
            uptime_secs: 60,
            last_error: None,
        }
    }

    #[test]
    fn peer_ranking_prefers_live_and_low_latency() {
        let ranked = rank_peer_quality(vec![
            quality("down", false, None, 1),
            quality("slow", true, Some(80), 80),
            quality("fast", true, Some(10), 10),
        ]);
        let order: Vec<&str> = ranked.iter().map(|peer| peer.uri.as_str()).collect();
        assert_eq!(order, ["fast", "slow", "down"]);
    }

    #[test]
    fn peer_uri_parser_handles_tls_queries_and_bracketed_ipv6() {
        assert_eq!(
            peer_uri_host_port("tls://example.org:443?key=abcd&priority=1"),
            Some(("example.org".to_string(), 443))
        );
        assert_eq!(
            peer_uri_host_port("tcp://[2001:db8::1]:1234"),
            Some(("2001:db8::1".to_string(), 1234))
        );
        assert_eq!(peer_uri_host_port("tls://missing-port"), None);
        assert_eq!(peer_uri_host_port("not-a-peer"), None);
    }
}
