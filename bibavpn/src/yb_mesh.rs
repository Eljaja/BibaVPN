//! Yggdrasil transport for reaching a Biba server without its public IP.
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use yggdrasil::{core::Core, ipv6rwc::ReadWriteCloser};
use yggstack::{config, netstack::YggNetstack};

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

/// A userspace IPv6 stack backed by one Yggdrasil node.
pub struct MeshNode {
    core: Arc<Core>,
    pub netstack: Arc<YggNetstack>,
    peer_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
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
        let peer_core = core.clone();
        let peer_task = tokio::spawn(async move {
            for peer in peers {
                if let Err(error) = peer_core.add_peer(&peer).await {
                    tracing::warn!(%peer, %error, "could not register mesh peer");
                }
            }
        });
        Ok(Self { core, netstack, peer_task: std::sync::Mutex::new(Some(peer_task)) })
    }

    pub async fn connected_peers(&self) -> usize {
        self.core.get_peers().await.into_iter().filter(|peer| peer.up).count()
    }

    pub async fn shutdown(&self) {
        if let Some(task) = self.peer_task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        self.netstack.shutdown().await;
        let _ = self.core.close().await;
    }
}

impl Drop for MeshNode {
    fn drop(&mut self) {
        if let Some(task) = self.peer_task.lock().unwrap_or_else(|e| e.into_inner()).take() {
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
}
