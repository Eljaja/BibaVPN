//! Minimal SOCKS5 (no auth, CONNECT and UDP ASSOCIATE, IPv4 / domain / IPv6).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 command after method negotiation.
#[derive(Debug)]
pub enum SocksCommand {
    Connect { host: String, port: u16 },
    /// BND in reply is where the client must send UDP datagrams.
    UdpAssociate { host: String, port: u16 },
}

pub async fn socks5_read_command(local: &mut TcpStream) -> anyhow::Result<SocksCommand> {
    let mut buf = [0u8; 2];
    local.read_exact(&mut buf).await.context("socks version")?;
    if buf[0] != 5 {
        bail!("unsupported socks version {}", buf[0]);
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    local.read_exact(&mut methods).await.context("methods")?;
    local.write_all(&[5u8, 0u8]).await.context("socks no auth")?;

    let mut hdr = [0u8; 4];
    local.read_exact(&mut hdr).await.context("request hdr")?;
    if hdr[0] != 5 {
        bail!("bad SOCKS version in request (expected 5)");
    }
    let cmd = hdr[1];
    if hdr[2] != 0 {
        bail!("non-zero RSV");
    }

    let atyp = hdr[3];
    let host = match atyp {
        1 => {
            let mut a = [0u8; 4];
            local.read_exact(&mut a).await?;
            IpAddr::V4(Ipv4Addr::from(a)).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            local.read_exact(&mut l).await?;
            let len = l[0] as usize;
            let mut domain = vec![0u8; len];
            local.read_exact(&mut domain).await?;
            std::str::from_utf8(&domain)?.to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            local.read_exact(&mut a).await?;
            IpAddr::V6(Ipv6Addr::from(a)).to_string()
        }
        _ => bail!("unsupported ATYP {}", atyp),
    };

    let mut p = [0u8; 2];
    local.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    match cmd {
        1 => Ok(SocksCommand::Connect { host, port }),
        3 => Ok(SocksCommand::UdpAssociate { host, port }),
        _ => bail!("unsupported SOCKS cmd {cmd}"),
    }
}

/// Backward-compatible: CONNECT only, same as before.
pub async fn socks5_handshake(local: &mut TcpStream) -> anyhow::Result<(String, u16)> {
    match socks5_read_command(local).await? {
        SocksCommand::Connect { host, port } => Ok((host, port)),
        SocksCommand::UdpAssociate { .. } => bail!("UDP ASSOCIATE requires socks5_read_command"),
    }
}

/// SOCKS5 reply: success, bind 0.0.0.0:0
pub async fn socks5_reply_ok(local: &mut TcpStream) -> anyhow::Result<()> {
    const REPLY: &[u8] = &[
        5, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    ];
    local.write_all(REPLY).await.context("socks reply")?;
    Ok(())
}

/// Reply to UDP ASSOCIATE: relay is reachable at `local_addr` of this control connection
/// (fallback `127.0.0.1` if the listener was bound to an unspecified address).
pub async fn socks5_reply_udp_associate(local: &mut TcpStream, relay_port: u16) -> anyhow::Result<()> {
    let sock_ip = match local.local_addr().context("socks local_addr")? {
        SocketAddr::V4(v4) => {
            if v4.ip().is_unspecified() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V4(*v4.ip())
            }
        }
        SocketAddr::V6(v6) => {
            if v6.ip().is_unspecified() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(*v6.ip())
            }
        }
    };

    let mut reply = vec![5u8, 0, 0];
    match sock_ip {
        IpAddr::V4(ip) => {
            reply.push(1);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(4);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&relay_port.to_be_bytes());
    local.write_all(&reply).await.context("socks udp associate reply")?;
    Ok(())
}

pub async fn socks5_reply_err(local: &mut TcpStream) -> anyhow::Result<()> {
    const REPLY: &[u8] = &[
        5, 1, 0, 1, 0, 0, 0, 0, 0, 0,
    ];
    let _ = local.write_all(REPLY).await;
    Ok(())
}

/// Parse target for testing without full SOCKS (used by direct forward tests).
#[allow(dead_code)]
pub fn socket_addr_for_test(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    Ok(format!("{host}:{port}").parse()?)
}
