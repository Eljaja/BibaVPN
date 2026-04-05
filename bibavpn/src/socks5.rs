//! Minimal SOCKS5 (no auth, CONNECT only, IPv4 / domain / IPv6).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn socks5_handshake(local: &mut TcpStream) -> anyhow::Result<(String, u16)> {
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
        bail!("bad socks rsv");
    }
    if hdr[1] != 1 {
        bail!("only CONNECT (cmd={}) is supported", hdr[1]);
    }
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

    Ok((host, port))
}

/// SOCKS5 reply: success, bind 0.0.0.0:0
pub async fn socks5_reply_ok(local: &mut TcpStream) -> anyhow::Result<()> {
    const REPLY: &[u8] = &[
        5, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    ];
    local.write_all(REPLY).await.context("socks reply")?;
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
