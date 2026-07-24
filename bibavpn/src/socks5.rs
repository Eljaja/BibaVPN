//! Minimal SOCKS5 (optional RFC 1929 user/pass, CONNECT and UDP ASSOCIATE, IPv4 / domain / IPv6).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto_layer::secret_eq;

const SOCKS5_AUTH_NONE: u8 = 0;
const SOCKS5_AUTH_USERPASS: u8 = 2;

async fn socks5_negotiate_method(local: &mut TcpStream, require_userpass: bool) -> anyhow::Result<()> {
    let mut buf = [0u8; 2];
    local.read_exact(&mut buf).await.context("socks version")?;
    if buf[0] != 5 {
        bail!("unsupported socks version {}", buf[0]);
    }
    let nmethods = buf[1] as usize;
    if nmethods == 0 {
        bail!("socks nmethods=0");
    }
    let mut methods = vec![0u8; nmethods];
    local.read_exact(&mut methods).await.context("methods")?;

    let method = if require_userpass {
        if !methods.contains(&SOCKS5_AUTH_USERPASS) {
            let _ = local.write_all(&[5u8, 0xFF]).await;
            bail!("socks client did not offer username/password (method 2)");
        }
        SOCKS5_AUTH_USERPASS
    } else if methods.contains(&SOCKS5_AUTH_NONE) {
        SOCKS5_AUTH_NONE
    } else {
        let _ = local.write_all(&[5u8, 0xFF]).await;
        bail!("socks client did not offer no-auth (method 0)");
    };

    local
        .write_all(&[5u8, method])
        .await
        .context("socks method reply")?;
    Ok(())
}

/// Both comparisons always run and are constant time, so a wrong username is not
/// distinguishable from a wrong password by timing.
fn socks5_userpass_ok(
    uname: &[u8],
    passwd: &[u8],
    expected_user: &str,
    expected_pass: &str,
) -> bool {
    let user_ok = secret_eq(uname, expected_user);
    let pass_ok = secret_eq(passwd, expected_pass);
    user_ok & pass_ok
}

async fn socks5_userpass_verify(
    local: &mut TcpStream,
    expected_user: &str,
    expected_pass: &str,
) -> anyhow::Result<()> {
    let mut ver = [0u8; 1];
    local.read_exact(&mut ver).await.context("rfc1929 ver")?;
    if ver[0] != 1 {
        bail!("RFC1929 version {} (expected 1)", ver[0]);
    }
    let mut ulen = [0u8; 1];
    local.read_exact(&mut ulen).await.context("ulen")?;
    let ulen = ulen[0] as usize;
    let mut uname = vec![0u8; ulen];
    local.read_exact(&mut uname).await.context("uname")?;
    let mut plen = [0u8; 1];
    local.read_exact(&mut plen).await.context("plen")?;
    let plen = plen[0] as usize;
    let mut passwd = vec![0u8; plen];
    local.read_exact(&mut passwd).await.context("passwd")?;

    let ok = socks5_userpass_ok(&uname, &passwd, expected_user, expected_pass);
    if ok {
        local.write_all(&[1u8, 0u8]).await.context("rfc1929 ok")?;
        Ok(())
    } else {
        let _ = local.write_all(&[1u8, 1u8]).await;
        bail!("SOCKS5 username/password rejected");
    }
}

/// SOCKS5 command after method negotiation.
#[derive(Debug)]
pub enum SocksCommand {
    Connect {
        host: String,
        port: u16,
    },
    /// BND in reply is where the client must send UDP datagrams.
    UdpAssociate {
        host: String,
        port: u16,
    },
}

async fn socks5_read_connect_request(local: &mut TcpStream) -> anyhow::Result<SocksCommand> {
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

/// Full SOCKS5 handshake: method negotiation, optional RFC 1929, then CONNECT / UDP ASSOCIATE request.
///
/// `auth`: when `Some((user, pass))` with non-empty strings, only username/password auth is accepted
/// (method 2); no-auth is not offered by the server path.
pub async fn socks5_read_command(
    local: &mut TcpStream,
    auth: Option<&(String, String)>,
) -> anyhow::Result<SocksCommand> {
    let creds = auth.filter(|(u, p)| !u.is_empty() && !p.is_empty());
    let require_userpass = creds.is_some();
    socks5_negotiate_method(local, require_userpass).await?;
    if let Some((u, p)) = creds {
        socks5_userpass_verify(local, u, p).await?;
    }
    socks5_read_connect_request(local).await
}

/// Backward-compatible: CONNECT only, same as before.
pub async fn socks5_handshake(local: &mut TcpStream) -> anyhow::Result<(String, u16)> {
    match socks5_read_command(local, None).await? {
        SocksCommand::Connect { host, port } => Ok((host, port)),
        SocksCommand::UdpAssociate { .. } => bail!("UDP ASSOCIATE requires socks5_read_command"),
    }
}

/// SOCKS5 reply: success, bind 0.0.0.0:0
pub async fn socks5_reply_ok(local: &mut TcpStream) -> anyhow::Result<()> {
    const REPLY: &[u8] = &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    local.write_all(REPLY).await.context("socks reply")?;
    Ok(())
}

/// Reply to UDP ASSOCIATE: relay is reachable at `local_addr` of this control connection
/// (fallback `127.0.0.1` if the listener was bound to an unspecified address).
pub async fn socks5_reply_udp_associate(
    local: &mut TcpStream,
    relay_port: u16,
) -> anyhow::Result<()> {
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
    local
        .write_all(&reply)
        .await
        .context("socks udp associate reply")?;
    Ok(())
}

pub async fn socks5_reply_err(local: &mut TcpStream) -> anyhow::Result<()> {
    const REPLY: &[u8] = &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0];
    let _ = local.write_all(REPLY).await;
    Ok(())
}

/// Parse target for testing without full SOCKS (used by direct forward tests).
#[allow(dead_code)]
pub fn socket_addr_for_test(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    Ok(format!("{host}:{port}").parse()?)
}

/// True when the peer opened TCP then closed before completing the SOCKS5 handshake
/// (port probes, reachability checks, or clients that never send a version byte).
pub fn is_benign_handshake_abort(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}");
    if !msg.contains("early eof") {
        return false;
    }
    msg.contains("socks version")
        || msg.contains("methods")
        || msg.contains("request hdr")
        || msg.contains("rfc1929 ver")
        || msg.contains("ulen")
        || msg.contains("uname")
        || msg.contains("plen")
        || msg.contains("passwd")
}

#[cfg(test)]
mod tests {
    use super::{is_benign_handshake_abort, socks5_userpass_ok};
    use anyhow::Context;

    #[test]
    fn userpass_ok_only_for_both_correct() {
        assert!(socks5_userpass_ok(b"user", b"pass", "user", "pass"));
        assert!(!socks5_userpass_ok(b"user", b"wrong", "user", "pass"));
        assert!(!socks5_userpass_ok(b"wrong", b"pass", "user", "pass"));
        assert!(!socks5_userpass_ok(b"wrong", b"wrong", "user", "pass"));
        // Length mismatches (prefix of the expected value must not pass).
        assert!(!socks5_userpass_ok(b"use", b"pass", "user", "pass"));
        assert!(!socks5_userpass_ok(b"user", b"pas", "user", "pass"));
        assert!(!socks5_userpass_ok(b"", b"", "user", "pass"));
    }

    #[test]
    fn benign_abort_detects_version_eof() {
        let err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "early eof");
        let err = Err::<(), _>(err).context("socks version").unwrap_err();
        assert!(is_benign_handshake_abort(&err));
    }

    #[test]
    fn benign_abort_rejects_real_failures() {
        let err = anyhow::anyhow!("unsupported socks version 4");
        assert!(!is_benign_handshake_abort(&err));
    }
}
