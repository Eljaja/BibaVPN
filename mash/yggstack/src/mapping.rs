/// Port-forwarding specification parser.
///
/// Supported formats (mirroring the Go yggstack):
///   local-tcp / local-udp:
///     `<local-port>:<remote-ygg-addr>:<remote-port>`
///     `<local-addr>:<local-port>:<remote-ygg-addr>:<remote-port>`
///
///   remote-tcp / remote-udp:
///     `<port>`                    – same port locally and remotely
///     `<remote-port>:<local-port>`
///     `<remote-port>:<local-addr>:<local-port>`
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

#[derive(Debug, Clone)]
pub struct TcpMapping {
    pub listen: SocketAddr,
    pub target: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct UdpMapping {
    pub listen: SocketAddr,
    pub target: SocketAddr,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    // handles "[::1]:1234" and "1.2.3.4:1234" and "host:1234"
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some((sa.ip().to_string(), sa.port()));
    }
    // fallback: last colon separates host:port
    let colon = s.rfind(':')?;
    let host = s[..colon].trim_matches(|c| c == '[' || c == ']').to_string();
    let port: u16 = s[colon + 1..].parse().ok()?;
    Some((host, port))
}

/// Parse a mapping spec that may contain an IPv6 address.
/// The tricky part is that IPv6 addresses contain `:`, so we have to be smart.
///
/// For local-{tcp,udp}:
///   tokens split on `:` – if we find `[…]` we strip brackets.
///
/// Returns (local_addr, local_port, remote_addr, remote_port)
fn parse_mapping(value: &str) -> Result<(Option<String>, u16, String, u16), String> {
    // Strategy: parse right-to-left.
    // Last element = remote port (numeric)
    // Then walk back looking for an IPv6 `[…]` or plain IPv4/hostname
    // Then the remaining left side is the local spec.

    let s = value;

    // Find the remote port (last colon-separated token that is pure digits)
    let rport_start = s
        .rfind(':')
        .ok_or_else(|| format!("malformed mapping '{}'", s))?;
    let remote_port: u16 = s[rport_start + 1..]
        .parse()
        .map_err(|_| format!("invalid port in '{}'", s))?;
    let rest = &s[..rport_start];

    // Find remote address (IPv6 in brackets or plain hostname/IPv4)
    let (remote_addr, rest) = if rest.ends_with(']') {
        // IPv6 address
        let bracket_start = rest
            .rfind('[')
            .ok_or_else(|| format!("unmatched '[' in '{}'", s))?;
        let addr = rest[bracket_start + 1..rest.len() - 1].to_string();
        let before = rest[..bracket_start].trim_end_matches(':');
        (addr, before)
    } else {
        // hostname or IPv4: last segment before the next colon
        let colon = rest.rfind(':').ok_or_else(|| {
            // No colon left → the entire rest is the remote address (2-token spec)
            String::new()
        });
        match colon {
            Ok(pos) => {
                let addr = rest[pos + 1..].to_string();
                let before = rest[..pos].trim_end_matches(':');
                (addr, before)
            }
            Err(_) => {
                // 2-token form: <local-port>:<remote-addr>:<remote-port> but we
                // already consumed remote-port; what remains must be:
                // <local-port> : <remote-addr>  → but that was split above.
                // Actually this means rest IS the remote addr, local is empty.
                (rest.to_string(), "")
            }
        }
    };

    if remote_addr.is_empty() {
        return Err(format!("missing remote address in '{}'", s));
    }

    // Validate remote is an IPv6 address (yggdrasil requirement)
    if !remote_addr.contains(':') {
        return Err(format!(
            "remote address '{}' must be an IPv6 address (Yggdrasil)",
            remote_addr
        ));
    }

    // Parse local side
    let (local_addr, local_port) = if rest.is_empty() {
        (None, remote_port) // same port locally
    } else if let Some((h, p)) = parse_host_port(rest) {
        // e.g. "0.0.0.0:8080" or just "8080"
        if h.is_empty() {
            (None, p)
        } else {
            (Some(h), p)
        }
    } else {
        let p: u16 = rest
            .parse()
            .map_err(|_| format!("invalid local spec '{}' in '{}'", rest, s))?;
        (None, p)
    };

    Ok((local_addr, local_port, remote_addr, remote_port))
}

/// Parse a remote forwarding spec:
///   `<port>`
///   `<remote-port>:<local-port>`
///   `<remote-port>:<local-addr>:<local-port>`
fn parse_remote_mapping(value: &str) -> Result<(u16, Option<String>, u16), String> {
    let parts: Vec<&str> = value.splitn(3, ':').collect();
    match parts.len() {
        1 => {
            let port: u16 = parts[0]
                .parse()
                .map_err(|_| format!("invalid port '{}'", parts[0]))?;
            Ok((port, None, port))
        }
        2 => {
            let rport: u16 = parts[0]
                .parse()
                .map_err(|_| format!("invalid port '{}'", parts[0]))?;
            let lport: u16 = parts[1]
                .parse()
                .map_err(|_| format!("invalid port '{}'", parts[1]))?;
            Ok((rport, None, lport))
        }
        3 => {
            // <remote-port>:<local-addr>:<local-port>  OR
            // <remote-port>:[ipv6addr]:port  – handle via the last colon trick
            let rport: u16 = parts[0]
                .parse()
                .map_err(|_| format!("invalid port '{}'", parts[0]))?;
            // Re-parse the rest as host:port
            let rest = &value[parts[0].len() + 1..];
            let (host, lport) = parse_host_port(rest)
                .ok_or_else(|| format!("invalid local spec '{}' in '{}'", rest, value))?;
            Ok((rport, Some(host), lport))
        }
        _ => Err(format!("too many tokens in '{}'", value)),
    }
}

// ── Public constructors ───────────────────────────────────────────────────────

impl TcpMapping {
    /// Parse a local-tcp spec.
    pub fn parse_local(value: &str) -> Result<Self, String> {
        let (local_addr, local_port, remote_addr, remote_port) = parse_mapping(value)?;

        let listen_ip: IpAddr = match &local_addr {
            Some(a) => a.parse().map_err(|_| format!("invalid address '{}'", a))?,
            None => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        };

        let remote_ip: Ipv6Addr = remote_addr
            .parse()
            .map_err(|_| format!("invalid IPv6 '{}'", remote_addr))?;

        Ok(TcpMapping {
            listen: SocketAddr::new(listen_ip, local_port),
            target: SocketAddr::V6(SocketAddrV6::new(remote_ip, remote_port, 0, 0)),
        })
    }

    /// Parse a remote-tcp spec.
    pub fn parse_remote(value: &str) -> Result<Self, String> {
        let (remote_port, local_addr, local_port) = parse_remote_mapping(value)?;

        let local_ip: IpAddr = match &local_addr {
            Some(a) => a.parse().map_err(|_| format!("invalid address '{}'", a))?,
            None => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };

        Ok(TcpMapping {
            // For remote-tcp: listen on our Yggdrasil addr (filled in at startup)
            // We use 0.0.0.0:remote_port as a placeholder; the netstack will
            // bind on our actual Yggdrasil IPv6 address.
            listen: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), remote_port),
            target: SocketAddr::new(local_ip, local_port),
        })
    }
}

impl UdpMapping {
    /// Parse a local-udp spec.
    pub fn parse_local(value: &str) -> Result<Self, String> {
        let (local_addr, local_port, remote_addr, remote_port) = parse_mapping(value)?;

        let listen_ip: IpAddr = match &local_addr {
            Some(a) => a.parse().map_err(|_| format!("invalid address '{}'", a))?,
            None => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        };

        let remote_ip: Ipv6Addr = remote_addr
            .parse()
            .map_err(|_| format!("invalid IPv6 '{}'", remote_addr))?;

        Ok(UdpMapping {
            listen: SocketAddr::new(listen_ip, local_port),
            target: SocketAddr::V6(SocketAddrV6::new(remote_ip, remote_port, 0, 0)),
        })
    }

    /// Parse a remote-udp spec.
    pub fn parse_remote(value: &str) -> Result<Self, String> {
        let (remote_port, local_addr, local_port) = parse_remote_mapping(value)?;

        let local_ip: IpAddr = match &local_addr {
            Some(a) => a.parse().map_err(|_| format!("invalid address '{}'", a))?,
            None => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };

        Ok(UdpMapping {
            listen: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), remote_port),
            target: SocketAddr::new(local_ip, local_port),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_tcp_basic() {
        let m = TcpMapping::parse_local("8080:[200:1:2:3:4:5:6:7]:80").unwrap();
        assert_eq!(m.listen.port(), 8080);
        assert_eq!(m.target.port(), 80);
    }

    #[test]
    fn test_local_udp_basic() {
        let m = UdpMapping::parse_local("553:[200:1:2:3:4:5:6:7]:53").unwrap();
        assert_eq!(m.listen.port(), 553);
        assert_eq!(m.target.port(), 53);
    }

    #[test]
    fn test_remote_tcp_port_only() {
        let m = TcpMapping::parse_remote("22").unwrap();
        assert_eq!(m.listen.port(), 22);
        assert_eq!(m.target.port(), 22);
    }
}
