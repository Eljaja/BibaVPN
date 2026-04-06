//! Opening a logical TCP proxy channel: first WebSocket binary message after optional junk.
//! UDP-over-WS: second channel type with `UDP_MUX_OPEN` then `UDP_REQ` / `UDP_REP` datagrams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;

/// Fixed magic so random junk frames never collide.
pub const OPEN_MAGIC: &[u8] = b"BIBA\x01OPEN\x00";

/// Opens a WebSocket session that carries UDP datagrams (same TLS+WSS envelope as TCP tun).
pub const UDP_MUX_OPEN_MAGIC: &[u8] = b"BIBA\x01UDPM\x00";

/// Client → server: one logical UDP payload toward `host:port`.
pub const UDP_REQ_MAGIC: &[u8] = b"BIBA\x01UDPR\x00";

/// Server → client: reply `payload` from `host:port` (source of the UDP packet).
pub const UDP_REP_MAGIC: &[u8] = b"BIBA\x01UDPQ\x00";

pub const MAX_UDP_PAYLOAD: usize = 60 * 1024;

pub fn encode_open(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let h = host.as_bytes();
    if h.len() > 0xffff {
        anyhow::bail!("host too long");
    }
    let mut v = Vec::with_capacity(OPEN_MAGIC.len() + 2 + h.len() + 2);
    v.extend_from_slice(OPEN_MAGIC);
    v.extend_from_slice(&(h.len() as u16).to_be_bytes());
    v.extend_from_slice(h);
    v.extend_from_slice(&port.to_be_bytes());
    Ok(v)
}

pub fn decode_open(data: &[u8]) -> anyhow::Result<(String, u16)> {
    if data.len() < OPEN_MAGIC.len() + 2 + 2 {
        anyhow::bail!("short open frame");
    }
    if !data.starts_with(OPEN_MAGIC) {
        anyhow::bail!("not an open frame");
    }
    let mut i = OPEN_MAGIC.len();
    let hl = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let host =
        std::str::from_utf8(data.get(i..i + hl).context("host slice")?)?.to_string();
    i += hl;
    if data.len() < i + 2 {
        anyhow::bail!("missing port");
    }
    let port = u16::from_be_bytes([data[i], data[i + 1]]);
    Ok((host, port))
}

pub fn encode_udp_mux_open() -> Vec<u8> {
    UDP_MUX_OPEN_MAGIC.to_vec()
}

pub fn is_udp_mux_open(data: &[u8]) -> bool {
    data == UDP_MUX_OPEN_MAGIC
}

pub(crate) fn encode_atyp_host_port(host: &str, port: u16, buf: &mut Vec<u8>) -> anyhow::Result<()> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        buf.push(1);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        buf.push(4);
        buf.extend_from_slice(&ip.octets());
    } else {
        let b = host.as_bytes();
        if b.len() > u8::MAX as usize {
            anyhow::bail!("host too long");
        }
        buf.push(3);
        buf.push(b.len() as u8);
        buf.extend_from_slice(b);
    }
    buf.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Returns `(host, port, total_prefix_len)` for the ATYP|addr|port prefix.
pub(crate) fn decode_atyp_host_port(data: &[u8]) -> anyhow::Result<(String, u16, usize)> {
    if data.is_empty() {
        anyhow::bail!("empty addr");
    }
    let atyp = data[0];
    let (host, end_addr) = match atyp {
        1 => {
            if data.len() < 1 + 4 + 2 {
                anyhow::bail!("short ipv4");
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            (ip.to_string(), 1 + 4)
        }
        3 => {
            if data.len() < 2 {
                anyhow::bail!("short domain");
            }
            let l = data[1] as usize;
            if data.len() < 2 + l + 2 {
                anyhow::bail!("short domain host");
            }
            let h = std::str::from_utf8(&data[2..2 + l])?.to_string();
            (h, 2 + l)
        }
        4 => {
            if data.len() < 1 + 16 + 2 {
                anyhow::bail!("short ipv6");
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&data[1..17]);
            (IpAddr::V6(Ipv6Addr::from(a)).to_string(), 17)
        }
        _ => anyhow::bail!("bad ATYP {atyp}"),
    };
    let port = u16::from_be_bytes([data[end_addr], data[end_addr + 1]]);
    Ok((host, port, end_addr + 2))
}

pub fn encode_udp_req(xid: u64, host: &str, port: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > MAX_UDP_PAYLOAD {
        anyhow::bail!("UDP payload too large");
    }
    let mut v = Vec::with_capacity(UDP_REQ_MAGIC.len() + 8 + 16 + payload.len());
    v.extend_from_slice(UDP_REQ_MAGIC);
    v.extend_from_slice(&xid.to_be_bytes());
    encode_atyp_host_port(host, port, &mut v)?;
    v.extend_from_slice(payload);
    Ok(v)
}

pub fn decode_udp_req(data: &[u8]) -> anyhow::Result<(u64, String, u16, Vec<u8>)> {
    let i0 = UDP_REQ_MAGIC.len() + 8;
    if data.len() < i0 {
        anyhow::bail!("short udp req");
    }
    if !data.starts_with(UDP_REQ_MAGIC) {
        anyhow::bail!("bad udp req magic");
    }
    let xid = u64::from_be_bytes(data[UDP_REQ_MAGIC.len()..UDP_REQ_MAGIC.len() + 8].try_into()?);
    let rest = &data[UDP_REQ_MAGIC.len() + 8..];
    let (h, p, addr_len) = decode_atyp_host_port(rest)?;
    let payload = rest[addr_len..].to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        anyhow::bail!("udp req payload too large");
    }
    Ok((xid, h, p, payload))
}

pub fn encode_udp_rep(xid: u64, src_host: &str, src_port: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.len() > MAX_UDP_PAYLOAD {
        anyhow::bail!("UDP payload too large");
    }
    let mut v = Vec::with_capacity(UDP_REP_MAGIC.len() + 8 + 16 + payload.len());
    v.extend_from_slice(UDP_REP_MAGIC);
    v.extend_from_slice(&xid.to_be_bytes());
    encode_atyp_host_port(src_host, src_port, &mut v)?;
    v.extend_from_slice(payload);
    Ok(v)
}

pub fn decode_udp_rep(data: &[u8]) -> anyhow::Result<(u64, String, u16, Vec<u8>)> {
    let i0 = UDP_REP_MAGIC.len() + 8;
    if data.len() < i0 {
        anyhow::bail!("short udp rep");
    }
    if !data.starts_with(UDP_REP_MAGIC) {
        anyhow::bail!("bad udp rep magic");
    }
    let xid = u64::from_be_bytes(data[UDP_REP_MAGIC.len()..UDP_REP_MAGIC.len() + 8].try_into()?);
    let rest = &data[UDP_REP_MAGIC.len() + 8..];
    let (h, p, addr_len) = decode_atyp_host_port(rest)?;
    let payload = rest[addr_len..].to_vec();
    Ok((xid, h, p, payload))
}

/// SOCKS5 UDP request/response header + payload (RSV+FRAG+ATYP+ADDR+PORT already consumed in parse).
pub fn build_socks5_udp_datagram(dest_host: &str, dest_port: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut v = vec![0u8, 0, 0];
    encode_atyp_host_port(dest_host, dest_port, &mut v)?;
    v.extend_from_slice(payload);
    Ok(v)
}

/// Parse SOCKS5 UDP framing (RSV, FRAG, ATYP … DATA).
pub fn parse_socks5_udp_datagram(data: &[u8]) -> anyhow::Result<(String, u16, Vec<u8>)> {
    if data.len() < 4 {
        anyhow::bail!("short socks udp");
    }
    if data[0] != 0 || data[1] != 0 {
        anyhow::bail!("bad RSV");
    }
    if data[2] != 0 {
        anyhow::bail!("UDP fragment not supported");
    }
    let (h, p, n) = decode_atyp_host_port(&data[3..])?;
    Ok((h, p, data[3 + n..].to_vec()))
}

#[cfg(test)]
mod udp_tests {
    use super::*;

    #[test]
    fn udp_req_rep_roundtrip() {
        let p = encode_udp_req(0x1122_3344_5566_7788, "example.com", 443, b"abc").unwrap();
        let (xid, h, port, pl) = decode_udp_req(&p).unwrap();
        assert_eq!(xid, 0x1122_3344_5566_7788);
        assert_eq!(h, "example.com");
        assert_eq!(port, 443);
        assert_eq!(pl, b"abc");

        let q = encode_udp_rep(xid, "1.2.3.4", 53, &pl).unwrap();
        let (x2, sh, sp, pl2) = decode_udp_rep(&q).unwrap();
        assert_eq!(x2, xid);
        assert_eq!(sh, "1.2.3.4");
        assert_eq!(sp, 53);
        assert_eq!(pl2, pl);
    }
}
