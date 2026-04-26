//! Opening a logical TCP proxy channel: first WebSocket binary message after optional junk.
//! UDP-over-WS: second channel type with v3 `UDP_MUX` opcode then `UDP_REQ` / `UDP_REP` inner frames.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Context;

/// Fixed magic so random junk frames never collide.
pub const OPEN_MAGIC: &[u8] = b"BIBA\x01OPEN\x00";
pub const OPEN_OK_MAGIC: &[u8] = b"BIBA\x01OPOK\x00";
pub const OPEN_ERR_MAGIC: &[u8] = b"BIBA\x01OPER\x00";
const OPEN_EXT_V1: u8 = 1;
pub const OPEN_FLAG_STATUS: u8 = 0x01;

/// Client → server: session token after WebSocket upgrade (auth outside URL path).
pub const AUTH_MAGIC: &[u8] = b"BIBA\x01AUTH\x00";

pub const MAX_UDP_PAYLOAD: usize = 60 * 1024;

// Biba v3 inner control (plaintext inside padded frame, then AEAD on the wire)
pub const V3_CTRL_AUTH: u8 = 0x01;
pub const V3_CTRL_OPEN: u8 = 0x02;
pub const V3_CTRL_UDP_MUX: u8 = 0x03;
pub const V3_CTRL_MUX: u8 = 0x04;
/// Inner plaintext: UDP request (after `UDP_MUX` channel is open).
pub const V3_CTRL_UDP_REQ: u8 = 0x05;
/// Inner plaintext: UDP reply from server.
pub const V3_CTRL_UDP_REP: u8 = 0x06;
pub const V3_CTRL_OPEN_OK: u8 = 0x10;
pub const V3_CTRL_OPEN_ERR: u8 = 0x11;

pub fn encode_auth(token: &str) -> anyhow::Result<Vec<u8>> {
    let t = token.as_bytes();
    if t.len() > 0xffff {
        anyhow::bail!("token too long");
    }
    let mut v = Vec::with_capacity(AUTH_MAGIC.len() + 2 + t.len());
    v.extend_from_slice(AUTH_MAGIC);
    v.extend_from_slice(&(t.len() as u16).to_be_bytes());
    v.extend_from_slice(t);
    Ok(v)
}

pub fn decode_auth(data: &[u8]) -> anyhow::Result<String> {
    if data.len() < AUTH_MAGIC.len() + 2 {
        anyhow::bail!("short auth frame");
    }
    if !data.starts_with(AUTH_MAGIC) {
        anyhow::bail!("not an auth frame");
    }
    let i = AUTH_MAGIC.len();
    let tl = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    if data.len() < i + 2 + tl {
        anyhow::bail!("truncated auth token");
    }
    let s = std::str::from_utf8(&data[i + 2..i + 2 + tl])?.to_string();
    Ok(s)
}

pub fn is_auth_frame(data: &[u8]) -> bool {
    data.len() >= AUTH_MAGIC.len() && data.starts_with(AUTH_MAGIC)
}

pub fn encode_open(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let h = host.as_bytes();
    if h.len() > 0xffff {
        anyhow::bail!("host too long");
    }
    let mut v = Vec::with_capacity(OPEN_MAGIC.len() + 2 + h.len() + 2 + 2);
    v.extend_from_slice(OPEN_MAGIC);
    v.extend_from_slice(&(h.len() as u16).to_be_bytes());
    v.extend_from_slice(h);
    v.extend_from_slice(&port.to_be_bytes());
    // Optional trailer. Older servers ignore trailing bytes after `host:port`.
    v.push(OPEN_EXT_V1);
    v.push(OPEN_FLAG_STATUS);
    Ok(v)
}

fn decode_open_inner(data: &[u8]) -> anyhow::Result<(String, u16, &[u8])> {
    if data.len() < OPEN_MAGIC.len() + 2 + 2 {
        anyhow::bail!("short open frame");
    }
    if !data.starts_with(OPEN_MAGIC) {
        anyhow::bail!("not an open frame");
    }
    let mut i = OPEN_MAGIC.len();
    let hl = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let host = std::str::from_utf8(data.get(i..i + hl).context("host slice")?)?.to_string();
    i += hl;
    if data.len() < i + 2 {
        anyhow::bail!("missing port");
    }
    let port = u16::from_be_bytes([data[i], data[i + 1]]);
    i += 2;
    Ok((host, port, &data[i..]))
}

pub fn decode_open(data: &[u8]) -> anyhow::Result<(String, u16)> {
    let (host, port, _) = decode_open_inner(data)?;
    Ok((host, port))
}

pub fn decode_open_with_flags(data: &[u8]) -> anyhow::Result<(String, u16, u8)> {
    let (host, port, rest) = decode_open_inner(data)?;
    let flags = if rest.len() >= 2 && rest[0] == OPEN_EXT_V1 {
        rest[1]
    } else {
        0
    };
    Ok((host, port, flags))
}

pub fn encode_open_ok() -> Vec<u8> {
    OPEN_OK_MAGIC.to_vec()
}

pub fn is_open_ok(data: &[u8]) -> bool {
    data == OPEN_OK_MAGIC
}

pub fn encode_open_err(reason: &str) -> anyhow::Result<Vec<u8>> {
    let msg = reason.as_bytes();
    if msg.len() > 0xffff {
        anyhow::bail!("open error too long");
    }
    let mut v = Vec::with_capacity(OPEN_ERR_MAGIC.len() + 2 + msg.len());
    v.extend_from_slice(OPEN_ERR_MAGIC);
    v.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    v.extend_from_slice(msg);
    Ok(v)
}

pub fn decode_open_err(data: &[u8]) -> anyhow::Result<String> {
    if data.len() < OPEN_ERR_MAGIC.len() + 2 {
        anyhow::bail!("short open error frame");
    }
    if !data.starts_with(OPEN_ERR_MAGIC) {
        anyhow::bail!("not an open error frame");
    }
    let i = OPEN_ERR_MAGIC.len();
    let ml = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    if data.len() < i + 2 + ml {
        anyhow::bail!("truncated open error");
    }
    Ok(std::str::from_utf8(&data[i + 2..i + 2 + ml])?.to_string())
}

pub(crate) fn encode_atyp_host_port(
    host: &str,
    port: u16,
    buf: &mut Vec<u8>,
) -> anyhow::Result<()> {
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
    let mut v = Vec::with_capacity(1 + 8 + 16 + payload.len());
    v.push(V3_CTRL_UDP_REQ);
    v.extend_from_slice(&xid.to_be_bytes());
    encode_atyp_host_port(host, port, &mut v)?;
    v.extend_from_slice(payload);
    Ok(v)
}

pub fn decode_udp_req(data: &[u8]) -> anyhow::Result<(u64, String, u16, Vec<u8>)> {
    if data.is_empty() || data[0] != V3_CTRL_UDP_REQ {
        anyhow::bail!("bad udp req opcode");
    }
    if data.len() < 1 + 8 {
        anyhow::bail!("short udp req");
    }
    let xid = u64::from_be_bytes(data[1..9].try_into()?);
    let rest = &data[9..];
    let (h, p, addr_len) = decode_atyp_host_port(rest)?;
    let payload = rest[addr_len..].to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        anyhow::bail!("udp req payload too large");
    }
    Ok((xid, h, p, payload))
}

pub fn encode_udp_rep(
    xid: u64,
    src_host: &str,
    src_port: u16,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > MAX_UDP_PAYLOAD {
        anyhow::bail!("UDP payload too large");
    }
    let mut v = Vec::with_capacity(1 + 8 + 16 + payload.len());
    v.push(V3_CTRL_UDP_REP);
    v.extend_from_slice(&xid.to_be_bytes());
    encode_atyp_host_port(src_host, src_port, &mut v)?;
    v.extend_from_slice(payload);
    Ok(v)
}

pub fn decode_udp_rep(data: &[u8]) -> anyhow::Result<(u64, String, u16, Vec<u8>)> {
    if data.is_empty() || data[0] != V3_CTRL_UDP_REP {
        anyhow::bail!("bad udp rep opcode");
    }
    if data.len() < 1 + 8 {
        anyhow::bail!("short udp rep");
    }
    let xid = u64::from_be_bytes(data[1..9].try_into()?);
    let rest = &data[9..];
    let (h, p, addr_len) = decode_atyp_host_port(rest)?;
    let payload = rest[addr_len..].to_vec();
    Ok((xid, h, p, payload))
}

/// SOCKS5 UDP request/response header + payload (RSV+FRAG+ATYP+ADDR+PORT already consumed in parse).
pub fn build_socks5_udp_datagram(
    dest_host: &str,
    dest_port: u16,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
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

pub fn encode_v3_auth(token: &str) -> anyhow::Result<Vec<u8>> {
    let t = token.as_bytes();
    if t.len() > 0xffff {
        anyhow::bail!("token too long");
    }
    let mut v = Vec::with_capacity(1 + 2 + t.len());
    v.push(V3_CTRL_AUTH);
    v.extend_from_slice(&(t.len() as u16).to_be_bytes());
    v.extend_from_slice(t);
    Ok(v)
}

pub fn decode_v3_auth(data: &[u8]) -> anyhow::Result<String> {
    if data.is_empty() || data[0] != V3_CTRL_AUTH {
        anyhow::bail!("not v3 auth");
    }
    if data.len() < 3 {
        anyhow::bail!("short v3 auth");
    }
    let tl = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() < 3 + tl {
        anyhow::bail!("truncated v3 auth");
    }
    Ok(std::str::from_utf8(&data[3..3 + tl])?.to_string())
}

pub fn encode_v3_open(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    encode_v3_open_with_flags(host, port, 0)
}

pub fn encode_v3_open_with_flags(host: &str, port: u16, flags: u8) -> anyhow::Result<Vec<u8>> {
    let h = host.as_bytes();
    if h.len() > 0xffff {
        anyhow::bail!("host too long");
    }
    let mut v = Vec::with_capacity(1 + 2 + h.len() + 2 + 2);
    v.push(V3_CTRL_OPEN);
    v.extend_from_slice(&(h.len() as u16).to_be_bytes());
    v.extend_from_slice(h);
    v.extend_from_slice(&port.to_be_bytes());
    v.push(OPEN_EXT_V1);
    v.push(flags);
    Ok(v)
}

fn decode_v3_open_inner(data: &[u8]) -> anyhow::Result<(String, u16, u8, &[u8])> {
    if data.is_empty() || data[0] != V3_CTRL_OPEN {
        anyhow::bail!("not v3 open");
    }
    if data.len() < 1 + 2 + 2 {
        anyhow::bail!("short v3 open");
    }
    let mut i = 1usize;
    let hl = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let host = std::str::from_utf8(data.get(i..i + hl).context("host slice")?)?.to_string();
    i += hl;
    if data.len() < i + 2 {
        anyhow::bail!("missing port");
    }
    let port = u16::from_be_bytes([data[i], data[i + 1]]);
    i += 2;
    let flags = if data.len() >= i + 2 && data[i] == OPEN_EXT_V1 {
        data[i + 1]
    } else {
        0
    };
    Ok((host, port, flags, &data[i..]))
}

pub fn decode_v3_open(data: &[u8]) -> anyhow::Result<(String, u16)> {
    let (h, p, _, _) = decode_v3_open_inner(data)?;
    Ok((h, p))
}

pub fn decode_v3_open_with_flags(data: &[u8]) -> anyhow::Result<(String, u16, u8)> {
    let (h, p, f, _) = decode_v3_open_inner(data)?;
    Ok((h, p, f))
}

pub fn encode_v3_udp_mux_open() -> Vec<u8> {
    vec![V3_CTRL_UDP_MUX]
}

pub fn is_v3_udp_mux_open(data: &[u8]) -> bool {
    data == [V3_CTRL_UDP_MUX]
}

pub fn encode_v3_mux_open() -> Vec<u8> {
    vec![V3_CTRL_MUX]
}

pub fn is_v3_mux_open(data: &[u8]) -> bool {
    data == [V3_CTRL_MUX]
}

pub fn encode_v3_open_ok() -> Vec<u8> {
    vec![V3_CTRL_OPEN_OK]
}

pub fn is_v3_open_ok(data: &[u8]) -> bool {
    data == [V3_CTRL_OPEN_OK]
}

pub fn encode_v3_open_err(reason: &str) -> anyhow::Result<Vec<u8>> {
    let msg = reason.as_bytes();
    if msg.len() > 0xffff {
        anyhow::bail!("open error too long");
    }
    let mut v = Vec::with_capacity(1 + 2 + msg.len());
    v.push(V3_CTRL_OPEN_ERR);
    v.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    v.extend_from_slice(msg);
    Ok(v)
}

pub fn decode_v3_open_err(data: &[u8]) -> anyhow::Result<String> {
    if data.len() < 3 || data[0] != V3_CTRL_OPEN_ERR {
        anyhow::bail!("not v3 open err");
    }
    let ml = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() < 3 + ml {
        anyhow::bail!("truncated v3 open err");
    }
    Ok(std::str::from_utf8(&data[3..3 + ml])?.to_string())
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn auth_roundtrip() {
        let t = "secret-token-xyz";
        let b = encode_auth(t).unwrap();
        assert_eq!(decode_auth(&b).unwrap(), t);
    }
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
