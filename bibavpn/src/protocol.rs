//! Opening a logical TCP proxy channel: first WebSocket binary message after optional junk.

use anyhow::Context;

/// Fixed magic so random junk frames never collide.
pub const OPEN_MAGIC: &[u8] = b"BIBA\x01OPEN\x00";

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
