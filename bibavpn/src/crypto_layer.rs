//! PSK handshake + ChaCha20-Poly1305 outer framing (v3 domain-separated keys).

use std::sync::Mutex;

use anyhow::{bail, Context};
use blake3::derive_key;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;

/// First byte of Biba v3 opaque client hello (after WS noise/junk).
pub const V3_HELLO_TAG: u8 = 0x03;

/// Trailing random padding length is 0..=this (byte stored after client_random).
pub const V3_HELLO_PAD_MAX: u8 = 64;
/// Same for server ACK after MAC.
pub const V3_ACK_PAD_MAX: u8 = 64;

/// Minimum v3 HELLO: tag + client_random + pad_len byte (+ optional pad).
pub const V3_HELLO_MIN_WIRE_LEN: usize = 1 + 32 + 1;

const MAC_LEN: usize = 16;

fn mac_psk_key_v3(psk: &[u8], domain: &str) -> [u8; 32] {
    let d = domain.as_bytes();
    let mut buf = Vec::with_capacity(4 + psk.len() + 4 + d.len());
    buf.extend_from_slice(&(psk.len() as u32).to_be_bytes());
    buf.extend_from_slice(psk);
    buf.extend_from_slice(&(d.len() as u32).to_be_bytes());
    buf.extend_from_slice(d);
    derive_key("bibavpn.v3.mac.psk", &buf)
}

fn compute_mac(
    psk: &[u8],
    domain: &str,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; MAC_LEN] {
    let key = mac_psk_key_v3(psk, domain);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(client_random);
    h.update(server_random);
    let out = h.finalize();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&out.as_bytes()[..MAC_LEN]);
    tag
}

fn transport_keys(
    psk: &[u8],
    domain: &str,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let d = domain.as_bytes();
    let mut ctx = Vec::with_capacity(4 + psk.len() + 4 + d.len() + 64);
    ctx.extend_from_slice(&(psk.len() as u32).to_be_bytes());
    ctx.extend_from_slice(psk);
    ctx.extend_from_slice(&(d.len() as u32).to_be_bytes());
    ctx.extend_from_slice(d);
    ctx.extend_from_slice(client_random);
    ctx.extend_from_slice(server_random);
    let k_up = derive_key("bibavpn.v3.c2s", &ctx);
    let k_dn = derive_key("bibavpn.v3.s2c", &ctx);
    (k_up, k_dn)
}

struct ChaHalf {
    cipher: ChaCha20Poly1305,
    ctr: u64,
}

impl ChaHalf {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(key).expect("32B key"),
            ctr: 0,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.ctr.to_be_bytes());
        self.ctr = self.ctr.wrapping_add(1);
        n
    }

    fn seal(&mut self, decoy_max: u8, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        let plain = if decoy_max == 0 {
            let mut v = Vec::with_capacity(1 + inner.len());
            v.push(0u8);
            v.extend_from_slice(inner);
            v
        } else {
            let mut plain = Vec::with_capacity(1 + usize::from(decoy_max) + inner.len());
            let dlen: u8 = rand::thread_rng().gen_range(0..=decoy_max);
            plain.push(dlen);
            if dlen > 0 {
                let mut noise = vec![0u8; usize::from(dlen)];
                OsRng.fill_bytes(&mut noise);
                plain.extend_from_slice(&noise);
            }
            plain.extend_from_slice(inner);
            plain
        };

        let nonce = self.next_nonce();
        let ct = self
            .cipher
            .encrypt(&nonce.into(), plain.as_slice())
            .map_err(|e| anyhow::anyhow!("chacha encrypt: {e}"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        if wire.len() < 12 + 16 {
            bail!("short outer packet");
        }
        let (n, ct) = wire.split_at(12);
        let nonce: [u8; 12] = n.try_into().unwrap();
        let pt = self
            .cipher
            .decrypt(&nonce.into(), ct)
            .map_err(|_| anyhow::anyhow!("chacha decrypt"))?;
        strip_decoy(pt)
    }
}

/// Drop outer decoy prefix in place (one allocation from decrypt, no extra copy).
fn strip_decoy(mut pt: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
    if pt.is_empty() {
        bail!("empty plaintext");
    }
    let d = usize::from(pt[0]);
    if pt.len() < 1 + d {
        bail!("bad decoy length");
    }
    pt.drain(..1 + d);
    Ok(pt)
}

/// Bidirectional session keys. Each direction has its own `std::sync::Mutex` so seal/open stay
/// **synchronous** (no fake `async` / tokio mutex on the hot path). Uplink and downlink use
/// different mutexes and can run in parallel on different threads/tasks.
pub struct SessionCrypto {
    c2s: Mutex<ChaHalf>,
    s2c: Mutex<ChaHalf>,
    pub decoy_max: u8,
}

impl SessionCrypto {
    pub fn new(
        psk: &str,
        domain: &str,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        decoy_max: u8,
    ) -> Self {
        let (k_up, k_dn) = transport_keys(psk.as_bytes(), domain, client_random, server_random);
        Self {
            c2s: Mutex::new(ChaHalf::new(&k_up)),
            s2c: Mutex::new(ChaHalf::new(&k_dn)),
            decoy_max,
        }
    }

    pub fn seal_client_to_server(&self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut g = self.c2s.lock().expect("session crypto mutex poisoned");
        g.seal(self.decoy_max, inner)
    }

    pub fn open_client_to_server(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let g = self.c2s.lock().expect("session crypto mutex poisoned");
        g.open(wire).context("chacha decrypt (c2s)")
    }

    pub fn seal_server_to_client(&self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut g = self.s2c.lock().expect("session crypto mutex poisoned");
        g.seal(self.decoy_max, inner)
    }

    pub fn open_server_to_client(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let g = self.s2c.lock().expect("session crypto mutex poisoned");
        g.open(wire).context("chacha decrypt (s2c)")
    }
}

/// Wire: `[V3_HELLO_TAG][client_random:32][pad_len:u8][random padding]`.
pub fn build_hello_v3() -> ([u8; 32], Vec<u8>) {
    let mut c = [0u8; 32];
    OsRng.fill_bytes(&mut c);
    let pad_len: u8 = rand::thread_rng().gen_range(0..=V3_HELLO_PAD_MAX);
    let mut pad = vec![0u8; pad_len as usize];
    OsRng.fill_bytes(&mut pad);
    let mut v = Vec::with_capacity(V3_HELLO_MIN_WIRE_LEN + pad.len());
    v.push(V3_HELLO_TAG);
    v.extend_from_slice(&c);
    v.push(pad_len);
    v.extend_from_slice(&pad);
    (c, v)
}

pub fn parse_hello_v3(buf: &[u8]) -> anyhow::Result<[u8; 32]> {
    if buf.len() < V3_HELLO_MIN_WIRE_LEN || buf[0] != V3_HELLO_TAG {
        bail!("bad v3 HELLO");
    }
    let pad_len = buf[33] as usize;
    if pad_len > V3_HELLO_PAD_MAX as usize {
        bail!("bad v3 HELLO pad len");
    }
    if buf.len() != V3_HELLO_MIN_WIRE_LEN + pad_len {
        bail!("bad v3 HELLO length");
    }
    let mut c = [0u8; 32];
    c.copy_from_slice(&buf[1..33]);
    Ok(c)
}

/// Wire: `[server_random:32][mac:16][pad_len:u8][random padding]`.
pub fn build_ack(psk: &str, domain: &str, client_random: &[u8; 32]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    let mac = compute_mac(psk.as_bytes(), domain, client_random, &s);
    let pad_len: u8 = rand::thread_rng().gen_range(0..=V3_ACK_PAD_MAX);
    let mut pad = vec![0u8; pad_len as usize];
    OsRng.fill_bytes(&mut pad);
    let mut v = Vec::with_capacity(32 + MAC_LEN + 1 + pad.len());
    v.extend_from_slice(&s);
    v.extend_from_slice(&mac);
    v.push(pad_len);
    v.extend_from_slice(&pad);
    Ok((v, s))
}

pub fn parse_ack(
    psk: &str,
    domain: &str,
    buf: &[u8],
    client_random: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    if buf.len() < 32 + MAC_LEN + 1 {
        bail!("bad v3 ACK length");
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&buf[..32]);
    let tag = &buf[32..32 + MAC_LEN];
    let pad_len = buf[32 + MAC_LEN] as usize;
    if pad_len > V3_ACK_PAD_MAX as usize {
        bail!("bad v3 ACK pad len");
    }
    let expect_len = 32 + MAC_LEN + 1 + pad_len;
    if buf.len() != expect_len {
        bail!("bad v3 ACK length");
    }
    let expected = compute_mac(psk.as_bytes(), domain, client_random, &s);
    if tag != expected.as_slice() {
        bail!("ACK mac mismatch");
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_hello_ack_roundtrip() {
        let (c, hello) = build_hello_v3();
        assert_eq!(parse_hello_v3(&hello).unwrap(), c);
        let psk = "psk";
        let dom = "dom.example";
        let (ack, s) = build_ack(psk, dom, &c).unwrap();
        let s2 = parse_ack(psk, dom, &ack, &c).unwrap();
        assert_eq!(s2, s);
    }

    #[test]
    fn seal_roundtrip_both_dirs() {
        let psk = "unit-test-psk";
        let c = [1u8; 32];
        let s = [2u8; 32];
        let dom = "test.domain";
        let enc = SessionCrypto::new(psk, dom, &c, &s, 8);
        let dec = SessionCrypto::new(psk, dom, &c, &s, 8);
        let inner = b"padded-frame-blob".to_vec();
        let wire = enc.seal_client_to_server(&inner).unwrap();
        let out = dec.open_client_to_server(&wire).unwrap();
        assert_eq!(out, inner);

        let back = b"server-payload".to_vec();
        let w2 = dec.seal_server_to_client(&back).unwrap();
        let out2 = enc.open_server_to_client(&w2).unwrap();
        assert_eq!(out2, back);
    }

    #[test]
    fn v3_domain_changes_keys() {
        let psk = "same-psk";
        let c = [3u8; 32];
        let s = [4u8; 32];
        let a = SessionCrypto::new(psk, "a.example", &c, &s, 0);
        let b = SessionCrypto::new(psk, "b.example", &c, &s, 0);
        let inner = b"payload".to_vec();
        let w = a.seal_client_to_server(&inner).unwrap();
        assert!(b.open_client_to_server(&w).is_err());
    }
}
