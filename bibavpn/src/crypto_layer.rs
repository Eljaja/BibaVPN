//! BibaV2: PSK handshake + ChaCha20-Poly1305 outer framing (inspired by AmneziaWG2 session noise
//! and v2ray-style distinct bidirectional keys). Not compatible with stock WireGuard/Xray.

use anyhow::bail;
use blake3::derive_key;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::Rng;
use rand::RngCore;
use rand::rngs::OsRng;

pub const HELLO_MAGIC: &[u8] = b"BIBV2HL1";
pub const ACK_MAGIC: &[u8] = b"BIBV2ACK1";

const MAC_LEN: usize = 16;
pub const HELLO_LEN: usize = HELLO_MAGIC.len() + 32;
pub const ACK_LEN: usize = ACK_MAGIC.len() + 32 + MAC_LEN;

fn mac_psk_key(psk: &[u8]) -> [u8; 32] {
    derive_key("bibavpn.v2.mac.psk", psk)
}

fn compute_mac(psk: &[u8], client_random: &[u8; 32], server_random: &[u8; 32]) -> [u8; MAC_LEN] {
    let key = mac_psk_key(psk);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(client_random);
    h.update(server_random);
    let out = h.finalize();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&out.as_bytes()[..MAC_LEN]);
    tag
}

fn transport_keys(psk: &[u8], client_random: &[u8; 32], server_random: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut ctx = Vec::with_capacity(psk.len() + 64);
    ctx.extend_from_slice(psk);
    ctx.extend_from_slice(client_random);
    ctx.extend_from_slice(server_random);
    let k_up = derive_key("bibavpn.v2.c2s", &ctx);
    let k_dn = derive_key("bibavpn.v2.s2c", &ctx);
    (k_up, k_dn)
}

#[derive(Clone)]
pub struct SessionCrypto {
    c2s: ChaCha20Poly1305,
    s2c: ChaCha20Poly1305,
    ctr_c2s: u64,
    ctr_s2c: u64,
    pub decoy_max: u8,
}

impl SessionCrypto {
    pub fn new(psk: &str, client_random: &[u8; 32], server_random: &[u8; 32], decoy_max: u8) -> Self {
        let (k_up, k_dn) = transport_keys(psk.as_bytes(), client_random, server_random);
        let c2s = ChaCha20Poly1305::new_from_slice(&k_up).expect("32B key");
        let s2c = ChaCha20Poly1305::new_from_slice(&k_dn).expect("32B key");
        Self {
            c2s,
            s2c,
            ctr_c2s: 0,
            ctr_s2c: 0,
            decoy_max,
        }
    }

    fn nonce_c2s(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.ctr_c2s.to_be_bytes());
        self.ctr_c2s = self.ctr_c2s.wrapping_add(1);
        n
    }

    fn nonce_s2c(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.ctr_s2c.to_be_bytes());
        self.ctr_s2c = self.ctr_s2c.wrapping_add(1);
        n
    }

    pub fn seal_client_to_server(&mut self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(1 + usize::from(self.decoy_max) + inner.len());
        let dlen: u8 = if self.decoy_max == 0 {
            0
        } else {
            rand::thread_rng().gen_range(0..=self.decoy_max)
        };
        plain.push(dlen);
        if dlen > 0 {
            let mut noise = vec![0u8; usize::from(dlen)];
            OsRng.fill_bytes(&mut noise);
            plain.extend_from_slice(&noise);
        }
        plain.extend_from_slice(inner);

        let nonce = self.nonce_c2s();
        let ct = self
            .c2s
            .encrypt(&nonce.into(), plain.as_slice())
            .map_err(|e| anyhow::anyhow!("chacha encrypt: {e}"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open_client_to_server(&mut self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        if wire.len() < 12 + 16 {
            bail!("short v2 packet");
        }
        let (n, ct) = wire.split_at(12);
        let nonce: [u8; 12] = n.try_into().unwrap();
        let pt = self
            .c2s
            .decrypt(&nonce.into(), ct)
            .map_err(|_| anyhow::anyhow!("chacha decrypt (c2s)"))?;
        Self::strip_decoy(&pt)
    }

    pub fn seal_server_to_client(&mut self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut plain = Vec::with_capacity(1 + usize::from(self.decoy_max) + inner.len());
        let dlen: u8 = if self.decoy_max == 0 {
            0
        } else {
            rand::thread_rng().gen_range(0..=self.decoy_max)
        };
        plain.push(dlen);
        if dlen > 0 {
            let mut noise = vec![0u8; usize::from(dlen)];
            OsRng.fill_bytes(&mut noise);
            plain.extend_from_slice(&noise);
        }
        plain.extend_from_slice(inner);

        let nonce = self.nonce_s2c();
        let ct = self
            .s2c
            .encrypt(&nonce.into(), plain.as_slice())
            .map_err(|e| anyhow::anyhow!("chacha encrypt: {e}"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open_server_to_client(&mut self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        if wire.len() < 12 + 16 {
            bail!("short v2 packet");
        }
        let (n, ct) = wire.split_at(12);
        let nonce: [u8; 12] = n.try_into().unwrap();
        let pt = self
            .s2c
            .decrypt(&nonce.into(), ct)
            .map_err(|_| anyhow::anyhow!("chacha decrypt (s2c)"))?;
        Self::strip_decoy(&pt)
    }

    fn strip_decoy(pt: &[u8]) -> anyhow::Result<Vec<u8>> {
        if pt.is_empty() {
            bail!("empty plaintext");
        }
        let d = usize::from(pt[0]);
        if pt.len() < 1 + d {
            bail!("bad decoy length");
        }
        Ok(pt[1 + d..].to_vec())
    }
}

pub fn build_hello() -> ([u8; 32], Vec<u8>) {
    let mut c = [0u8; 32];
    OsRng.fill_bytes(&mut c);
    let mut v = Vec::with_capacity(HELLO_LEN);
    v.extend_from_slice(HELLO_MAGIC);
    v.extend_from_slice(&c);
    (c, v)
}

pub fn parse_hello(buf: &[u8]) -> anyhow::Result<[u8; 32]> {
    if buf.len() != HELLO_LEN || !buf.starts_with(HELLO_MAGIC) {
        bail!("bad HELLO");
    }
    let mut c = [0u8; 32];
    c.copy_from_slice(&buf[HELLO_MAGIC.len()..]);
    Ok(c)
}

pub fn build_ack(psk: &str, client_random: &[u8; 32]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    let mac = compute_mac(psk.as_bytes(), client_random, &s);
    let mut v = Vec::with_capacity(ACK_LEN);
    v.extend_from_slice(ACK_MAGIC);
    v.extend_from_slice(&s);
    v.extend_from_slice(&mac);
    Ok((v, s))
}

pub fn parse_ack(psk: &str, buf: &[u8], client_random: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    if buf.len() != ACK_LEN || !buf.starts_with(ACK_MAGIC) {
        bail!("bad ACK");
    }
    let body = &buf[ACK_MAGIC.len()..];
    let (srv, tag) = body.split_at(32);
    let mut s = [0u8; 32];
    s.copy_from_slice(srv);
    let expected = compute_mac(psk.as_bytes(), client_random, &s);
    if tag != expected.as_slice() {
        bail!("ACK mac mismatch");
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_both_dirs() {
        let psk = "unit-test-psk";
        let c = [1u8; 32];
        let s = [2u8; 32];
        let mut enc = SessionCrypto::new(psk, &c, &s, 8);
        let mut dec = SessionCrypto::new(psk, &c, &s, 8);
        let inner = b"padded-frame-blob".to_vec();
        let wire = enc.seal_client_to_server(&inner).unwrap();
        let out = dec.open_client_to_server(&wire).unwrap();
        assert_eq!(out, inner);

        let back = b"server-payload".to_vec();
        let w2 = dec.seal_server_to_client(&back).unwrap();
        let out2 = enc.open_server_to_client(&w2).unwrap();
        assert_eq!(out2, back);
    }
}
