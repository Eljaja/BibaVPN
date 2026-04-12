//! BibaV2: PSK handshake + ChaCha20-Poly1305 outer framing (inspired by AmneziaWG2 session noise
//! and v2ray-style distinct bidirectional keys). Not compatible with stock WireGuard/Xray.

use anyhow::{bail, Context};
use blake3::derive_key;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;

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

fn transport_keys(
    psk: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut ctx = Vec::with_capacity(psk.len() + 64);
    ctx.extend_from_slice(psk);
    ctx.extend_from_slice(client_random);
    ctx.extend_from_slice(server_random);
    let k_up = derive_key("bibavpn.v2.c2s", &ctx);
    let k_dn = derive_key("bibavpn.v2.s2c", &ctx);
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
        let mut plain = Vec::with_capacity(1 + usize::from(decoy_max) + inner.len());
        let dlen: u8 = if decoy_max == 0 {
            0
        } else {
            rand::thread_rng().gen_range(0..=decoy_max)
        };
        plain.push(dlen);
        if dlen > 0 {
            let mut noise = vec![0u8; usize::from(dlen)];
            OsRng.fill_bytes(&mut noise);
            plain.extend_from_slice(&noise);
        }
        plain.extend_from_slice(inner);

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
            bail!("short v2 packet");
        }
        let (n, ct) = wire.split_at(12);
        let nonce: [u8; 12] = n.try_into().unwrap();
        let pt = self
            .cipher
            .decrypt(&nonce.into(), ct)
            .map_err(|_| anyhow::anyhow!("chacha decrypt"))?;
        strip_decoy(&pt)
    }
}

fn strip_decoy(pt: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if pt.is_empty() {
        bail!("empty plaintext");
    }
    let d = usize::from(pt[0]);
    if pt.len() < 1 + d {
        bail!("bad decoy length");
    }
    Ok(pt[1 + d..].to_vec())
}

/// Bidirectional session keys. Each direction has its own lock so seal/open on different halves
/// can run concurrently (e.g. TCP uplink vs downlink on one tunnel).
pub struct SessionCrypto {
    c2s: tokio::sync::Mutex<ChaHalf>,
    s2c: tokio::sync::Mutex<ChaHalf>,
    pub decoy_max: u8,
}

impl SessionCrypto {
    pub fn new(
        psk: &str,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        decoy_max: u8,
    ) -> Self {
        let (k_up, k_dn) = transport_keys(psk.as_bytes(), client_random, server_random);
        Self {
            c2s: tokio::sync::Mutex::new(ChaHalf::new(&k_up)),
            s2c: tokio::sync::Mutex::new(ChaHalf::new(&k_dn)),
            decoy_max,
        }
    }

    pub async fn seal_client_to_server(&self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut g = self.c2s.lock().await;
        g.seal(self.decoy_max, inner)
    }

    pub async fn open_client_to_server(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let g = self.c2s.lock().await;
        g.open(wire).context("chacha decrypt (c2s)")
    }

    pub async fn seal_server_to_client(&self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut g = self.s2c.lock().await;
        g.seal(self.decoy_max, inner)
    }

    pub async fn open_server_to_client(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let g = self.s2c.lock().await;
        g.open(wire).context("chacha decrypt (s2c)")
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

    #[tokio::test]
    async fn seal_roundtrip_both_dirs() {
        let psk = "unit-test-psk";
        let c = [1u8; 32];
        let s = [2u8; 32];
        let enc = SessionCrypto::new(psk, &c, &s, 8);
        let dec = SessionCrypto::new(psk, &c, &s, 8);
        let inner = b"padded-frame-blob".to_vec();
        let wire = enc.seal_client_to_server(&inner).await.unwrap();
        let out = dec.open_client_to_server(&wire).await.unwrap();
        assert_eq!(out, inner);

        let back = b"server-payload".to_vec();
        let w2 = dec.seal_server_to_client(&back).await.unwrap();
        let out2 = enc.open_server_to_client(&w2).await.unwrap();
        assert_eq!(out2, back);
    }
}
