//! PSK handshake + ChaCha20-Poly1305 outer framing (v3 domain-separated keys).

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context};
use blake3::derive_key;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use subtle::ConstantTimeEq;

/// First byte of Biba v3 opaque client hello (after WS noise/junk).
pub const V3_HELLO_TAG: u8 = 0x03;

/// Trailing random padding length is 0..=this (byte stored after client_random).
pub const V3_HELLO_PAD_MAX: u8 = 64;
/// Same for server ACK after MAC.
pub const V3_ACK_PAD_MAX: u8 = 64;

/// Minimum v3 HELLO: tag + client_random + pad_len byte (+ optional pad).
pub const V3_HELLO_MIN_WIRE_LEN: usize = 1 + 32 + 1;

const MAC_LEN: usize = 16;

/// Compare a received secret (token, password, MAC) against the expected one without
/// leaking how many leading bytes matched.
///
/// Only the content comparison is constant time. The length check short-circuits, so the
/// length of `got` relative to `expected` is still observable; secret lengths are not hidden.
pub fn secret_eq(got: impl AsRef<[u8]>, expected: impl AsRef<[u8]>) -> bool {
    let got = got.as_ref();
    let expected = expected.as_ref();
    got.len() == expected.len() && got.ct_eq(expected).into()
}

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
    reality_dh: Option<&[u8; 32]>,
) -> ([u8; 32], [u8; 32]) {
    let d = domain.as_bytes();
    let mut ctx = Vec::with_capacity(4 + psk.len() + 4 + d.len() + 64 + 4 + 32);
    ctx.extend_from_slice(&(psk.len() as u32).to_be_bytes());
    ctx.extend_from_slice(psk);
    ctx.extend_from_slice(&(d.len() as u32).to_be_bytes());
    ctx.extend_from_slice(d);
    ctx.extend_from_slice(client_random);
    ctx.extend_from_slice(server_random);
    if let Some(dh) = reality_dh {
        ctx.extend_from_slice(&(32u32).to_be_bytes());
        ctx.extend_from_slice(dh);
    }
    let k_up = derive_key("bibavpn.v3.c2s", &ctx);
    let k_dn = derive_key("bibavpn.v3.s2c", &ctx);
    (k_up, k_dn)
}

struct ChaHalf {
    cipher: ChaCha20Poly1305,
    ctr: AtomicU64,
}

impl ChaHalf {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(key).expect("32B key"),
            ctr: AtomicU64::new(0),
        }
    }

    fn next_nonce(&self) -> [u8; 12] {
        let c = self.ctr.fetch_add(1, Ordering::Relaxed);
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&c.to_be_bytes());
        n
    }

    fn seal(&self, decoy_max: u8, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
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

/// Bidirectional session keys. Each direction uses a lock-free nonce counter; seal/open are `Sync`.
pub struct SessionCrypto {
    c2s: ChaHalf,
    s2c: ChaHalf,
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
        let (k_up, k_dn) =
            transport_keys(psk.as_bytes(), domain, client_random, server_random, None);
        Self {
            c2s: ChaHalf::new(&k_up),
            s2c: ChaHalf::new(&k_dn),
            decoy_max,
        }
    }

    /// REALITY + v3 PSK: transport keys also bind the X25519 shared secret from the REALITY handshake.
    pub fn new_with_reality_dh(
        psk: &str,
        domain: &str,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        reality_dh: &[u8; 32],
        decoy_max: u8,
    ) -> Self {
        let (k_up, k_dn) = transport_keys(
            psk.as_bytes(),
            domain,
            client_random,
            server_random,
            Some(reality_dh),
        );
        Self {
            c2s: ChaHalf::new(&k_up),
            s2c: ChaHalf::new(&k_dn),
            decoy_max,
        }
    }

    pub fn seal_client_to_server(&self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.c2s.seal(self.decoy_max, inner)
    }

    pub fn open_client_to_server(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.c2s.open(wire).context("chacha decrypt (c2s)")
    }

    pub fn seal_server_to_client(&self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.s2c.seal(self.decoy_max, inner)
    }

    pub fn open_server_to_client(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.s2c.open(wire).context("chacha decrypt (s2c)")
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
    // Constant-time compare: avoid leaking how many leading bytes matched.
    if tag.ct_ne(expected.as_slice()).into() {
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
    fn secret_eq_accepts_equal_and_rejects_everything_else() {
        assert!(secret_eq("token-abc", "token-abc"));
        assert!(secret_eq(&b"token-abc"[..], "token-abc"));
        // Same length, different content.
        assert!(!secret_eq("token-abc", "token-abd"));
        assert!(!secret_eq("Token-abc", "token-abc"));
        // Different lengths (prefix and suffix cases).
        assert!(!secret_eq("token-ab", "token-abc"));
        assert!(!secret_eq("token-abcd", "token-abc"));
    }

    #[test]
    fn secret_eq_empty_inputs() {
        assert!(secret_eq("", ""));
        assert!(secret_eq(&b""[..], ""));
        assert!(!secret_eq("", "token"));
        assert!(!secret_eq("token", ""));
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

    #[test]
    fn corrupt_ciphertext_fails_open() {
        let psk = "psk";
        let c = [1u8; 32];
        let s = [2u8; 32];
        let enc = SessionCrypto::new(psk, "dom", &c, &s, 0);
        let mut wire = enc.seal_client_to_server(b"x").unwrap();
        if let Some(b) = wire.last_mut() {
            *b ^= 0xff;
        }
        assert!(enc.open_client_to_server(&wire).is_err());
    }

    #[test]
    fn wrong_psk_fails_ack_mac() {
        let (c, hello) = build_hello_v3();
        let psk = "correct-psk";
        let dom = "dom";
        let (ack, _) = build_ack(psk, dom, &c).unwrap();
        assert!(parse_hello_v3(&hello).is_ok());
        assert!(parse_ack("wrong-psk", dom, &ack, &c).is_err());
        assert!(parse_ack(psk, "other.domain", &ack, &c).is_err());
    }

    #[test]
    fn decoy_max_zero_means_no_noise_bytes() {
        let psk = "psk";
        let c = [5u8; 32];
        let s = [6u8; 32];
        let enc = SessionCrypto::new(psk, "dom", &c, &s, 0);
        let wire = enc.seal_client_to_server(b"plain").unwrap();
        let plain = enc.open_client_to_server(&wire).unwrap();
        assert_eq!(plain, b"plain");
    }

    #[test]
    fn reality_dh_changes_keys() {
        let psk = "same-psk";
        let c = [3u8; 32];
        let s = [4u8; 32];
        let dom = "reality.example";
        let dh_a = [0x11u8; 32];
        let dh_b = [0x22u8; 32];
        let a = SessionCrypto::new_with_reality_dh(psk, dom, &c, &s, &dh_a, 0);
        let b = SessionCrypto::new_with_reality_dh(psk, dom, &c, &s, &dh_b, 0);
        let inner = b"payload".to_vec();
        let w = a.seal_client_to_server(&inner).unwrap();
        assert!(b.open_client_to_server(&w).is_err());
        let w2 = a.seal_server_to_client(&inner).unwrap();
        assert!(b.open_server_to_client(&w2).is_err());
    }

    #[test]
    fn reality_dh_same_roundtrip() {
        let psk = "unit-test-psk";
        let c = [1u8; 32];
        let s = [2u8; 32];
        let dom = "test.domain";
        let dh = [0xabu8; 32];
        let enc = SessionCrypto::new_with_reality_dh(psk, dom, &c, &s, &dh, 8);
        let dec = SessionCrypto::new_with_reality_dh(psk, dom, &c, &s, &dh, 8);
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
    fn reality_dh_vs_psk_only_mismatch() {
        let psk = "psk";
        let c = [5u8; 32];
        let s = [6u8; 32];
        let dom = "dom";
        let dh = [0xccu8; 32];
        let with_dh = SessionCrypto::new_with_reality_dh(psk, dom, &c, &s, &dh, 0);
        let psk_only = SessionCrypto::new(psk, dom, &c, &s, 0);
        let inner = b"x".to_vec();
        let w = with_dh.seal_client_to_server(&inner).unwrap();
        assert!(psk_only.open_client_to_server(&w).is_err());
        let w2 = psk_only.seal_client_to_server(&inner).unwrap();
        assert!(with_dh.open_client_to_server(&w2).is_err());
    }

    #[test]
    fn concurrent_c2s_seals_open_correctly() {
        let psk = "c-test";
        let c = [9u8; 32];
        let s = [8u8; 32];
        let enc = std::sync::Arc::new(SessionCrypto::new(psk, "d", &c, &s, 0));
        std::thread::scope(|sc| {
            for _ in 0..32 {
                let enc = enc.clone();
                sc.spawn(move || {
                    for _ in 0..64 {
                        let inner: Vec<u8> = rand::random::<[u8; 16]>().to_vec();
                        let wire = enc.seal_client_to_server(&inner).unwrap();
                        let out = enc.open_client_to_server(&wire).unwrap();
                        assert_eq!(out, inner);
                    }
                });
            }
        });
    }
}
