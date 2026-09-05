//! PSK handshake + ChaCha20-Poly1305 outer framing (v3 domain-separated keys).

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context};
use blake3::derive_key;
use bytes::Bytes;
#[cfg(test)]
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
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
        self.seal_with(decoy_max, inner.len(), |out| out.extend_from_slice(inner))
    }

    fn seal_with(
        &self,
        decoy_max: u8,
        inner_len: usize,
        append: impl FnOnce(&mut Vec<u8>),
    ) -> anyhow::Result<Vec<u8>> {
        let dlen = if decoy_max == 0 {
            0
        } else {
            rand::thread_rng().gen_range(0..=decoy_max)
        };
        let nonce = self.next_nonce();
        // One allocation, including space for the detached tag. Fill decoy directly
        // in its final location rather than allocating temporary random scratch.
        let mut out = Vec::with_capacity(12 + 1 + usize::from(dlen) + inner_len + 16);
        out.extend_from_slice(&nonce);
        out.push(dlen);
        out.resize(13 + usize::from(dlen), 0);
        if dlen != 0 {
            rand::thread_rng().fill_bytes(&mut out[13..]);
        }
        append(&mut out);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce.into(), b"", &mut out[12..])
            .map_err(|e| anyhow::anyhow!("chacha encrypt: {e}"))?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypt in place; return the payload range without sliding nonce/decoy bytes.
    fn open_range(&self, wire: &mut [u8]) -> anyhow::Result<std::ops::Range<usize>> {
        if wire.len() < 12 + 16 {
            bail!("short outer packet");
        }
        let nonce: [u8; 12] = wire[..12].try_into().unwrap();
        let end = wire.len() - 16;
        let tag: [u8; 16] = wire[end..].try_into().unwrap();
        self.cipher
            .decrypt_in_place_detached(&nonce.into(), b"", &mut wire[12..end], &tag.into())
            .map_err(|_| anyhow::anyhow!("chacha decrypt"))?;
        if end == 12 {
            bail!("empty plaintext");
        }
        let start = 13 + usize::from(wire[12]);
        if start > end {
            bail!("bad decoy length");
        }
        Ok(start..end)
    }

    fn open_owned(&self, mut wire: Vec<u8>) -> anyhow::Result<Bytes> {
        let payload = self.open_range(&mut wire)?;
        Ok(Bytes::from(wire).slice(payload))
    }

    fn open(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = wire.to_vec();
        let payload = self.open_range(&mut out)?;
        out.truncate(payload.end);
        out.drain(..payload.start);
        Ok(out)
    }
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
        let (k_up, k_dn) = transport_keys(psk.as_bytes(), domain, client_random, server_random);
        Self {
            c2s: ChaHalf::new(&k_up),
            s2c: ChaHalf::new(&k_dn),
            decoy_max,
        }
    }

    pub(crate) fn seal_frame(
        &self,
        client: bool,
        frame: &crate::frame::PreparedFrame<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let half = if client { &self.c2s } else { &self.s2c };
        half.seal_with(self.decoy_max, frame.wire_len(), |out| frame.append_to(out))
    }

    pub fn seal_client_to_server(&self, inner: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.c2s.seal(self.decoy_max, inner)
    }

    pub fn open_client_to_server(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.c2s.open(wire).context("chacha decrypt (c2s)")
    }

    /// Consume a wire buffer and decrypt without moving its payload. The returned
    /// slice retains the full input allocation; bounded queues must account for it.
    pub fn open_client_to_server_owned(&self, wire: Vec<u8>) -> anyhow::Result<Bytes> {
        self.c2s.open_owned(wire).context("chacha decrypt (c2s)")
    }

    /// See [`Self::open_client_to_server_owned`] for backing-allocation ownership.
    pub fn open_server_to_client_owned(&self, wire: Vec<u8>) -> anyhow::Result<Bytes> {
        self.s2c.open_owned(wire).context("chacha decrypt (s2c)")
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
pub fn build_ack(
    psk: &str,
    domain: &str,
    client_random: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
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

    // Build the old encrypt(plain) wire independently from the in-place implementation.
    fn legacy_wire(cipher: &ChaCha20Poly1305, plain: &[u8]) -> Vec<u8> {
        let nonce = [37u8; 12];
        let mut wire = nonce.to_vec();
        wire.extend(cipher.encrypt(&nonce.into(), plain).unwrap());
        wire
    }

    #[test]
    fn owned_open_matches_legacy_layout_without_moving_payload() {
        let half = ChaHalf::new(&[17; 32]);
        for decoy in [0usize, 1, 255] {
            for payload in [&b""[..], &b"legacy payload"[..]] {
                let mut plain = vec![91; 1 + decoy];
                plain[0] = decoy as u8;
                plain.extend_from_slice(payload);
                let wire = legacy_wire(&half.cipher, &plain);
                let start = wire.as_ptr().wrapping_add(12 + 1 + decoy);
                let opened = half.open_owned(wire).unwrap();
                assert_eq!(opened.as_ref(), payload);
                if !payload.is_empty() {
                    assert_eq!(opened.as_ptr(), start, "prefix removal must only slice");
                }
            }
        }
    }

    #[test]
    fn fused_seal_keeps_final_allocation_and_legacy_wire() {
        use crate::frame::{PadMode, PreparedFrame};
        let half = ChaHalf::new(&[17; 32]);
        let payload = vec![0x47; 65536];
        let header = [0, 0, 0, 19, 2, 0, 1, 0, 0];
        for mode in [PadMode::Random, PadMode::Adaptive, PadMode::HttpBuckets] {
            for max_pad in [0, 255] {
                let parts: &[&[u8]] = &[&header, &payload];
                let frame = PreparedFrame::new(parts, max_pad, mode, None).unwrap();
                let mut pointer = std::ptr::null();
                let wire = half
                    .seal_with(255, frame.wire_len(), |out| {
                        pointer = out.as_ptr();
                        frame.append_to(out);
                        assert_eq!(out.as_ptr(), pointer);
                    })
                    .unwrap();
                assert_eq!(wire.as_ptr(), pointer, "AEAD/tag must not reallocate");
                let nonce: [u8; 12] = wire[..12].try_into().unwrap();
                let plain = half.cipher.decrypt(&nonce.into(), &wire[12..]).unwrap();
                let raw = &plain[1 + plain[0] as usize..];
                assert_eq!(&raw[..4], &[1, 1, 0, 9]);
                assert!(raw[4] <= max_pad);
                assert_eq!(&raw[5 + raw[4] as usize..][..9], &header);
                assert_eq!(&raw[14 + raw[4] as usize..], payload.as_slice());
                for at in [0, 12, wire.len() / 2, wire.len() - 1] {
                    let mut bad = wire.clone();
                    bad[at] ^= 1;
                    assert!(half.open_owned(bad).is_err());
                }
            }
        }
    }

    #[test]
    fn new_seal_is_readable_by_legacy_aead() {
        let half = ChaHalf::new(&[17; 32]);
        for decoy in [0, 255] {
            for payload in [&b""[..], &b"new payload"[..]] {
                let wire = half.seal(decoy, payload).unwrap();
                let nonce: [u8; 12] = wire[..12].try_into().unwrap();
                let plain = half.cipher.decrypt(&nonce.into(), &wire[12..]).unwrap();
                assert!(plain[0] <= decoy);
                assert_eq!(&plain[1 + usize::from(plain[0])..], payload);
            }
        }
    }

    #[test]
    fn owned_open_rejects_malformed_prefix_and_tampering() {
        let half = ChaHalf::new(&[17; 32]);
        for plain in [&b""[..], &[1][..], &[255, 9][..]] {
            assert!(half.open_owned(legacy_wire(&half.cipher, plain)).is_err());
        }
        for n in 0..28 {
            assert!(half.open_owned(vec![0; n]).is_err());
        }
        let original = legacy_wire(&half.cipher, b"\0ok");
        for i in 0..original.len() {
            let mut wire = original.clone();
            wire[i] ^= 1;
            assert!(half.open_owned(wire).is_err(), "tamper byte {i}");
        }
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
