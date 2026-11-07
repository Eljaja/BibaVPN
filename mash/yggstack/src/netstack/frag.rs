//! IPv6 Fragment Extension Header reassembly.
//!
//! smoltcp (0.11) does not reassemble IPv6 fragments for `Medium::Ip`.
//! We reassemble them ourselves before feeding packets to smoltcp.
//!
//! RFC 2460 / RFC 8200 IPv6 Fragment Header layout (after IPv6 header):
//!   byte 0: Next Header (protocol of the reassembled payload)
//!   byte 1: Reserved
//!   bytes 2-3: Fragment Offset (bits 15:3) | Res (bits 2:1) | M (bit 0)
//!   bytes 4-7: Identification (32-bit)

use std::collections::HashMap;
use std::time::{Duration, Instant};

const FRAG_TIMEOUT: Duration = Duration::from_secs(60);
const IPV6_HEADER_LEN: usize = 40;
const FRAG_EXT_LEN: usize = 8;

#[derive(Hash, Eq, PartialEq, Clone)]
struct FragKey {
    src: [u8; 16],
    dst: [u8; 16],
    identification: u32,
}

struct FragSlot {
    next_header: u8,
    src: [u8; 16],
    dst: [u8; 16],
    total_len: Option<usize>,
    received: usize,
    buf: Vec<u8>,    // reassembly buffer (payload only, no headers)
    created: Instant,
}

pub struct FragReassembler {
    slots: HashMap<FragKey, FragSlot>,
}

impl FragReassembler {
    pub fn new() -> Self {
        Self { slots: HashMap::new() }
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Feed an incoming IPv6 packet.  Returns:
    /// - `None`  — packet is a fragment, not yet complete (or malformed)
    /// - `Some(pkt)` — reassembled packet ready to deliver (or non-fragment pass-through)
    pub fn feed(&mut self, pkt: Vec<u8>) -> Option<Vec<u8>> {
        self.evict_expired();

        // Minimal sanity: at least a full IPv6 header.
        if pkt.len() < IPV6_HEADER_LEN {
            return Some(pkt);
        }

        // IPv6 next header field is at byte 6.
        let next_hdr = pkt[6];
        if next_hdr != 44 {
            // Not a fragment — pass through unchanged.
            return Some(pkt);
        }

        // Need room for the fragment extension header too.
        if pkt.len() < IPV6_HEADER_LEN + FRAG_EXT_LEN {
            tracing::debug!("IPv6 fragment: packet too short, dropping");
            return None;
        }

        let fh = &pkt[IPV6_HEADER_LEN..IPV6_HEADER_LEN + FRAG_EXT_LEN];
        let frag_next_header = fh[0];
        let offset_and_m = u16::from_be_bytes([fh[2], fh[3]]);
        let frag_offset = (offset_and_m >> 3) as usize * 8; // in bytes
        let more_fragments = (offset_and_m & 0x01) != 0;
        let identification = u32::from_be_bytes([fh[4], fh[5], fh[6], fh[7]]);

        let src: [u8; 16] = pkt[8..24].try_into().unwrap();
        let dst: [u8; 16] = pkt[24..40].try_into().unwrap();

        // Payload = everything after the fragment extension header.
        let payload = &pkt[IPV6_HEADER_LEN + FRAG_EXT_LEN..];
        let payload_len = payload.len();

        let key = FragKey { src, dst, identification };
        let slot = self.slots.entry(key.clone()).or_insert_with(|| FragSlot {
            next_header: frag_next_header,
            src,
            dst,
            total_len: None,
            received: 0,
            buf: vec![0u8; 65535],
            created: Instant::now(),
        });

        // Write fragment payload into the reassembly buffer.
        let end = frag_offset + payload_len;
        if end > slot.buf.len() {
            tracing::debug!("IPv6 frag: exceeds reassembly buffer, dropping id={:#010x}", identification);
            self.slots.remove(&key);
            return None;
        }
        slot.buf[frag_offset..end].copy_from_slice(payload);
        slot.received += payload_len;

        if !more_fragments {
            slot.total_len = Some(end);
        }

        // Check if complete.
        match slot.total_len {
            Some(total) if slot.received >= total => {
                let slot = self.slots.remove(&key).unwrap();
                Some(build_reassembled(slot.src, slot.dst, slot.next_header, &slot.buf[..total]))
            }
            _ => None,
        }
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.slots.retain(|_, s| now.duration_since(s.created) < FRAG_TIMEOUT);
    }
}

impl Default for FragReassembler {
    fn default() -> Self {
        Self::new()
    }
}

fn build_reassembled(src: [u8; 16], dst: [u8; 16], next_header: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = IPV6_HEADER_LEN + payload.len();
    let mut pkt = vec![0u8; total_len];
    // Version=6, Traffic Class=0, Flow Label=0
    pkt[0] = 0x60;
    // Payload length (16-bit big-endian)
    let plen = payload.len() as u16;
    pkt[4] = (plen >> 8) as u8;
    pkt[5] = plen as u8;
    // Next Header
    pkt[6] = next_header;
    // Hop limit — use a reasonable default
    pkt[7] = 64;
    // Source and destination
    pkt[8..24].copy_from_slice(&src);
    pkt[24..40].copy_from_slice(&dst);
    // Payload
    pkt[IPV6_HEADER_LEN..].copy_from_slice(payload);
    pkt
}
