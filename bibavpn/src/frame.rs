use std::str::FromStr;

use rand::{Rng, RngCore};

const FRAME_VER: u8 = 1;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Per-connection counter for BibaV4 **adaptive** padding (first bursts, then smaller frames).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdaptivePadState {
    /// Incremented for each **inner** padded frame sent on this WebSocket.
    pub count: u32,
}

/// Padding strategy for inner frames (wire format unchanged).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PadMode {
    Random,
    /// Pad total inner frame size toward common HTTP response lengths.
    HttpBuckets,
    /// BibaV4: mimic HTTP/2-style bursts (first ~7 frames target ~900–1400 B total inner size, then smaller).
    #[default]
    Adaptive,
}

impl FromStr for PadMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(
            match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
                "" | "adaptive" => PadMode::Adaptive,
                "random" => PadMode::Random,
                "http-buckets" | "buckets" => PadMode::HttpBuckets,
                other => anyhow::bail!(
                    "unknown pad-mode {other:?}: use adaptive, random, or http-buckets"
                ),
            },
        )
    }
}

const HTTP_BUCKETS: &[usize] = &[
    128, 256, 512, 1024, 1460, 2048, 4096, 8192, 16384, 32768, 65536,
];

/// Default cap for one WebSocket binary message (fewer frames = higher throughput; lower if middleboxes break).
pub const DEFAULT_MAX_WS_BINARY: usize = 262_144;

/// Worst-case plaintext (TCP chunk) per tunnel frame so sealed WS binary ≤ `max_ws_binary`.
/// For plain mode: one WS binary = padded frame only. For BibaV2: includes ChaChaPoly nonce+tag and inner decoy prefix.
pub fn max_tcp_payload_per_ws_message(
    v2: bool,
    decoy_max: u8,
    max_pad: u8,
    max_ws_binary: usize,
) -> usize {
    if max_ws_binary < 48 {
        return 0;
    }
    if !v2 {
        let overhead = 5usize.saturating_add(usize::from(max_pad));
        return max_ws_binary.saturating_sub(overhead);
    }
    let fixed = 29usize
        .saturating_add(usize::from(decoy_max))
        .saturating_add(5)
        .saturating_add(usize::from(max_pad));
    max_ws_binary.saturating_sub(fixed)
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("protocol: {0}")]
    Proto(String),
    #[error("payload too large")]
    TooLarge,
}

/// On-wire (inside one WebSocket binary message):
/// `[ver u8][payload_len u24 BE][pad_len u8][pad * pad_len][payload * payload_len]`
pub fn write_padded_frame(
    buf: &mut Vec<u8>,
    payload: &[u8],
    max_pad: u8,
) -> Result<(), FrameError> {
    write_padded_frame_with_mode(buf, payload, max_pad, PadMode::Random)
}

/// Same as [`write_padded_frame`] with selectable padding distribution (no adaptive session state).
pub fn write_padded_frame_with_mode(
    buf: &mut Vec<u8>,
    payload: &[u8],
    max_pad: u8,
    mode: PadMode,
) -> Result<(), FrameError> {
    write_padded_frame_with_mode_state(buf, payload, max_pad, mode, None)
}

/// Padded frame with optional [`AdaptivePadState`] for [`PadMode::Adaptive`]. Pass `None` to use
/// burst-size targets without a monotonic frame index (suitable for one-off control frames).
pub fn write_padded_frame_with_mode_state(
    buf: &mut Vec<u8>,
    payload: &[u8],
    max_pad: u8,
    mode: PadMode,
    adaptive: Option<&mut AdaptivePadState>,
) -> Result<(), FrameError> {
    let parts = [payload];
    let frame = PreparedFrame::new(&parts, max_pad, mode, adaptive)?;
    buf.clear();
    frame.append_to(buf);
    Ok(())
}

/// Validated scatter/gather input; append directly into the final encryption buffer.
pub(crate) struct PreparedFrame<'a> {
    parts: &'a [&'a [u8]],
    len: usize,
    pad_len: u8,
}

impl<'a> PreparedFrame<'a> {
    pub(crate) fn new(
        parts: &'a [&'a [u8]],
        max_pad: u8,
        mode: PadMode,
        adaptive: Option<&mut AdaptivePadState>,
    ) -> Result<Self, FrameError> {
        let len = parts
            .iter()
            .try_fold(0usize, |n, part| n.checked_add(part.len()))
            .ok_or(FrameError::TooLarge)?;
        if len > MAX_PAYLOAD || len > 0xFF_FFFF {
            return Err(FrameError::TooLarge);
        }
        let base = 5usize.saturating_add(len);
        let pad_len: u8 = if max_pad == 0 {
            0
        } else {
            let mut rng = rand::thread_rng();
            match mode {
                PadMode::Random => rng.gen_range(0..=max_pad),
                PadMode::HttpBuckets => {
                    let mut target = HTTP_BUCKETS
                        .iter()
                        .copied()
                        .find(|&b| b >= base)
                        .unwrap_or(*HTTP_BUCKETS.last().unwrap_or(&base));
                    let j = rng.gen_range(95u16..=105u16);
                    target = (target.saturating_mul(j as usize) / 100).max(base);
                    let need = target.saturating_sub(base).min(usize::from(max_pad));
                    need as u8
                }
                PadMode::Adaptive => {
                    let target_total = if let Some(st) = adaptive {
                        let c = st.count;
                        st.count = st.count.saturating_add(1);
                        if c < 7 {
                            rng.gen_range(900usize..=1400)
                        } else {
                            rng.gen_range(128usize..=512)
                        }
                    } else {
                        // No session: still bias toward "fat" browser-like inner sizes.
                        rng.gen_range(900usize..=1400)
                    };
                    let need = target_total.saturating_sub(base).min(usize::from(max_pad));
                    need as u8
                }
            }
        };

        Ok(Self {
            parts,
            len,
            pad_len,
        })
    }

    pub(crate) fn wire_len(&self) -> usize {
        5 + usize::from(self.pad_len) + self.len
    }

    pub(crate) fn append_to(&self, buf: &mut Vec<u8>) {
        buf.reserve(1 + 3 + 1 + usize::from(self.pad_len) + self.len);
        let len = self.len;
        let pad_len = self.pad_len;
        buf.push(FRAME_VER);
        buf.push(((len >> 16) & 0xFF) as u8);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
        buf.push(pad_len);
        if pad_len > 0 {
            let pl = usize::from(pad_len);
            let start = buf.len();
            buf.resize(start + pl, 0);
            rand::thread_rng().fill_bytes(&mut buf[start..]);
        }
        for part in self.parts {
            buf.extend_from_slice(part);
        }
    }
}

/// Byte offset where inner payload starts (after `ver|len|pad_len|pad`).
fn padded_frame_payload_start(raw: &[u8]) -> Result<usize, FrameError> {
    if raw.len() < 4 {
        return Err(FrameError::Proto("short frame".into()));
    }
    if raw[0] != FRAME_VER {
        return Err(FrameError::Proto(format!("bad ver {}", raw[0])));
    }
    let plen = (usize::from(raw[1]) << 16) | (usize::from(raw[2]) << 8) | usize::from(raw[3]);
    if plen > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    if raw.len() < 5 {
        return Err(FrameError::Proto("missing pad_len".into()));
    }
    let pad_len = usize::from(raw[4]);
    let need = 5 + pad_len + plen;
    if raw.len() != need {
        return Err(FrameError::Proto(format!(
            "length mismatch: got {} expected {}",
            raw.len(),
            need
        )));
    }
    Ok(5 + pad_len)
}

/// Borrow inner payload slice (no copy). Hot-path friendly after decrypt.
pub fn read_padded_frame_borrow(raw: &[u8]) -> Result<&[u8], FrameError> {
    let start = padded_frame_payload_start(raw)?;
    Ok(&raw[start..])
}

/// Consume a shared buffer and slice the padded payload without moving bytes.
/// The slice retains the complete backing allocation, including padding.
pub fn read_padded_frame_bytes(raw: bytes::Bytes) -> Result<bytes::Bytes, FrameError> {
    let start = padded_frame_payload_start(&raw)?;
    Ok(raw.slice(start..))
}

/// Consume `raw` and return only payload bytes (reuse buffer; no `to_vec` of payload).
pub fn read_padded_frame_into(mut raw: Vec<u8>) -> Result<Vec<u8>, FrameError> {
    let start = padded_frame_payload_start(&raw)?;
    raw.drain(..start);
    Ok(raw)
}

/// Returns payload bytes (allocated copy). Prefer [`read_padded_frame_borrow`] or
/// [`read_padded_frame_into`] on hot paths.
pub fn read_padded_frame(raw: &[u8]) -> Result<Vec<u8>, FrameError> {
    read_padded_frame_borrow(raw).map(|s| s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_parser_slices_payload_and_rejects_bad_lengths() {
        for pad in [0usize, 255] {
            let mut wire = vec![1, 0, 0, 3, pad as u8];
            wire.resize(5 + pad, 9);
            wire.extend_from_slice(b"abc");
            let wire = bytes::Bytes::from(wire);
            let start = wire.as_ptr().wrapping_add(5 + pad);
            let payload = read_padded_frame_bytes(wire.clone()).unwrap();
            assert_eq!(payload.as_ref(), b"abc");
            assert_eq!(payload.as_ptr(), start);
            assert!(read_padded_frame_bytes(wire.slice(..wire.len() - 1)).is_err());
        }
        assert!(
            read_padded_frame_bytes(bytes::Bytes::from_static(&[1, 0, 0, 0, 0]))
                .unwrap()
                .is_empty()
        );
        assert!(read_padded_frame_bytes(bytes::Bytes::from_static(&[2, 0, 0, 0, 0])).is_err());
    }

    #[test]
    fn prepared_parts_validate_combined_length_and_append_prefix() {
        let oversized = vec![0; 0xFF_FFFF];
        assert!(PreparedFrame::new(&[&oversized, b"x"], 0, PadMode::Random, None).is_err());
        let parts: &[&[u8]] = &[b"ab", b"", b"cd"];
        let frame = PreparedFrame::new(parts, 0, PadMode::Random, None).unwrap();
        let mut out = vec![99];
        frame.append_to(&mut out);
        assert_eq!(out, [99, 1, 0, 0, 4, 0, b'a', b'b', b'c', b'd']);
    }

    #[test]
    fn round_trip_zero_pad() {
        let mut v = Vec::new();
        write_padded_frame(&mut v, b"hello", 0).unwrap();
        assert_eq!(read_padded_frame(&v).unwrap(), b"hello");
        assert_eq!(read_padded_frame_borrow(&v).unwrap(), b"hello");
        assert_eq!(read_padded_frame_into(v).unwrap(), b"hello");
    }

    #[test]
    fn round_trip_with_pad() {
        let mut v = Vec::new();
        write_padded_frame(&mut v, b"x", 20).unwrap();
        assert_eq!(read_padded_frame(&v).unwrap(), b"x");
        assert_eq!(read_padded_frame_borrow(&v).unwrap(), b"x");
        assert_eq!(read_padded_frame_into(v).unwrap(), b"x");
    }

    #[test]
    fn adaptive_uses_count_and_clamps_to_max_pad() {
        let mut st = AdaptivePadState::default();
        let mut buf = Vec::new();
        for _ in 0..3 {
            write_padded_frame_with_mode_state(
                &mut buf,
                b"",
                255,
                PadMode::Adaptive,
                Some(&mut st),
            )
            .unwrap();
            // burst target ~900+ B, but u8 `max_pad` caps padding to 255 B.
            assert_eq!(buf.len(), 5 + 255);
        }
        assert_eq!(st.count, 3);
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut v = Vec::new();
        write_padded_frame(&mut v, b"hi", 0).unwrap();
        v.push(0xfe);
        assert!(read_padded_frame(&v).is_err());
    }

    #[test]
    fn mtu_cap_plaintext_budget() {
        let small = 1400usize;
        let n = max_tcp_payload_per_ws_message(false, 0, 64, small);
        assert!(n > 1300);
        let v2 = max_tcp_payload_per_ws_message(true, 32, 64, small);
        assert_eq!(v2, small - (29 + 32 + 5 + 64));
        assert!(v2 < n);
        assert!(v2 > 1000);

        let n_large = max_tcp_payload_per_ws_message(true, 32, 64, DEFAULT_MAX_WS_BINARY);
        assert!(n_large > 200_000);
    }
}
