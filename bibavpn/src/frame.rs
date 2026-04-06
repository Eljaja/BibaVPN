use rand::Rng;

const FRAME_VER: u8 = 1;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

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
    let fixed = 28usize
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
pub fn write_padded_frame(buf: &mut Vec<u8>, payload: &[u8], max_pad: u8) -> Result<(), FrameError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    let len = payload.len();
    if len > 0xFF_FFFF {
        return Err(FrameError::TooLarge);
    }
    let mut rng = rand::thread_rng();
    let pad_len: u8 = if max_pad == 0 {
        0
    } else {
        rng.gen_range(0..=max_pad)
    };

    buf.clear();
    buf.reserve(1 + 3 + 1 + usize::from(pad_len) + len);
    buf.push(FRAME_VER);
    buf.push(((len >> 16) & 0xFF) as u8);
    buf.push(((len >> 8) & 0xFF) as u8);
    buf.push((len & 0xFF) as u8);
    buf.push(pad_len);
    for _ in 0..pad_len {
        buf.push(rng.gen());
    }
    buf.extend_from_slice(payload);
    Ok(())
}

/// Returns payload bytes (allocated) from full WS binary message.
pub fn read_padded_frame(raw: &[u8]) -> Result<Vec<u8>, FrameError> {
    if raw.len() < 4 {
        return Err(FrameError::Proto("short frame".into()));
    }
    if raw[0] != FRAME_VER {
        return Err(FrameError::Proto(format!("bad ver {}", raw[0])));
    }
    let plen =
        (usize::from(raw[1]) << 16) | (usize::from(raw[2]) << 8) | usize::from(raw[3]);
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
    Ok(raw[5 + pad_len..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_zero_pad() {
        let mut v = Vec::new();
        write_padded_frame(&mut v, b"hello", 0).unwrap();
        assert_eq!(read_padded_frame(&v).unwrap(), b"hello");
    }

    #[test]
    fn round_trip_with_pad() {
        let mut v = Vec::new();
        write_padded_frame(&mut v, b"x", 20).unwrap();
        assert_eq!(read_padded_frame(&v).unwrap(), b"x");
    }

    #[test]
    fn mtu_cap_plaintext_budget() {
        let small = 1400usize;
        let n = max_tcp_payload_per_ws_message(false, 0, 64, small);
        assert!(n > 1300);
        let v2 = max_tcp_payload_per_ws_message(true, 32, 64, small);
        assert!(v2 < n);
        assert!(v2 > 1000);

        let n_large = max_tcp_payload_per_ws_message(true, 32, 64, DEFAULT_MAX_WS_BINARY);
        assert!(n_large > 200_000);
    }
}
