//! TLS GREASE helpers ([draft-ietf-tls-grease](https://datatracker.ietf.org/doc/html/draft-ietf-tls-grease-01)).

use crate::constants::GREASE_PLACEHOLDER;

/// Returns true if `v` matches the GREASE pattern (ωaωa with low nibble `a`).
#[inline]
pub fn is_grease_u16(v: u16) -> bool {
    ((v >> 8) == (v & 0xff)) && (v & 0xf == 0xa)
}

/// Normalizes GREASE values to [`GREASE_PLACEHOLDER`] for fingerprint comparison.
#[inline]
pub fn ungrease_u16(v: u16) -> u16 {
    if is_grease_u16(v) {
        GREASE_PLACEHOLDER
    } else {
        v
    }
}

/// Deterministic GREASE value from seed slot (BoringSSL-style), matching uTLS `GetBoringGREASEValue`.
#[inline]
pub fn boring_grease_value(grease_seed: &[u16; 5], index: usize) -> u16 {
    let mut ret = grease_seed[index];
    ret = (ret & 0xf0) | 0x0a;
    ret |= ret << 8;
    ret
}

pub const GREASE_CIPHER: usize = 0;
pub const GREASE_GROUP: usize = 1;
pub const GREASE_EXTENSION1: usize = 2;
pub const GREASE_EXTENSION2: usize = 3;
pub const GREASE_VERSION: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_classification_matches_utls() {
        let cases = [
            (0x0a0a, true),
            (0x1a1a, true),
            (0x2a1a, false),
            (0x2a2a, true),
            (0x1234, false),
            (0x1a2a, false),
            (0xdeed, false),
            (0xb1b1, false),
            (0x0b0b, false),
        ];
        for (v, want) in cases {
            assert_eq!(is_grease_u16(v), want, "wrong for {v:#06x}");
        }
    }
}
