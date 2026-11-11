//! Parse TLS records and ClientHello into [`ClientHelloSpec`](crate::spec::ClientHelloSpec).

use crate::constants::*;
use crate::error::{Error, Result};
use crate::extensions::{parse_extension_block, Extension};
use crate::grease::{is_grease_u16, ungrease_u16};
use crate::spec::ClientHelloSpec;

/// Parse full TLS record (as in uTLS `ClientHelloSpec.FromRaw`).
pub fn client_hello_spec_from_tls_record(
    raw: &[u8],
    blunt_mimicry: bool,
    _real_psk: bool,
) -> Result<ClientHelloSpec> {
    if raw.len() < 5 {
        return Err(Error::UnexpectedEof);
    }
    if raw[0] != RECORD_TYPE_HANDSHAKE {
        return Err(Error::InvalidRecord("not a handshake record"));
    }
    let _ = u16::from_be_bytes([raw[1], raw[2]]);
    let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    if raw.len() < 5 + rec_len {
        return Err(Error::UnexpectedEof);
    }
    let inner = &raw[5..5 + rec_len];
    parse_client_hello_handshake(inner, blunt_mimicry)
}

fn parse_client_hello_handshake(data: &[u8], blunt: bool) -> Result<ClientHelloSpec> {
    if data.len() < 4 {
        return Err(Error::UnexpectedEof);
    }
    if data[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(Error::InvalidClientHello("not client hello"));
    }
    let hs_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    if data.len() < 4 + hs_len {
        return Err(Error::UnexpectedEof);
    }
    let ch = &data[4..4 + hs_len];
    if ch.len() < 2 + 32 + 1 {
        return Err(Error::UnexpectedEof);
    }
    let mut o = 0usize;
    let legacy_ver = u16::from_be_bytes([ch[o], ch[o + 1]]);
    o += 2;
    o += 32; // random
    let sid_len = ch[o] as usize;
    o += 1;
    if ch.len() < o + sid_len + 2 {
        return Err(Error::UnexpectedEof);
    }
    o += sid_len;

    let cs_len = u16::from_be_bytes([ch[o], ch[o + 1]]) as usize;
    o += 2;
    if !cs_len.is_multiple_of(2) {
        // Must be a whole number of u16 cipher suites; an odd length would read
        // past the list (into the compression byte, or out of bounds → panic).
        return Err(Error::InvalidClientHello("odd cipher-suite length"));
    }
    if ch.len() < o + cs_len + 1 {
        return Err(Error::UnexpectedEof);
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for i in (0..cs_len).step_by(2) {
        let v = u16::from_be_bytes([ch[o + i], ch[o + i + 1]]);
        cipher_suites.push(ungrease_u16(v));
    }
    o += cs_len;

    let comp_len = ch[o] as usize;
    o += 1;
    if ch.len() < o + comp_len + 2 {
        return Err(Error::UnexpectedEof);
    }
    let compression_methods = ch[o..o + comp_len].to_vec();
    o += comp_len;

    let mut tls_min = legacy_ver;
    let mut tls_max = legacy_ver;
    let extensions = if o >= ch.len() {
        Vec::new()
    } else {
        if ch.len() < o + 2 {
            return Err(Error::UnexpectedEof);
        }
        let ext_len = u16::from_be_bytes([ch[o], ch[o + 1]]) as usize;
        o += 2;
        if ch.len() < o + ext_len {
            return Err(Error::UnexpectedEof);
        }
        let ext_block = &ch[o..o + ext_len];
        let mut exts = parse_extension_block(ext_block, blunt)?;
        for e in &mut exts {
            if let Extension::SupportedVersions { versions } = e {
                tls_min = u16::MAX;
                tls_max = 0;
                for v in versions.iter_mut() {
                    if !is_grease_u16(*v) {
                        tls_min = tls_min.min(*v);
                        tls_max = tls_max.max(*v);
                    }
                    *v = ungrease_u16(*v);
                }
                if tls_min > tls_max {
                    // Empty or GREASE-only list: fall back to the legacy version.
                    tls_min = legacy_ver;
                    tls_max = legacy_ver;
                }
            }
            if let Extension::SupportedCurves { curves } = e {
                for c in curves.iter_mut() {
                    *c = ungrease_u16(*c);
                }
            }
            if let Extension::KeyShare { entries } = e {
                for ks in entries.iter_mut() {
                    ks.group = ungrease_u16(ks.group);
                }
            }
        }
        exts
    };

    Ok(ClientHelloSpec {
        cipher_suites,
        compression_methods,
        extensions,
        tls_vers_min: tls_min,
        tls_vers_max: tls_max,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{GREASE_PLACEHOLDER, VERSION_TLS12};
    use crate::marshal::{marshal_tls_client_hello_record, MarshalParams};

    fn tls12_spec(versions: Vec<u16>) -> ClientHelloSpec {
        ClientHelloSpec {
            cipher_suites: vec![0xC02F, 0x009C],
            compression_methods: vec![0],
            extensions: vec![Extension::SupportedVersions { versions }],
            tls_vers_min: VERSION_TLS12,
            tls_vers_max: VERSION_TLS12,
        }
    }

    #[test]
    fn tls12_versions_survive_roundtrip() {
        let record =
            marshal_tls_client_hello_record(&tls12_spec(vec![VERSION_TLS12]), &MarshalParams::default())
                .expect("marshal");
        // record header (5) + handshake header (4) precede legacy_version.
        assert_eq!(u16::from_be_bytes([record[9], record[10]]), VERSION_TLS12);

        let parsed = client_hello_spec_from_tls_record(&record, false, false).expect("parse");
        assert_eq!(parsed.tls_vers_min, VERSION_TLS12);
        assert_eq!(parsed.tls_vers_max, VERSION_TLS12);

        let again =
            marshal_tls_client_hello_record(&parsed, &MarshalParams::default()).expect("marshal");
        assert_eq!(again, record, "TLS version bounds must round-trip");
    }

    #[test]
    fn grease_versions_are_ignored_for_bounds() {
        let record = marshal_tls_client_hello_record(
            &tls12_spec(vec![GREASE_PLACEHOLDER, VERSION_TLS12]),
            &MarshalParams::default(),
        )
        .expect("marshal");

        let parsed = client_hello_spec_from_tls_record(&record, false, false).expect("parse");
        assert_eq!(parsed.tls_vers_min, VERSION_TLS12);
        assert_eq!(parsed.tls_vers_max, VERSION_TLS12);
        assert!(
            matches!(parsed.extensions.as_slice(), [Extension::SupportedVersions { versions }]
                if versions.as_slice() == [GREASE_PLACEHOLDER, VERSION_TLS12].as_slice()),
            "GREASE version should be ungreased, not counted"
        );
    }
}
