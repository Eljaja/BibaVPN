//! Parse TLS records and ClientHello into [`ClientHelloSpec`](crate::spec::ClientHelloSpec).

use crate::error::{Error, Result};
use crate::extensions::{parse_extension_block, Extension};
use crate::grease::ungrease_u16;
use crate::spec::ClientHelloSpec;
use crate::constants::*;

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
    let hs_len =
        ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
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
                tls_min = 0;
                tls_max = 0;
                for v in versions.iter_mut() {
                    *v = ungrease_u16(*v);
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
