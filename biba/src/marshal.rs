//! Serialize `ClientHelloSpec` to handshake bytes and TLS records.

use crate::constants::{self, *};
use crate::error::{Error, Result};
use crate::extensions::{Extension, PaddingStyle};
use crate::grease::boring_grease_value;
use crate::spec::ClientHelloSpec;

/// Parameters for building wire-format ClientHello.
#[derive(Clone, Debug)]
pub struct MarshalParams<'a> {
    pub server_name: &'a str,
    pub session_id: &'a [u8],
    pub random: &'a [u8; 32],
    /// Resolves GREASE placeholders in cipher suites / curves / versions / GREASE extensions.
    pub grease_seed: [u16; 5],
}

impl Default for MarshalParams<'_> {
    fn default() -> Self {
        Self {
            server_name: "",
            session_id: &[],
            random: &[0u8; 32],
            grease_seed: [0x3a, 0x4b, 0x5c, 0x6d, 0x7e],
        }
    }
}

/// Build TLS plaintext record: type 22, legacy version 0x0301, handshake ClientHello.
pub fn marshal_tls_client_hello_record(
    spec: &ClientHelloSpec,
    p: &MarshalParams,
) -> Result<Vec<u8>> {
    let hs = marshal_handshake_client_hello(spec, p)?;
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(RECORD_TYPE_HANDSHAKE);
    rec.extend_from_slice(&VERSION_TLS10.to_be_bytes());
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    Ok(rec)
}

/// Handshake message only (type + 24-bit length + ClientHello body).
pub fn marshal_handshake_client_hello(
    spec: &ClientHelloSpec,
    p: &MarshalParams,
) -> Result<Vec<u8>> {
    let body = marshal_client_hello_body(spec, p)?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    let len = body.len();
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(&body);
    Ok(out)
}

/// ClientHello body: version, random, session id, ciphers, compression, extensions.
pub fn marshal_client_hello_body(spec: &ClientHelloSpec, p: &MarshalParams) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // Legacy version: TLS 1.2 for middlebox compat when TLS 1.3 is offered.
    let legacy = if spec.has_tls13() {
        VERSION_TLS12
    } else {
        spec.tls_vers_max.max(spec.tls_vers_min)
    };
    out.extend_from_slice(&legacy.to_be_bytes());
    out.extend_from_slice(p.random);
    if p.session_id.len() > 255 {
        return Err(Error::InvalidClientHello("session id too long"));
    }
    out.push(p.session_id.len() as u8);
    out.extend_from_slice(p.session_id);

    let suites: Vec<u16> = spec
        .cipher_suites
        .iter()
        .map(|c| resolve_grease_cipher(*c, p.grease_seed))
        .collect();
    let cs_len = suites.len() * 2;
    out.extend_from_slice(&(cs_len as u16).to_be_bytes());
    for c in &suites {
        out.extend_from_slice(&c.to_be_bytes());
    }

    if spec.compression_methods.is_empty() {
        out.push(1);
        out.push(COMPRESSION_NONE);
    } else {
        out.push(spec.compression_methods.len() as u8);
        out.extend_from_slice(&spec.compression_methods);
    }

    let ext_bytes = marshal_extensions(spec, p)?;
    out.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&ext_bytes);
    Ok(out)
}

fn resolve_grease_cipher(c: u16, seed: [u16; 5]) -> u16 {
    if c == constants::GREASE_PLACEHOLDER {
        return boring_grease_value(&seed, crate::grease::GREASE_CIPHER);
    }
    c
}

fn marshal_extensions(spec: &ClientHelloSpec, p: &MarshalParams) -> Result<Vec<u8>> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut boring_idx: Option<usize> = None;
    let mut grease_ext_slot = 0u8;
    for (i, ext) in spec.extensions.iter().enumerate() {
        if let Extension::Padding {
            style: PaddingStyle::Boring,
        } = ext
        {
            boring_idx = Some(i);
            parts.push(Vec::new());
            continue;
        }
        parts.push(marshal_one_extension(ext, p, &mut grease_ext_slot)?);
    }

    if let Some(bi) = boring_idx {
        let unpadded: usize = parts.iter().map(|v| v.len()).sum();
        let (plen, will_pad) = crate::extensions::boring_padding_len(
            2 + 32
                + 1
                + p.session_id.len()
                + 2
                + spec.cipher_suites.len() * 2
                + 1
                + spec.compression_methods.len().max(1)
                + 2
                + unpadded,
        );
        let mut pad_payload = vec![0u8; plen];
        let mut pad = Vec::with_capacity(4 + plen);
        pad.extend_from_slice(&EXT_PADDING.to_be_bytes());
        pad.extend_from_slice(&(plen as u16).to_be_bytes());
        pad.append(&mut pad_payload);
        parts[bi] = pad;
        if !will_pad {
            parts[bi].clear();
        }
    }

    Ok(parts.into_iter().flatten().collect())
}

fn marshal_one_extension(
    ext: &Extension,
    p: &MarshalParams,
    grease_ext_slot: &mut u8,
) -> Result<Vec<u8>> {
    let mut e = ext.clone();
    apply_grease_to_extension(&mut e, p.grease_seed, grease_ext_slot);
    inject_sni(&mut e, p.server_name);
    Ok(e.marshal())
}

fn inject_sni(ext: &mut Extension, server_name: &str) {
    if let Extension::ServerName { host } = ext {
        if host.is_empty() && !server_name.is_empty() {
            *host = server_name.to_string();
        }
    }
}

fn apply_grease_to_extension(ext: &mut Extension, seed: [u16; 5], grease_ext_slot: &mut u8) {
    match ext {
        Extension::Grease { value, body } if *value == constants::GREASE_PLACEHOLDER => {
            let idx = if *grease_ext_slot == 0 {
                crate::grease::GREASE_EXTENSION1
            } else {
                crate::grease::GREASE_EXTENSION2
            };
            *value = boring_grease_value(&seed, idx);
            if *grease_ext_slot == 0 {
                *body = Vec::new();
            } else {
                *body = vec![0];
            }
            *grease_ext_slot = grease_ext_slot.saturating_add(1);
        }
        Extension::SupportedCurves { curves } => {
            for c in curves.iter_mut() {
                if *c == constants::GREASE_PLACEHOLDER {
                    *c = boring_grease_value(&seed, crate::grease::GREASE_GROUP);
                }
            }
        }
        Extension::SupportedVersions { versions } => {
            for v in versions.iter_mut() {
                if *v == constants::GREASE_PLACEHOLDER {
                    *v = boring_grease_value(&seed, crate::grease::GREASE_VERSION);
                }
            }
        }
        Extension::KeyShare { entries } => {
            for e in entries.iter_mut() {
                if e.group == constants::GREASE_PLACEHOLDER {
                    e.group = boring_grease_value(&seed, crate::grease::GREASE_GROUP);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parrot::utls_id_to_spec;
    use crate::ClientHelloId;

    #[test]
    fn chrome_70_marshals_and_roundtrips_structure() {
        let spec = utls_id_to_spec(ClientHelloId::Chrome70).expect("spec");
        let mut p = MarshalParams::default();
        p.server_name = "example.com";
        let record = marshal_tls_client_hello_record(&spec, &p).expect("marshal");
        let parsed =
            crate::parse::client_hello_spec_from_tls_record(&record, false, false).expect("parse");
        assert_eq!(parsed.cipher_suites.len(), spec.cipher_suites.len());
        assert_eq!(parsed.extensions.len(), spec.extensions.len());
    }
}
