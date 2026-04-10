//! TLS extensions as used by uTLS ClientHello.

use crate::constants::*;
use crate::error::{Error, Result};
use crate::grease::is_grease_u16;

/// How to compute the RFC 7627 padding extension payload length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaddingStyle {
    /// BoringSSL `ssl_add_clienthello_tlsext_padding` heuristic.
    Boring,
    /// Pad so the overall TLS record reaches `target_record_len` bytes (uTLS `AlwaysPadToLen`).
    PadRecordTo(usize),
    /// Explicit payload length (extension data only, not the 4-byte ext header).
    FixedPayloadLen(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extension {
    Grease { value: u16, body: Vec<u8> },
    ServerName { host: String },
    ExtendedMasterSecret,
    RenegotiationInfo { renegotiation: u8 },
    SessionTicket { ticket: Vec<u8> },
    SignatureAlgorithms { schemes: Vec<u16> },
    StatusRequest,
    SignedCertificateTimestamp,
    Alpn { protocols: Vec<String> },
    FakeChannelId { old_extension_id: bool },
    SupportedPoints { formats: Vec<u8> },
    KeyShare { entries: Vec<KeyShareEntry> },
    PskKeyExchangeModes { modes: Vec<u8> },
    SupportedVersions { versions: Vec<u16> },
    SupportedCurves { curves: Vec<u16> },
    CompressCertificate { algorithms: Vec<u16> },
    Padding { style: PaddingStyle },
    /// `record_size_limit` (28) — Firefox / uTLS fake compatibility.
    RecordSizeLimit { limit: u16 },
    Generic { id: u16, data: Vec<u8> },
}

impl Extension {
    /// IANA / uTLS extension type on the wire (before length).
    pub fn wire_type(&self) -> u16 {
        match self {
            Extension::Grease { value, .. } => *value,
            Extension::ServerName { .. } => EXT_SERVER_NAME,
            Extension::ExtendedMasterSecret => EXT_EXTENDED_MASTER_SECRET,
            Extension::RenegotiationInfo { .. } => EXT_RENEGOTIATION_INFO,
            Extension::SessionTicket { .. } => EXT_SESSION_TICKET,
            Extension::SignatureAlgorithms { .. } => EXT_SIGNATURE_ALGORITHMS,
            Extension::StatusRequest => EXT_STATUS_REQUEST,
            Extension::SignedCertificateTimestamp => EXT_SIGNED_CERTIFICATE_TIMESTAMP,
            Extension::Alpn { .. } => EXT_ALPN,
            Extension::FakeChannelId { old_extension_id } => {
                if *old_extension_id {
                    30031
                } else {
                    FAKE_EXTENSION_CHANNEL_ID
                }
            }
            Extension::SupportedPoints { .. } => EXT_EC_POINT_FORMATS,
            Extension::KeyShare { .. } => EXT_KEY_SHARE,
            Extension::PskKeyExchangeModes { .. } => EXT_PSK_KEY_EXCHANGE_MODES,
            Extension::SupportedVersions { .. } => EXT_SUPPORTED_VERSIONS,
            Extension::SupportedCurves { .. } => EXT_SUPPORTED_GROUPS,
            Extension::CompressCertificate { .. } => EXT_COMPRESS_CERTIFICATE,
            Extension::Padding { .. } => EXT_PADDING,
            Extension::RecordSizeLimit { .. } => EXT_RECORD_SIZE_LIMIT,
            Extension::Generic { id, .. } => *id,
        }
    }

    fn marshal_payload(&self) -> Vec<u8> {
        match self {
            Extension::Grease { body, .. } => body.clone(),
            Extension::ServerName { host } => {
                let host = hostname_for_sni(host);
                if host.is_empty() {
                    return Vec::new();
                }
                let mut b = Vec::new();
                let name_list_len = host.len() + 3;
                b.extend_from_slice(&(name_list_len as u16).to_be_bytes());
                b.push(0); // host_name
                b.extend_from_slice(&(host.len() as u16).to_be_bytes());
                b.extend_from_slice(host.as_bytes());
                b
            }
            Extension::ExtendedMasterSecret => Vec::new(),
            Extension::RenegotiationInfo { renegotiation } => vec![*renegotiation],
            Extension::SessionTicket { ticket } => ticket.clone(),
            Extension::SignatureAlgorithms { schemes } => {
                let mut b = Vec::new();
                let body_len = schemes.len() * 2;
                b.extend_from_slice(&(body_len as u16).to_be_bytes());
                for s in schemes {
                    b.extend_from_slice(&s.to_be_bytes());
                }
                b
            }
            Extension::StatusRequest => vec![0x01, 0x00, 0x00, 0x00, 0x00],
            Extension::SignedCertificateTimestamp => Vec::new(),
            Extension::Alpn { protocols } => {
                let mut inner = Vec::new();
                for p in protocols {
                    inner.push(p.len() as u8);
                    inner.extend_from_slice(p.as_bytes());
                }
                let mut b = Vec::new();
                b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                b.extend_from_slice(&inner);
                b
            }
            Extension::FakeChannelId { .. } => Vec::new(),
            Extension::SupportedPoints { formats } => {
                let mut b = vec![formats.len() as u8];
                b.extend_from_slice(formats);
                b
            }
            Extension::KeyShare { entries } => {
                let mut inner = Vec::new();
                for e in entries {
                    inner.extend_from_slice(&e.group.to_be_bytes());
                    inner.extend_from_slice(&(e.key_exchange.len() as u16).to_be_bytes());
                    inner.extend_from_slice(&e.key_exchange);
                }
                let mut b = Vec::new();
                b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                b.extend_from_slice(&inner);
                b
            }
            Extension::PskKeyExchangeModes { modes } => {
                let mut b = vec![modes.len() as u8];
                b.extend_from_slice(modes);
                b
            }
            Extension::SupportedVersions { versions } => {
                let mut b = vec![(versions.len() * 2) as u8];
                for v in versions {
                    b.extend_from_slice(&v.to_be_bytes());
                }
                b
            }
            Extension::SupportedCurves { curves } => {
                let mut inner = Vec::new();
                for c in curves {
                    inner.extend_from_slice(&c.to_be_bytes());
                }
                let mut b = Vec::new();
                b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                b.extend_from_slice(&inner);
                b
            }
            Extension::CompressCertificate { algorithms } => {
                let mut b = vec![(algorithms.len() * 2) as u8];
                for a in algorithms {
                    b.extend_from_slice(&a.to_be_bytes());
                }
                b
            }
            Extension::Padding { style } => match style {
                PaddingStyle::FixedPayloadLen(n) => vec![0u8; *n],
                _ => Vec::new(),
            },
            Extension::RecordSizeLimit { limit } => limit.to_be_bytes().to_vec(),
            Extension::Generic { data, .. } => data.clone(),
        }
    }

    /// Full extension: type + len + data.
    pub fn marshal(&self) -> Vec<u8> {
        let wt = self.wire_type();
        let mut payload = self.marshal_payload();
        if let Extension::Padding { style } = self {
            match style {
                PaddingStyle::Boring | PaddingStyle::PadRecordTo(_) => {
                    panic!("Padding extension must be resolved via marshal_extensions_with_padding")
                }
                PaddingStyle::FixedPayloadLen(_) => {}
            }
        }
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&wt.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.append(&mut payload);
        out
    }
}

fn hostname_for_sni(host: &str) -> String {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return String::new();
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.contains(':') {
        return String::new();
    }
    host.to_ascii_lowercase()
}

/// BoringSSL padding: <https://github.com/google/boringssl/blob/master/ssl/t1_lib.c>
pub fn boring_padding_len(unpadded_client_hello_len: usize) -> (usize, bool) {
    let u = unpadded_client_hello_len;
    if u > 0xff && u < 0x200 {
        let mut padding_len = 0x200 - u;
        if padding_len >= 5 {
            padding_len -= 4;
        } else {
            padding_len = 1;
        }
        (padding_len, true)
    } else {
        (0, false)
    }
}

/// Serializes extensions in order, resolving [`Extension::Padding`] with [`PaddingStyle::Boring`].
pub fn marshal_extensions_with_padding(
    exts: &[Extension],
    boring_unpadded_client_hello_len: impl Fn(usize) -> usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, ext) in exts.iter().enumerate() {
        if let Extension::Padding { style: PaddingStyle::Boring } = ext {
            let prefix_len = boring_unpadded_client_hello_len(i);
            let (plen, will_pad) = boring_padding_len(prefix_len);
            if !will_pad {
                continue;
            }
            let mut payload = vec![0u8; plen];
            out.extend_from_slice(&EXT_PADDING.to_be_bytes());
            out.extend_from_slice(&(plen as u16).to_be_bytes());
            out.append(&mut payload);
            continue;
        }
        if let Extension::Padding {
            style: PaddingStyle::PadRecordTo(target),
        } = ext
        {
            let prefix_len = boring_unpadded_client_hello_len(i);
            let mut padding_len = target.saturating_sub(prefix_len + 4);
            if padding_len >= 5 {
                padding_len -= 4;
            } else if padding_len > 0 {
                padding_len = 1;
            }
            if padding_len == 0 {
                continue;
            }
            let mut payload = vec![0u8; padding_len];
            out.extend_from_slice(&EXT_PADDING.to_be_bytes());
            out.extend_from_slice(&(padding_len as u16).to_be_bytes());
            out.append(&mut payload);
            continue;
        }
        out.extend_from_slice(&ext.marshal());
    }
    out
}

pub fn extension_from_wire(id: u16, data: &[u8]) -> Result<Extension> {
    if is_grease_u16(id) {
        return Ok(Extension::Grease {
            value: id,
            body: data.to_vec(),
        });
    }
    match id {
        EXT_SERVER_NAME => parse_sni(data),
        EXT_EXTENDED_MASTER_SECRET => Ok(Extension::ExtendedMasterSecret),
        EXT_RENEGOTIATION_INFO => {
            let r = *data.first().unwrap_or(&0);
            Ok(Extension::RenegotiationInfo {
                renegotiation: r,
            })
        }
        EXT_SESSION_TICKET => Ok(Extension::SessionTicket {
            ticket: data.to_vec(),
        }),
        EXT_SIGNATURE_ALGORITHMS => parse_sig_algs(data),
        EXT_STATUS_REQUEST => Ok(Extension::StatusRequest),
        EXT_SIGNED_CERTIFICATE_TIMESTAMP => Ok(Extension::SignedCertificateTimestamp),
        EXT_ALPN => parse_alpn(data),
        FAKE_EXTENSION_CHANNEL_ID | 30031 => Ok(Extension::FakeChannelId {
            old_extension_id: id == 30031,
        }),
        EXT_EC_POINT_FORMATS => {
            if data.is_empty() {
                return Ok(Extension::SupportedPoints { formats: vec![] });
            }
            let n = data[0] as usize;
            Ok(Extension::SupportedPoints {
                formats: data.get(1..1 + n).unwrap_or(&[]).to_vec(),
            })
        }
        EXT_KEY_SHARE => parse_key_share(data),
        EXT_PSK_KEY_EXCHANGE_MODES => {
            if data.is_empty() {
                return Ok(Extension::PskKeyExchangeModes { modes: vec![] });
            }
            let n = data[0] as usize;
            Ok(Extension::PskKeyExchangeModes {
                modes: data.get(1..1 + n).unwrap_or(&[]).to_vec(),
            })
        }
        EXT_SUPPORTED_VERSIONS => parse_supported_versions(data),
        EXT_SUPPORTED_GROUPS => parse_supported_curves(data),
        EXT_COMPRESS_CERTIFICATE => parse_compress_cert(data),
        EXT_PADDING => Ok(Extension::Padding {
            style: PaddingStyle::FixedPayloadLen(data.len()),
        }),
        EXT_RECORD_SIZE_LIMIT => {
            if data.len() < 2 {
                return Err(Error::Parse("record_size_limit".into()));
            }
            let limit = u16::from_be_bytes([data[0], data[1]]);
            Ok(Extension::RecordSizeLimit { limit })
        }
        _ => Err(Error::UnsupportedExtension(id)),
    }
}

fn parse_sni(data: &[u8]) -> Result<Extension> {
    if data.len() < 2 {
        return Ok(Extension::ServerName {
            host: String::new(),
        });
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len == 0 || data.len() < 2 + list_len {
        return Ok(Extension::ServerName {
            host: String::new(),
        });
    }
    let mut rest = &data[2..2 + list_len];
    let mut host = String::new();
    while !rest.is_empty() {
        if rest.len() < 3 {
            break;
        }
        let name_type = rest[0];
        let len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
        rest = &rest[3..];
        if rest.len() < len {
            break;
        }
        if name_type == 0 {
            host = String::from_utf8_lossy(&rest[..len]).to_string();
            break;
        }
        rest = &rest[len..];
    }
    Ok(Extension::ServerName { host })
}

fn parse_sig_algs(data: &[u8]) -> Result<Extension> {
    if data.len() < 2 {
        return Ok(Extension::SignatureAlgorithms { schemes: vec![] });
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut schemes = Vec::with_capacity(n / 2);
    let mut i = 2;
    while i + 2 <= 2 + n && i + 2 <= data.len() {
        schemes.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    Ok(Extension::SignatureAlgorithms { schemes })
}

fn parse_alpn(data: &[u8]) -> Result<Extension> {
    if data.len() < 2 {
        return Ok(Extension::Alpn {
            protocols: vec![],
        });
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut protos = Vec::new();
    let mut rest = data.get(2..2 + n).unwrap_or(&[]);
    while !rest.is_empty() {
        if rest.is_empty() {
            break;
        }
        let l = rest[0] as usize;
        rest = &rest[1..];
        if rest.len() < l {
            break;
        }
        protos.push(String::from_utf8_lossy(&rest[..l]).to_string());
        rest = &rest[l..];
    }
    Ok(Extension::Alpn { protocols: protos })
}

fn parse_key_share(data: &[u8]) -> Result<Extension> {
    if data.len() < 2 {
        return Ok(Extension::KeyShare { entries: vec![] });
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut entries = Vec::new();
    let mut rest = data.get(2..2 + n).unwrap_or(&[]);
    while rest.len() >= 4 {
        let group = u16::from_be_bytes([rest[0], rest[1]]);
        let ks_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < ks_len {
            break;
        }
        entries.push(KeyShareEntry {
            group,
            key_exchange: rest[..ks_len].to_vec(),
        });
        rest = &rest[ks_len..];
    }
    Ok(Extension::KeyShare { entries })
}

fn parse_supported_versions(data: &[u8]) -> Result<Extension> {
    if data.is_empty() {
        return Ok(Extension::SupportedVersions { versions: vec![] });
    }
    let n = data[0] as usize;
    let mut v = Vec::new();
    let mut i = 1;
    while i + 2 <= 1 + n && i + 2 <= data.len() {
        v.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    Ok(Extension::SupportedVersions { versions: v })
}

fn parse_supported_curves(data: &[u8]) -> Result<Extension> {
    if data.len() < 2 {
        return Ok(Extension::SupportedCurves { curves: vec![] });
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut curves = Vec::new();
    let mut i = 2;
    while i + 2 <= 2 + n && i + 2 <= data.len() {
        curves.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    Ok(Extension::SupportedCurves { curves })
}

fn parse_compress_cert(data: &[u8]) -> Result<Extension> {
    if data.is_empty() {
        return Ok(Extension::CompressCertificate {
            algorithms: vec![],
        });
    }
    let n = data[0] as usize;
    let mut algs = Vec::new();
    let mut i = 1;
    while i + 2 <= 1 + n && i + 2 <= data.len() {
        algs.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    Ok(Extension::CompressCertificate { algorithms: algs })
}

/// Parse extension list (contents of ClientHello extensions block — **without** outer u16 length).
pub fn parse_extension_block(mut buf: &[u8], blunt: bool) -> Result<Vec<Extension>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(Error::UnexpectedEof);
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        buf = &buf[4..];
        if buf.len() < len {
            return Err(Error::UnexpectedEof);
        }
        let data = &buf[..len];
        buf = &buf[len..];
        match extension_from_wire(id, data) {
            Ok(e) => out.push(e),
            Err(Error::UnsupportedExtension(_)) if blunt => {
                out.push(Extension::Generic {
                    id,
                    data: data.to_vec(),
                });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}
