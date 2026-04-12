//! **biba** — Rust port of the core uTLS ideas: TLS [`ClientHelloSpec`](spec::ClientHelloSpec),
//! browser-like presets, fingerprinting raw records, and helpers to align [`rustls`] settings.
//!
//! This is **not** a full TLS implementation: handshake crypto belongs to `rustls` (or another stack).
//! Use [`marshal`] when you need exact ClientHello bytes; with the `rustls` feature, [`rustls_compat`]
//! maps ALPN and cipher suites onto a `rustls::ClientConfig` where supported.

#![forbid(unsafe_code)]

pub mod constants;
pub mod error;
pub mod extensions;
pub mod fingerprinter;
pub mod grease;
pub mod marshal;
pub mod parrot;
pub mod parse;
pub mod randomized;
pub mod roller;
pub mod spec;

#[cfg(feature = "rustls")]
pub mod rustls_compat;

pub use error::{Error, Result};
pub use fingerprinter::Fingerprinter;
pub use marshal::{marshal_handshake_client_hello, marshal_tls_client_hello_record, MarshalParams};
pub use parrot::{utls_id_to_spec, ClientHelloId};
pub use parse::client_hello_spec_from_tls_record;
pub use roller::Roller;
pub use spec::ClientHelloSpec;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grease::is_grease_u16;
    use crate::marshal::{marshal_tls_client_hello_record, MarshalParams};

    #[test]
    fn grease_matrix() {
        assert!(is_grease_u16(0x0a0a));
        assert!(!is_grease_u16(0x1234));
    }

    #[test]
    fn firefox_fingerprint_roundtrip() {
        let spec = utls_id_to_spec(ClientHelloId::Firefox65).unwrap();
        let mut p = MarshalParams::default();
        p.server_name = "example.org";
        let rec = marshal_tls_client_hello_record(&spec, &p).unwrap();
        let back = client_hello_spec_from_tls_record(&rec, false, false).unwrap();
        assert_eq!(back.cipher_suites.len(), spec.cipher_suites.len());
        assert_eq!(back.extensions.len(), spec.extensions.len());
    }

    #[test]
    fn fingerprinter_accepts_record() {
        let spec = utls_id_to_spec(ClientHelloId::Chrome70).unwrap();
        let rec = marshal_tls_client_hello_record(
            &spec,
            &MarshalParams {
                server_name: "t.example",
                ..Default::default()
            },
        )
        .unwrap();
        let fp = Fingerprinter::default();
        let s2 = fp.raw_client_hello(&rec).unwrap();
        assert!(!s2.cipher_suites.is_empty());
    }
}

#[cfg(all(test, feature = "rustls"))]
mod tests_rustls {
    use super::*;
    use crate::rustls_compat::hints_from_spec;

    #[test]
    fn hints_non_empty_suites() {
        let spec = utls_id_to_spec(ClientHelloId::Chrome70).unwrap();
        let h = hints_from_spec(&spec);
        assert!(!h.cipher_suites.is_empty());
    }
}
