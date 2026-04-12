//! Map a [`ClientHelloSpec`](crate::spec::ClientHelloSpec) to settings `rustls` actually supports.
//!
//! **Important:** `rustls` does not expose byte-for-byte ClientHello control (see
//! [rustls#1932](https://github.com/rustls/rustls/issues/1932)). This module only aligns
//! cipher suites and ALPN on [`rustls::ClientConfig`](rustls::ClientConfig) with the spec
//! where possible. For full uTLS-style wire control you still need a custom stack or a fork.

use rustls::crypto::ring::ALL_CIPHER_SUITES;

use crate::extensions::Extension;
use crate::spec::ClientHelloSpec;

/// Hints derived from a [`ClientHelloSpec`] for configuring rustls.
#[derive(Debug)]
pub struct RustlsClientConfigHints {
    pub cipher_suites: Vec<&'static rustls::SupportedCipherSuite>,
    pub alpn: Vec<Vec<u8>>,
}

fn suite_from_u16(id: u16) -> Option<&'static rustls::SupportedCipherSuite> {
    ALL_CIPHER_SUITES
        .iter()
        .find(|s| u16::from(s.suite()) == id)
}

/// Pick rustls cipher suites present in `spec` (TLS 1.2 / 1.3 suites only).
pub fn hints_from_spec(spec: &ClientHelloSpec) -> RustlsClientConfigHints {
    let mut suites = Vec::new();
    for id in &spec.cipher_suites {
        if let Some(s) = suite_from_u16(*id) {
            if !suites.contains(&s) {
                suites.push(s);
            }
        }
    }
    if suites.is_empty() {
        suites.extend(ALL_CIPHER_SUITES.iter().take(3));
    }

    let mut alpn: Vec<Vec<u8>> = Vec::new();
    for e in &spec.extensions {
        if let Extension::Alpn { protocols } = e {
            for p in protocols {
                alpn.push(p.as_bytes().to_vec());
            }
            break;
        }
    }

    RustlsClientConfigHints {
        cipher_suites: suites,
        alpn,
    }
}
