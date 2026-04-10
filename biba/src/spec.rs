//! ClientHello specification (uTLS `ClientHelloSpec`).

use crate::extensions::Extension;

/// TLS ClientHello description: cipher suites, compression, and ordered extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHelloSpec {
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub tls_vers_min: u16,
    pub tls_vers_max: u16,
}

impl Default for ClientHelloSpec {
    fn default() -> Self {
        Self {
            cipher_suites: Vec::new(),
            compression_methods: vec![0],
            extensions: Vec::new(),
            tls_vers_min: crate::constants::VERSION_TLS10,
            tls_vers_max: crate::constants::VERSION_TLS12,
        }
    }
}

impl ClientHelloSpec {
    pub fn has_tls13(&self) -> bool {
        use crate::constants::VERSION_TLS13;
        self.tls_vers_max == VERSION_TLS13
            || self.extensions.iter().any(|e| {
                matches!(e, Extension::SupportedVersions { versions } if versions.contains(&VERSION_TLS13))
            })
    }
}
