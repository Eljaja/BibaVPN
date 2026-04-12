//! Fingerprint raw ClientHello bytes into a [`ClientHelloSpec`](crate::spec::ClientHelloSpec).

use crate::error::Result;
use crate::extensions::{Extension, PaddingStyle};
use crate::parse::client_hello_spec_from_tls_record;
use crate::spec::ClientHelloSpec;

/// Options for [`Fingerprinter::raw_client_hello`] (uTLS `Fingerprinter`).
#[derive(Clone, Debug, Default)]
pub struct Fingerprinter {
    pub allow_blunt_mimicry: bool,
    pub always_add_padding: bool,
    pub real_psk_resumption: bool,
}

impl Fingerprinter {
    /// Full TLS record → spec (uTLS `RawClientHello` / `FingerprintClientHello`).
    pub fn raw_client_hello(&self, raw: &[u8]) -> Result<ClientHelloSpec> {
        let mut spec = client_hello_spec_from_tls_record(
            raw,
            self.allow_blunt_mimicry,
            self.real_psk_resumption,
        )?;
        if self.always_add_padding {
            spec.always_add_padding();
        }
        Ok(spec)
    }
}

impl ClientHelloSpec {
    /// Append Boring-style padding if missing (uTLS `AlwaysAddPadding`).
    pub fn always_add_padding(&mut self) {
        let has_pad = self
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::Padding { .. }));
        if has_pad {
            return;
        }
        self.extensions.push(Extension::Padding {
            style: PaddingStyle::Boring,
        });
    }
}
