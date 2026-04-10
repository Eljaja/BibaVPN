//! Browser presets (`ClientHelloID` → [`ClientHelloSpec`](crate::spec::ClientHelloSpec)).

use crate::constants::*;
use crate::error::{Error, Result};
use crate::extensions::{Extension, KeyShareEntry, PaddingStyle};
use crate::spec::ClientHelloSpec;

/// Identifies a built-in ClientHello profile (uTLS `ClientHelloID` subset).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClientHelloId {
    HelloCustom,
    HelloRandomized,
    HelloRandomizedAlpn,
    HelloRandomizedNoAlpn,
    Chrome58,
    Chrome62,
    Chrome70,
    Chrome72,
    Firefox63,
    Firefox65,
    Firefox99,
}

/// Maps a [`ClientHelloId`] to a [`ClientHelloSpec`] (uTLS `utlsIdToSpec`).
pub fn utls_id_to_spec(id: ClientHelloId) -> Result<ClientHelloSpec> {
    match id {
        ClientHelloId::HelloCustom => Ok(ClientHelloSpec::default()),
        ClientHelloId::Chrome70 => Ok(chrome_70()),
        ClientHelloId::Firefox63 | ClientHelloId::Firefox65 => Ok(firefox_63_65()),
        ClientHelloId::HelloRandomized
        | ClientHelloId::HelloRandomizedAlpn
        | ClientHelloId::HelloRandomizedNoAlpn => {
            crate::randomized::generate_randomized_spec(id)
        }
        _ => Err(Error::UnknownClientHelloId),
    }
}

fn chrome_70() -> ClientHelloSpec {
    ClientHelloSpec {
        tls_vers_min: VERSION_TLS10,
        tls_vers_max: VERSION_TLS13,
        cipher_suites: vec![
            GREASE_PLACEHOLDER,
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
        compression_methods: vec![COMPRESSION_NONE],
        extensions: vec![
            Extension::Grease {
                value: GREASE_PLACEHOLDER,
                body: Vec::new(),
            },
            Extension::RenegotiationInfo {
                renegotiation: RENEGOTIATE_ONCE_AS_CLIENT,
            },
            Extension::ServerName {
                host: String::new(),
            },
            Extension::ExtendedMasterSecret,
            Extension::SessionTicket {
                ticket: Vec::new(),
            },
            Extension::SignatureAlgorithms {
                schemes: vec![
                    ECDSA_SECP256R1_SHA256,
                    RSA_PSS_RSAE_SHA256,
                    RSA_PKCS1_SHA256,
                    ECDSA_SECP384R1_SHA384,
                    RSA_PSS_RSAE_SHA384,
                    RSA_PKCS1_SHA384,
                    RSA_PSS_RSAE_SHA512,
                    RSA_PKCS1_SHA512,
                    RSA_PKCS1_SHA1,
                ],
            },
            Extension::StatusRequest,
            Extension::SignedCertificateTimestamp,
            Extension::Alpn {
                protocols: vec!["h2".into(), "http/1.1".into()],
            },
            Extension::FakeChannelId {
                old_extension_id: false,
            },
            Extension::SupportedPoints {
                formats: vec![POINT_FORMAT_UNCOMPRESSED],
            },
            Extension::KeyShare {
                entries: vec![
                    KeyShareEntry {
                        group: GREASE_PLACEHOLDER,
                        key_exchange: vec![0],
                    },
                    KeyShareEntry {
                        group: X25519,
                        key_exchange: vec![0u8; 32],
                    },
                ],
            },
            Extension::PskKeyExchangeModes {
                modes: vec![PSK_MODE_DHE],
            },
            Extension::SupportedVersions {
                versions: vec![
                    GREASE_PLACEHOLDER,
                    VERSION_TLS13,
                    VERSION_TLS12,
                    VERSION_TLS11,
                    VERSION_TLS10,
                ],
            },
            Extension::SupportedCurves {
                curves: vec![
                    GREASE_PLACEHOLDER,
                    X25519,
                    CURVE_P256,
                    CURVE_P384,
                ],
            },
            Extension::CompressCertificate {
                algorithms: vec![CERT_COMPRESSION_BROTLI],
            },
            Extension::Grease {
                value: GREASE_PLACEHOLDER,
                body: Vec::new(),
            },
            Extension::Padding {
                style: PaddingStyle::Boring,
            },
        ],
    }
}

fn firefox_63_65() -> ClientHelloSpec {
    ClientHelloSpec {
        tls_vers_min: VERSION_TLS10,
        tls_vers_max: VERSION_TLS13,
        cipher_suites: vec![
            TLS_AES_128_GCM_SHA256,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
        compression_methods: vec![COMPRESSION_NONE],
        extensions: vec![
            Extension::ServerName {
                host: String::new(),
            },
            Extension::ExtendedMasterSecret,
            Extension::RenegotiationInfo {
                renegotiation: RENEGOTIATE_ONCE_AS_CLIENT,
            },
            Extension::SupportedCurves {
                curves: vec![
                    X25519,
                    CURVE_P256,
                    CURVE_P384,
                    CURVE_P521,
                    FAKE_FFDHE2048,
                    FAKE_FFDHE3072,
                ],
            },
            Extension::SupportedPoints {
                formats: vec![POINT_FORMAT_UNCOMPRESSED],
            },
            Extension::SessionTicket {
                ticket: Vec::new(),
            },
            Extension::Alpn {
                protocols: vec!["h2".into(), "http/1.1".into()],
            },
            Extension::StatusRequest,
            Extension::KeyShare {
                entries: vec![
                    KeyShareEntry {
                        group: X25519,
                        key_exchange: vec![0u8; 32],
                    },
                    KeyShareEntry {
                        group: CURVE_P256,
                        key_exchange: vec![0u8; 65],
                    },
                ],
            },
            Extension::SupportedVersions {
                versions: vec![
                    VERSION_TLS13,
                    VERSION_TLS12,
                    VERSION_TLS11,
                    VERSION_TLS10,
                ],
            },
            Extension::SignatureAlgorithms {
                schemes: vec![
                    ECDSA_SECP256R1_SHA256,
                    ECDSA_SECP384R1_SHA384,
                    ECDSA_SECP521R1_SHA512,
                    RSA_PSS_RSAE_SHA256,
                    RSA_PSS_RSAE_SHA384,
                    RSA_PSS_RSAE_SHA512,
                    RSA_PKCS1_SHA256,
                    RSA_PKCS1_SHA384,
                    RSA_PKCS1_SHA512,
                    ECDSA_SHA1,
                    RSA_PKCS1_SHA1,
                ],
            },
            Extension::PskKeyExchangeModes {
                modes: vec![PSK_MODE_DHE],
            },
            Extension::RecordSizeLimit { limit: 0x4001 },
            Extension::Padding {
                style: PaddingStyle::Boring,
            },
        ],
    }
}
