//! Randomized ClientHello profiles (uTLS `generateRandomizedSpec`).

use rand::seq::SliceRandom;
use rand::Rng;

use crate::constants::*;
use crate::error::{Error, Result};
use crate::extensions::{Extension, KeyShareEntry, PaddingStyle};
use crate::parrot::ClientHelloId;
use crate::spec::ClientHelloSpec;

/// TLS 1.2 suites used by uTLS `cipherSuites` shuffle (see Go `cipher_suites.go`).
const DEFAULT_CIPHER_SUITES_TLS12: &[u16] = &[
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_RSA_WITH_RC4_128_SHA,
];

const DEFAULT_CIPHER_SUITES_TLS13: &[u16] = &[
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
];

/// uTLS `DefaultWeights` (subset used here).
#[derive(Clone, Debug)]
pub struct RandomizedWeights {
    pub append_alpn: f64,
    pub tls13_max: f64,
    pub remove_cipher: f64,
    pub append_padding: f64,
}

impl Default for RandomizedWeights {
    fn default() -> Self {
        Self {
            append_alpn: 0.7,
            tls13_max: 0.4,
            remove_cipher: 0.4,
            append_padding: 0.62,
        }
    }
}

fn make_supported_versions(min_v: u16, max_v: u16) -> Vec<u16> {
    let mut a = Vec::new();
    let mut v = max_v;
    loop {
        a.push(v);
        if v == min_v {
            break;
        }
        v -= 1;
    }
    a
}

fn remove_rc4(mut v: Vec<u16>) -> Vec<u16> {
    v.retain(|c| {
        *c != TLS_RSA_WITH_RC4_128_SHA
            && *c != TLS_ECDHE_RSA_WITH_RC4_128_SHA
            && *c != TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    });
    v
}

fn remove_random_ciphers<R: Rng + ?Sized>(r: &mut R, mut s: Vec<u16>, max_p: f64) -> Vec<u16> {
    if s.len() <= 1 {
        return s;
    }
    let float_len = s.len() as f64;
    let mut i = 1usize;
    while i < s.len() {
        let p = max_p * i as f64 / float_len;
        if r.gen::<f64>() < p {
            s.remove(i);
        } else {
            i += 1;
        }
    }
    s
}

/// Build a randomized spec (uTLS `generateRandomizedSpec`).
pub fn generate_randomized_spec(id: ClientHelloId) -> Result<ClientHelloSpec> {
    let mut rng = rand::thread_rng();
    let weights = RandomizedWeights::default();

    let with_alpn = match id {
        ClientHelloId::HelloRandomizedAlpn => true,
        ClientHelloId::HelloRandomizedNoAlpn => false,
        ClientHelloId::HelloRandomized => rng.gen::<f64>() < weights.append_alpn,
        _ => return Err(Error::UnknownClientHelloId),
    };

    let mut tls_min = VERSION_TLS10;
    let mut tls_max = VERSION_TLS12;
    let mut suites: Vec<u16> = DEFAULT_CIPHER_SUITES_TLS12.to_vec();
    suites.shuffle(&mut rng);

    if rng.gen::<f64>() < weights.tls13_max {
        tls_min = if rng.gen_bool(0.5) {
            VERSION_TLS10
        } else {
            VERSION_TLS12
        };
        tls_max = VERSION_TLS13;
        let mut tls13: Vec<u16> = DEFAULT_CIPHER_SUITES_TLS13.to_vec();
        tls13.shuffle(&mut rng);
        suites.splice(0..0, tls13);
        suites = remove_rc4(suites);
    }

    suites = remove_random_ciphers(&mut rng, suites, weights.remove_cipher);

    let mut sig = vec![
        ECDSA_SECP256R1_SHA256,
        RSA_PKCS1_SHA256,
        ECDSA_SECP384R1_SHA384,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA1,
        RSA_PKCS1_SHA512,
    ];
    if tls_max == VERSION_TLS13 || rng.gen::<f64>() < 0.51 {
        sig.push(RSA_PSS_RSAE_SHA256);
        if rng.gen::<f64>() < 0.9 {
            sig.push(RSA_PSS_RSAE_SHA384);
            sig.push(RSA_PSS_RSAE_SHA512);
        }
    }
    sig.shuffle(&mut rng);

    let mut exts: Vec<Extension> = vec![
        Extension::ServerName {
            host: String::new(),
        },
        Extension::SessionTicket {
            ticket: Vec::new(),
        },
        Extension::SignatureAlgorithms { schemes: sig },
        Extension::SupportedPoints {
            formats: vec![POINT_FORMAT_UNCOMPRESSED],
        },
        Extension::SupportedCurves {
            curves: {
                let mut c = vec![X25519, CURVE_P256, CURVE_P384];
                if rng.gen::<f64>() < 0.46 {
                    c.push(CURVE_P521);
                }
                c
            },
        },
    ];

    if with_alpn {
        exts.push(Extension::Alpn {
            protocols: vec!["h2".into(), "http/1.1".into()],
        });
    }

    if tls_max == VERSION_TLS13 || rng.gen::<f64>() < weights.append_padding {
        exts.push(Extension::Padding {
            style: PaddingStyle::Boring,
        });
    }
    if rng.gen::<f64>() < 0.74 {
        exts.push(Extension::StatusRequest);
    }
    if rng.gen::<f64>() < 0.46 {
        exts.push(Extension::SignedCertificateTimestamp);
    }
    if rng.gen::<f64>() < 0.75 {
        exts.push(Extension::RenegotiationInfo {
            renegotiation: RENEGOTIATE_ONCE_AS_CLIENT,
        });
    }
    if rng.gen::<f64>() < 0.77 {
        exts.push(Extension::ExtendedMasterSecret);
    }

    if tls_max == VERSION_TLS13 {
        let mut ks = vec![
            KeyShareEntry {
                group: X25519,
                key_exchange: vec![0u8; 32],
            },
            KeyShareEntry {
                group: CURVE_P256,
                key_exchange: vec![0u8; 65],
            },
        ];
        ks.shuffle(&mut rng);
        exts.push(Extension::KeyShare { entries: ks });
        exts.push(Extension::PskKeyExchangeModes {
            modes: vec![PSK_MODE_DHE],
        });
        exts.push(Extension::SupportedVersions {
            versions: make_supported_versions(tls_min, tls_max),
        });
    }

    exts.shuffle(&mut rng);

    Ok(ClientHelloSpec {
        cipher_suites: suites,
        compression_methods: vec![COMPRESSION_NONE],
        extensions: exts,
        tls_vers_min: tls_min,
        tls_vers_max: tls_max,
    })
}
