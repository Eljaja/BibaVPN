use std::io::{BufReader, Cursor};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use biba::ClientHelloId;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use rustls::{SupportedCipherSuite, client::danger::ServerCertVerifier, crypto::CryptoProvider};

/// TLS client preset: maps to [`biba::ClientHelloId`] and aligns rustls cipher order + ALPN (best-effort).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsClientProfile {
    #[default]
    Default,
    Chrome70,
    Firefox65,
    Firefox63,
    Randomized,
    RandomizedAlpn,
    RandomizedNoAlpn,
}

impl TlsClientProfile {
    fn biba_id(self) -> Option<ClientHelloId> {
        match self {
            TlsClientProfile::Default => None,
            TlsClientProfile::Chrome70 => Some(ClientHelloId::Chrome70),
            TlsClientProfile::Firefox65 => Some(ClientHelloId::Firefox65),
            TlsClientProfile::Firefox63 => Some(ClientHelloId::Firefox63),
            TlsClientProfile::Randomized => Some(ClientHelloId::HelloRandomized),
            TlsClientProfile::RandomizedAlpn => Some(ClientHelloId::HelloRandomizedAlpn),
            TlsClientProfile::RandomizedNoAlpn => Some(ClientHelloId::HelloRandomizedNoAlpn),
        }
    }
}

impl FromStr for TlsClientProfile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("default") {
            return Ok(Self::Default);
        }
        Ok(match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "chrome70" | "chrome-70" => Self::Chrome70,
            "firefox65" | "firefox-65" => Self::Firefox65,
            "firefox63" | "firefox-63" => Self::Firefox63,
            "randomized" => Self::Randomized,
            "randomized-alpn" => Self::RandomizedAlpn,
            "randomized-no-alpn" => Self::RandomizedNoAlpn,
            other => anyhow::bail!(
                "unknown tls-profile {other:?}: expected default, chrome70, firefox65, firefox63, randomized, randomized-alpn, randomized-no-alpn"
            ),
        })
    }
}

fn read_certs(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certs")?;
    Ok(certs)
}

fn read_key(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let items = rustls_pemfile::read_all(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("read pem")?;
    for item in items {
        if let rustls_pemfile::Item::Pkcs8Key(k) = item {
            return Ok(PrivatePkcs8KeyDer::from(k).into());
        }
    }
    anyhow::bail!("no PKCS8 private key in pem")
}

pub fn server_config_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = read_certs(cert_pem)?;
    let key = read_key(key_pem)?;
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("server with_single_cert")?;
    Ok(Arc::new(cfg))
}

pub fn server_self_signed(san: &str) -> anyhow::Result<Arc<ServerConfig>> {
    let ck = rcgen::generate_simple_self_signed([san.to_string()]).context("rcgen")?;
    let cert_der = ck.cert.der().clone();
    let key_der = ck.key_pair.serialize_der();
    let cert_chain = vec![cert_der];
    let key = PrivatePkcs8KeyDer::from(key_der).into();
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("self-signed server")?;
    Ok(Arc::new(cfg))
}

pub fn client_config_insecure() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
    )
}

pub fn client_config_system_roots() -> anyhow::Result<Arc<ClientConfig>> {
    let mut store = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    if !loaded.errors.is_empty() {
        tracing::warn!("some native certs failed: {:?}", loaded.errors);
    }
    for c in loaded.certs {
        let _ = store.add(c);
    }
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth(),
    ))
}

/// Build TLS [`ClientConfig`] with optional [`TlsClientProfile`] (`biba` hints → rustls).
///
/// Call [`install_ring_crypto`] first.
pub fn client_config_for_profile(
    insecure: bool,
    profile: TlsClientProfile,
) -> anyhow::Result<Arc<ClientConfig>> {
    let Some(id) = profile.biba_id() else {
        return Ok(if insecure {
            client_config_insecure()
        } else {
            client_config_system_roots()?
        });
    };

    let spec = biba::utls_id_to_spec(id).map_err(|e| anyhow::anyhow!(e))?;
    let hints = biba::rustls_compat::hints_from_spec(&spec);

    let base_arc = CryptoProvider::get_default().ok_or_else(|| {
        anyhow::anyhow!("no rustls CryptoProvider; call install_ring_crypto() before connecting")
    })?;
    let base = base_arc.as_ref();

    let mut cipher_suites: Vec<SupportedCipherSuite> = Vec::new();
    for &suite_ref in &hints.cipher_suites {
        if base.cipher_suites.contains(suite_ref) {
            cipher_suites.push(*suite_ref);
        }
    }
    if cipher_suites.is_empty() {
        anyhow::bail!("TLS profile {:?}: no cipher suites overlap rustls provider", profile);
    }

    let mut provider = base.clone();
    provider.cipher_suites = cipher_suites;
    let provider = Arc::new(provider);

    let versions = rustls::DEFAULT_VERSIONS;
    let mut cfg = if insecure {
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| anyhow::anyhow!(e))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut store = RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            tracing::warn!("some native certs failed: {:?}", loaded.errors);
        }
        for c in loaded.certs {
            let _ = store.add(c);
        }
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| anyhow::anyhow!(e))?
            .with_root_certificates(store)
            .with_no_client_auth()
    };

    let mut alpn = hints.alpn;
    if alpn.is_empty() {
        alpn.push(b"http/1.1".to_vec());
    }
    cfg.alpn_protocols = alpn;

    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let prov = CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("no default crypto provider".to_string()))?;
        verify_tls12_signature(message, cert, dss, &prov.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let prov = CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("no default crypto provider".to_string()))?;
        verify_tls13_signature(message, cert, dss, &prov.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        CryptoProvider::get_default()
            .expect("default crypto")
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn install_ring_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
