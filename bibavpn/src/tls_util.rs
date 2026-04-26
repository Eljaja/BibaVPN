use std::io::{BufReader, Cursor};
use std::str::FromStr;
use std::sync::Arc;

/// Which TLS engine wraps the main WSS (`rustls` default; `boring` needs `--features boring-tls`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsStack {
    #[default]
    Rustls,
    /// BoringSSL + tokio-boring: enables `--tls-fragment` record splitting (client path).
    Boring,
}

impl FromStr for TlsStack {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "" | "rustls" => TlsStack::Rustls,
            "boring" | "boringssl" | "bssl" => TlsStack::Boring,
            o => anyhow::bail!("unknown tls-stack {o:?}: rustls, boring"),
        })
    }
}

use anyhow::Context;
use biba::ClientHelloId;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{client::danger::ServerCertVerifier, crypto::CryptoProvider, SupportedCipherSuite};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

/// TLS client preset: maps to [`biba::ClientHelloId`] and aligns rustls cipher order + ALPN (best-effort).
///
/// **Guarantee:** negotiated **cipher suite order** and **ALPN** only — not a wire-identical
/// ClientHello (no full JA3/JA4 parity); rustls does not expose byte-level CH control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsClientProfile {
    /// Rustls defaults only (no `biba` cipher/ALPN hints).
    #[default]
    Default,
    /// ~Chrome M70 ClientHello spec bytes (`biba` + rustls); use `Chrome132` for the v1.2 default label.
    Chrome70,
    /// BibaV1.2 default browser-like label (current wire spec matches `chrome_70` template; tune as uTLS data evolves).
    Chrome132,
    Firefox65,
    Firefox63,
    /// Alias template (see `biba` `Firefox136`).
    Firefox136,
    /// Safari 18 / WebKit placeholder (current: same as Chrome spec in `biba`).
    Safari18,
    Randomized,
    RandomizedAlpn,
    RandomizedNoAlpn,
}

impl TlsClientProfile {
    fn biba_id(self) -> Option<ClientHelloId> {
        match self {
            TlsClientProfile::Default => None,
            TlsClientProfile::Chrome70 => Some(ClientHelloId::Chrome70),
            TlsClientProfile::Chrome132 => Some(ClientHelloId::Chrome132),
            TlsClientProfile::Firefox65 => Some(ClientHelloId::Firefox65),
            TlsClientProfile::Firefox63 => Some(ClientHelloId::Firefox63),
            TlsClientProfile::Firefox136 => Some(ClientHelloId::Firefox136),
            TlsClientProfile::Safari18 => Some(ClientHelloId::Safari18),
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
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "chrome70" | "chrome-70" => Ok(Self::Chrome70),
            "chrome-132" | "chrome132" | "chromium-132" => Ok(Self::Chrome132),
            "firefox-136" | "firefox136" => Ok(Self::Firefox136),
            "safari-18" | "safari18" | "webkit" => Ok(Self::Safari18),
            "firefox65" | "firefox-65" => Ok(Self::Firefox65),
            "firefox63" | "firefox-63" => Ok(Self::Firefox63),
            "random" | "randomized" => Ok(Self::Randomized),
            "randomized-alpn" => Ok(Self::RandomizedAlpn),
            "randomized-no-alpn" => Ok(Self::RandomizedNoAlpn),
            other => anyhow::bail!(
                "unknown tls-profile / fingerprint {other:?}: \
                 use default, chrome-132, firefox-136, safari-18, random, chrome70, firefox65, firefox63, randomized-…"
            ),
        }
    }
}

impl TlsClientProfile {
    /// Same names as [`FromStr`] (for `--fingerprint`).
    pub fn from_fingerprint_str(s: &str) -> Result<Self, anyhow::Error> {
        s.parse()
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

pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<Arc<ServerConfig>> {
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
        anyhow::bail!(
            "TLS profile {:?}: no cipher suites overlap rustls provider",
            profile
        );
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

/// TLS knobs for the SOCKS/HTTP client: verification mode, `biba` profile, optional leaf pin (PEM).
#[derive(Clone, Debug, Default)]
pub struct ClientTlsParams {
    pub insecure: bool,
    pub profile: TlsClientProfile,
    /// PEM bytes containing one or more `CERTIFICATE` blocks; leaf must match one DER exactly.
    pub pinned_certs_pem: Option<Vec<u8>>,
}

/// Build [`ClientConfig`] from [`ClientTlsParams`] (call [`install_ring_crypto`] first).
pub fn client_tls_config(params: &ClientTlsParams) -> anyhow::Result<Arc<ClientConfig>> {
    if params.insecure && params.pinned_certs_pem.is_some() {
        anyhow::bail!("TLS: --insecure cannot be combined with certificate pinning");
    }
    if params.insecure {
        return Ok(client_config_insecure());
    }

    let pins: Option<Vec<CertificateDer<'static>>> = match &params.pinned_certs_pem {
        None => None,
        Some(pem) => {
            let v = read_certs(pem)?;
            if v.is_empty() {
                anyhow::bail!("pin-cert: no certificates in PEM");
            }
            Some(v)
        }
    };

    match (&pins, params.profile.biba_id()) {
        (None, None) => client_config_system_roots(),
        (None, Some(_)) => client_config_for_profile(false, params.profile),
        (Some(pins), None) => client_config_pinned_only(pins),
        (Some(pins), Some(id)) => client_config_profile_with_pins(id, params.profile, pins),
    }
}

fn client_config_pinned_only(
    pins: &[CertificateDer<'static>],
) -> anyhow::Result<Arc<ClientConfig>> {
    Ok(Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertsVerifier::new(pins.to_vec())))
            .with_no_client_auth(),
    ))
}

fn client_config_profile_with_pins(
    id: ClientHelloId,
    profile: TlsClientProfile,
    pins: &[CertificateDer<'static>],
) -> anyhow::Result<Arc<ClientConfig>> {
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
        anyhow::bail!(
            "TLS profile {:?}: no cipher suites overlap rustls provider",
            profile
        );
    }

    let mut provider = base.clone();
    provider.cipher_suites = cipher_suites;
    let provider = Arc::new(provider);

    let versions = rustls::DEFAULT_VERSIONS;
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| anyhow::anyhow!(e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertsVerifier::new(pins.to_vec())))
        .with_no_client_auth();

    let mut alpn = hints.alpn;
    if alpn.is_empty() {
        alpn.push(b"http/1.1".to_vec());
    }
    cfg.alpn_protocols = alpn;

    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct PinnedCertsVerifier {
    pins: Vec<CertificateDer<'static>>,
}

impl PinnedCertsVerifier {
    fn new(pins: Vec<CertificateDer<'static>>) -> Self {
        Self { pins }
    }
}

impl ServerCertVerifier for PinnedCertsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.pins.iter().any(|p| p.as_ref() == end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ))
        }
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
