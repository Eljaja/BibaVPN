use std::io::{BufReader, Cursor};
use std::sync::Arc;

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use rustls::{client::danger::ServerCertVerifier, crypto::CryptoProvider};

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
