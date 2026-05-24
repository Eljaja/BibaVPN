//! BoringSSL client handshake for the outer WSS (`--tls-stack boring` + `boring-tls` feature).
//!
//! Supports system trust roots, `--insecure`, `--pin-cert` (leaf DER match), and
//! `--tls-fragment` via `SSL_CTX_set_max_send_fragment`.

use tokio::net::TcpStream;

use anyhow::Context;

/// TLS knobs for the Boring outer stack (mirrors [`crate::tls_util::ClientTlsParams`] + fragment flag).
#[derive(Clone, Debug, Default)]
pub struct BoringTlsParams {
    pub insecure: bool,
    /// PEM with one or more `CERTIFICATE` blocks; leaf DER must match server cert when set.
    pub pinned_certs_pem: Option<Vec<u8>>,
    pub tls_fragment: bool,
}

impl BoringTlsParams {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.insecure && self.pinned_certs_pem.is_some() {
            anyhow::bail!("TLS: --insecure cannot be combined with certificate pinning");
        }
        Ok(())
    }
}

/// TCP → TLS with SNI, verification mode from [`BoringTlsParams`].
pub async fn upgrade_tcp_boring(
    tcp: TcpStream,
    sni: &str,
    params: &BoringTlsParams,
) -> anyhow::Result<tokio_boring::SslStream<TcpStream>> {
    params.validate()?;

    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use boring::x509::X509;
    use foreign_types::ForeignTypeRef;

    let mut build =
        SslConnector::builder(SslMethod::tls()).context("boring SslConnector::builder")?;

    let pin_ders: Option<Vec<Vec<u8>>> = if let Some(pem) = &params.pinned_certs_pem {
        Some(
            crate::tls_util::parse_pem_certificates(pem)?
                .into_iter()
                .map(|c| c.as_ref().to_vec())
                .collect(),
        )
    } else {
        None
    };

    if params.insecure {
        build.set_verify(SslVerifyMode::NONE);
    } else if let Some(ref pins) = pin_ders {
        use boring::x509::store::X509StoreBuilder;

        let mut store = X509StoreBuilder::new().context("boring X509StoreBuilder::new")?;
        for der in pins {
            let x = X509::from_der(der).context("boring: parse pinned cert DER")?;
            store
                .add_cert(&x)
                .context("boring: add pinned cert to trust store")?;
        }
        build.set_cert_store_builder(store);
        build.set_verify(SslVerifyMode::PEER);
    } else {
        use boring::x509::store::X509StoreBuilder;

        let mut store = X509StoreBuilder::new().context("boring X509StoreBuilder::new")?;
        let loaded = rustls_native_certs::load_native_certs();
        for e in &loaded.errors {
            tracing::warn!(target: "bibavpn_client", "boring: native cert: {e:?}");
        }
        for c in &loaded.certs {
            if let Ok(x) = X509::from_der(c.as_ref()) {
                if let Err(e) = store.add_cert(&x) {
                    tracing::debug!(target: "bibavpn_client", "boring: add_cert: {e:?}");
                }
            }
        }
        if loaded.certs.is_empty() {
            store
                .set_default_paths()
                .context("boring: no native certs; set_default_paths")?;
        }
        build.set_cert_store_builder(store);
        build.set_verify(SslVerifyMode::PEER);
    }

    build
        .set_alpn_protos(b"\x08http/1.1")
        .context("boring alpn")?;

    let connector = build.build();
    if params.tls_fragment {
        use std::os::raw::c_int;

        unsafe extern "C" {
            fn SSL_CTX_set_max_send_fragment(ctx: *mut std::ffi::c_void, m: usize) -> c_int;
        }
        let ctx_ptr = connector.context().as_ptr().cast::<std::ffi::c_void>();
        let rc = unsafe { SSL_CTX_set_max_send_fragment(ctx_ptr, 512) };
        if rc != 1 {
            tracing::warn!(
                target: "bibavpn_client",
                rc,
                "tls-fragment: SSL_CTX_set_max_send_fragment did not return success"
            );
        } else {
            tracing::info!(
                target: "bibavpn_client",
                "tls-fragment: BoringSSL max send fragment set to 512"
            );
        }
    }

    let connect_cfg = connector.configure().context("boring configure")?;
    let stream = tokio_boring::connect(connect_cfg, sni, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("boring handshake: {e:?}"))?;

    if let Some(pins) = pin_ders {
        verify_peer_pin_der(&stream, &pins)?;
    }

    Ok(stream)
}

fn verify_peer_pin_der(
    stream: &tokio_boring::SslStream<TcpStream>,
    pins: &[Vec<u8>],
) -> anyhow::Result<()> {
    use foreign_types::ForeignTypeRef;

    let peer = stream
        .ssl()
        .peer_certificate()
        .context("boring pin: no peer certificate presented")?;
    let der = peer.to_der().context("boring pin: peer cert to DER")?;
    if pins.iter().any(|p| p.as_slice() == der.as_slice()) {
        Ok(())
    } else {
        anyhow::bail!("boring pin-cert: server leaf does not match any pinned PEM certificate");
    }
}

#[cfg(all(test, feature = "boring-tls"))]
mod tests {
    use super::*;
    use boring::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
    use tokio::net::TcpListener;

    fn localhost_pem() -> (Vec<u8>, Vec<u8>) {
        let ck =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
                .expect("rcgen cert");
        (ck.cert.pem().into_bytes(), ck.key_pair.serialize_pem().into_bytes())
    }

    #[tokio::test]
    async fn boring_pin_accepts_matching_self_signed_leaf() {
        let (cert_pem, key_pem) = localhost_pem();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let cert_pem_c = cert_pem.clone();
        let key_pem_c = key_pem.clone();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut acceptor =
                SslAcceptor::mozilla_modern(SslMethod::tls()).expect("acceptor");
            acceptor.set_verify(SslVerifyMode::NONE);
            let cert = boring::x509::X509::from_pem(&cert_pem_c).unwrap();
            let key = boring::pkey::PKey::private_key_from_pem(&key_pem_c).unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.set_private_key(&key).unwrap();
            let acceptor = acceptor.build();
            let _ = tokio_boring::accept(&acceptor, tcp).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let params = BoringTlsParams {
            insecure: false,
            pinned_certs_pem: Some(cert_pem),
            tls_fragment: false,
        };
        let stream = upgrade_tcp_boring(tcp, "127.0.0.1", &params)
            .await
            .expect("pinned boring handshake");
        drop(stream);
    }

    #[tokio::test]
    async fn boring_pin_rejects_wrong_leaf() {
        let (cert_pem, key_pem) = localhost_pem();
        let (other_pem, _) = localhost_pem();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut acceptor =
                SslAcceptor::mozilla_modern(SslMethod::tls()).expect("acceptor");
            acceptor.set_verify(SslVerifyMode::NONE);
            let cert = boring::x509::X509::from_pem(&cert_pem).unwrap();
            let key = boring::pkey::PKey::private_key_from_pem(&key_pem).unwrap();
            acceptor.set_certificate(&cert).unwrap();
            acceptor.set_private_key(&key).unwrap();
            let acceptor = acceptor.build();
            let _ = tokio_boring::accept(&acceptor, tcp).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let params = BoringTlsParams {
            insecure: false,
            pinned_certs_pem: Some(other_pem),
            tls_fragment: false,
        };
        let err = upgrade_tcp_boring(tcp, "127.0.0.1", &params)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("pin") || msg.contains("CERTIFICATE_VERIFY_FAILED") || msg.contains("verify"),
            "expected pin/verify error, got {err:#}"
        );
    }

    #[test]
    fn boring_params_reject_insecure_and_pin() {
        let p = BoringTlsParams {
            insecure: true,
            pinned_certs_pem: Some(b"dummy".to_vec()),
            tls_fragment: false,
        };
        assert!(p.validate().is_err());
    }
}
