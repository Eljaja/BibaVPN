//! BoringSSL client handshake for the outer WSS (`--tls-stack boring` + `boring-tls` feature).
//!
//! `biba` / parrot **ClientHello** templates do not apply to this stack; use for TLS record
//! options (e.g. `SSL_set_max_send_fragment`–style) and standard Boring cipher negotiation.

use tokio::net::TcpStream;

use anyhow::Context;

/// TCP → TLS with SNI, optional cert verify skip, small TLS records for `--tls-fragment`.
pub async fn upgrade_tcp_boring(
    tcp: TcpStream,
    sni: &str,
    insecure: bool,
    tls_fragment: bool,
) -> anyhow::Result<tokio_boring::SslStream<TcpStream>> {
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use boring::x509::X509;

    let mut build = SslConnector::builder(SslMethod::tls()).context("boring SslConnector::builder")?;
    if insecure {
        build.set_verify(SslVerifyMode::NONE);
    } else {
        // Peer verification needs a real trust store. `cert_store_mut().add_cert` is not
        // available on the ref type; use `X509StoreBuilder` + `set_cert_store_builder` (boring 5.1).
        use boring::x509::store::X509StoreBuilder;

        let mut store = X509StoreBuilder::new().context("boring X509StoreBuilder::new")?;
        let loaded = rustls_native_certs::load_native_certs();
        for e in &loaded.errors {
            tracing::warn!("boring: native cert: {e:?}");
        }
        for c in &loaded.certs {
            if let Ok(x) = X509::from_der(c.as_ref()) {
                if let Err(e) = store.add_cert(&x) {
                    tracing::debug!("boring: add_cert: {e:?}");
                }
            }
        }
        if loaded.certs.is_empty() {
            store
                .set_default_paths()
                .context("boring: no native certs; set_default_paths")?;
        }
        build.set_cert_store_builder(store);
    }
    if tls_fragment {
        tracing::debug!(
            "tls-fragment: requested; Boring record cap needs SSL_CTX_set_max_send_fragment in bindings (work in progress)"
        );
    }
    // WebSocket over HTTPS
    build.set_alpn_protos(b"\x08http/1.1").context("boring alpn")?;

    let connector = build.build();
    let connect_cfg = connector.configure().context("boring configure")?;

    tokio_boring::connect(connect_cfg, sni, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("boring handshake: {e:?}"))
}
