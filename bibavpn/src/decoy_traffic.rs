//! Short-lived HTTPS GET requests to the same server as the tunnel (browser-like background).

use anyhow::Context;
use rand::seq::SliceRandom;
use rand::Rng;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep};
use tracing::warn;

use crate::tls_util::{ClientTlsParams, TlsClientProfile, client_tls_config};

pub struct DecoyConfig {
    pub server_host: String,
    pub server_port: u16,
    pub sni: String,
    pub insecure: bool,
    pub tls_profile: TlsClientProfile,
    pub pinned_certs_pem: Option<Vec<u8>>,
    pub interval_secs: u64,
    pub paths: Vec<String>,
    pub user_agent: String,
}

/// Background task: periodic tiny GETs (same TLS stack as the tunnel).
pub async fn run_decoy_gets_loop(cfg: DecoyConfig, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let tls = match client_tls_config(&ClientTlsParams {
        insecure: cfg.insecure,
        profile: cfg.tls_profile,
        pinned_certs_pem: cfg.pinned_certs_pem.clone(),
    }) {
        Ok(c) => c,
        Err(e) => {
            warn!("decoy gets: tls config: {e:#}");
            return;
        }
    };
    let domain = match ServerName::try_from(cfg.sni.clone()) {
        Ok(d) => d,
        Err(e) => {
            warn!("decoy gets: sni: {e:#}");
            return;
        }
    };
    let connector = tokio_rustls::TlsConnector::from(tls);
    let paths = if cfg.paths.is_empty() {
        vec![
            "/favicon.ico".into(),
            "/robots.txt".into(),
            "/manifest.json".into(),
        ]
    } else {
        cfg.paths.clone()
    };

    loop {
        if *shutdown.borrow() {
            break;
        }
        let base = cfg.interval_secs.max(5);
        let lo = base.saturating_mul(1).saturating_div(2).max(1);
        let hi = base.saturating_mul(3).saturating_div(2).max(lo);
        let wait_secs = rand::thread_rng().gen_range(lo..=hi);
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            _ = sleep(Duration::from_secs(wait_secs)) => {}
        }
        if *shutdown.borrow() {
            break;
        }
        let path = paths.choose(&mut rand::thread_rng()).map(|s| s.as_str()).unwrap_or("/");
        let host_hdr = if cfg.server_port == 443 {
            cfg.sni.clone()
        } else {
            format!("{}:{}", cfg.sni, cfg.server_port)
        };
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\n\r\n",
            path = path,
            host_hdr = host_hdr,
            ua = cfg.user_agent.as_str(),
        );

        let run = async {
            let tcp = TcpStream::connect((cfg.server_host.as_str(), cfg.server_port))
                .await
                .context("decoy tcp")?;
            let mut tls = connector.connect(domain.clone(), tcp).await.context("decoy tls")?;
            tls.write_all(req.as_bytes()).await.context("decoy write")?;
            let mut buf = vec![0u8; 8192];
            let _ = tls.read(&mut buf).await;
            Ok::<_, anyhow::Error>(())
        };
        if let Err(e) = run.await {
            warn!("decoy GET: {e:#}");
        }
    }
}

/// Spawn decoy loop; returns shutdown sender to stop with the main client shutdown channel.
pub fn spawn_decoy_gets(cfg: DecoyConfig, shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(run_decoy_gets_loop(cfg, shutdown));
}
