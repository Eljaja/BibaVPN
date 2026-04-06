//! Local SOCKS5 and optional HTTP CONNECT -> BibaVPN (WSS with padded payloads).
//! BibaV2 + BibaV2.1: PSK AEAD, WS ping, MTU-capped frames, custom WS headers, early noise.

use std::sync::Arc;

use bibavpn::local_client::{
    LocalClientOptions, DEFAULT_CLIENT_MAX_WS_BINARY, parse_host_port, parse_ws_header,
};
use bibavpn::tls_util::install_ring_crypto;
use clap::Parser;
use tokio::signal;
use tokio::sync::watch;
use tracing::info;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "bibavpn-client",
    about = "SOCKS5 / HTTP CONNECT front for BibaVPN (v2.1: WS ping, MTU cap, custom WS headers)"
)]
struct Args {
    #[arg(long)]
    server: String,

    #[arg(long, default_value = "change-me")]
    token: String,

    #[arg(long)]
    sni: Option<String>,

    #[arg(long, default_value = "127.0.0.1:1080")]
    socks5: String,

    /// HTTP CONNECT proxy bind (e.g. 127.0.0.1:8080). Omit to disable.
    #[arg(long)]
    http_proxy: Option<String>,

    #[arg(long)]
    insecure: bool,

    #[arg(long, default_value = "64")]
    max_pad: u8,

    #[arg(long, default_value = "0")]
    junk_frames: u32,

    /// Random binary WebSocket frames right after upgrade (before junk / HELLO). Shapes startup.
    #[arg(long, default_value = "0")]
    early_ws_frames: u8,

    #[arg(long)]
    psk: Option<String>,

    #[arg(long, default_value = "0")]
    decoy_max: u8,

    /// Override WebSocket `Host` header (default: SNI or SNI:port).
    #[arg(long)]
    ws_host: Option<String>,

    #[arg(long)]
    ws_origin: Option<String>,

    #[arg(long)]
    ws_user_agent: Option<String>,

    #[arg(long)]
    ws_accept_language: Option<String>,

    /// Extra header `Name: value` (repeatable). BibaV2.1.
    #[arg(long = "ws-header")]
    ws_headers: Vec<String>,

    #[arg(long, default_value_t = DEFAULT_CLIENT_MAX_WS_BINARY)]
    max_ws_binary: usize,

    /// WebSocket ping interval seconds (0 = off). Keeps NAT / middleboxes warm.
    #[arg(long, default_value_t = 25)]
    ws_ping_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    install_ring_crypto();
    let args = Args::parse();

    let (server_host, server_port) = parse_host_port(&args.server)?;
    let sni_owned = args.sni.clone().unwrap_or_else(|| server_host.clone());

    let mut extra = Vec::new();
    for line in &args.ws_headers {
        extra.push(parse_ws_header(line)?);
    }

    let opts = LocalClientOptions {
        server_host,
        server_port,
        sni: sni_owned,
        token: args.token,
        socks_bind: args.socks5,
        http_proxy_bind: args.http_proxy,
        insecure_tls: args.insecure,
        max_pad: args.max_pad,
        junk_frames: args.junk_frames,
        early_ws_frames: args.early_ws_frames,
        psk: args.psk,
        decoy_max: args.decoy_max,
        ws_host: args.ws_host,
        ws_origin: args.ws_origin,
        ws_user_agent: args.ws_user_agent,
        ws_accept_language: args.ws_accept_language,
        ws_extra_headers: Arc::new(extra),
        max_ws_binary: args.max_ws_binary,
        ws_ping_secs: args.ws_ping_secs,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        bibavpn::local_client::run_local_client(opts, shutdown_rx, None).await
    });

    signal::ctrl_c().await?;
    info!("ctrl-c");
    let _ = shutdown_tx.send(true);
    server.await??;
    Ok(())
}
