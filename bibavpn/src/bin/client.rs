//! Local SOCKS5 and optional HTTP CONNECT -> BibaVPN (WSS with padded payloads).
//! BibaV2 + BibaV2.1: PSK AEAD, WS ping, MTU-capped frames, custom WS headers, early noise.

use std::sync::Arc;

use anyhow::Context;
use bibavpn::invite_uri::decode_invite_v1;
use bibavpn::local_client::{
    LocalClientOptions, DEFAULT_CLIENT_MAX_WS_BINARY, parse_host_port, parse_ws_header,
};
use bibavpn::tls_util::{TlsClientProfile, install_ring_crypto};
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
    /// Encrypted `biba://...` invite (use with `--invite-passphrase`; mutually exclusive with `--server`).
    #[arg(long, conflicts_with = "server")]
    from_invite: Option<String>,

    /// Passphrase for `--from-invite`.
    #[arg(long)]
    invite_passphrase: Option<String>,

    #[arg(long, conflicts_with = "from_invite", required_unless_present = "from_invite")]
    server: Option<String>,

    #[arg(long, default_value = "change-me", conflicts_with = "from_invite")]
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

    /// TLS ClientHello profile (`biba` → rustls): default, chrome70, firefox65, firefox63,
    /// randomized, randomized-alpn, randomized-no-alpn. If omitted with `--from-invite`, uses invite field.
    #[arg(long)]
    tls_profile: Option<String>,
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
    if args.from_invite.is_some() != args.invite_passphrase.is_some() {
        anyhow::bail!("use --from-invite and --invite-passphrase together");
    }

    let mut extra = Vec::new();
    for line in &args.ws_headers {
        extra.push(parse_ws_header(line)?);
    }

    let inv_opt = if let Some(uri) = args.from_invite.as_ref() {
        let pass = args
            .invite_passphrase
            .as_deref()
            .expect("clap requires --invite-passphrase with --from-invite");
        Some(decode_invite_v1(uri, pass).context("decode --from-invite")?)
    } else {
        None
    };

    let (
        server_host,
        server_port,
        sni_owned,
        token,
        max_pad,
        junk_frames,
        early_ws_frames,
        psk,
        decoy_max,
        max_ws_binary,
        ws_ping_secs,
        insecure_tls,
    ) = if let Some(ref inv) = inv_opt {
        let (h, p) = parse_host_port(inv.server.trim()).context("invite server")?;
        let sni = args.sni.clone().unwrap_or_else(|| inv.sni.clone());
        (
            h,
            p,
            sni,
            inv.token.clone(),
            inv.max_pad,
            args.junk_frames,
            args.early_ws_frames,
            inv.psk.clone(),
            inv.decoy_max,
            inv.max_ws_binary,
            inv.ws_ping_secs,
            args.insecure || inv.insecure,
        )
    } else {
        let server = args.server.as_ref().expect("server or from-invite");
        let (h, p) = parse_host_port(server.trim()).context("server")?;
        let sni = args.sni.clone().unwrap_or_else(|| h.clone());
        (
            h,
            p,
            sni,
            args.token.clone(),
            args.max_pad,
            args.junk_frames,
            args.early_ws_frames,
            args.psk.clone(),
            args.decoy_max,
            args.max_ws_binary,
            args.ws_ping_secs,
            args.insecure,
        )
    };

    let tls_profile: TlsClientProfile =
        if let Some(s) = args.tls_profile.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
            s.parse().context("tls-profile")?
        } else if let Some(ref inv) = inv_opt {
            inv.tls_profile.parse().context("invite tls_profile")?
        } else {
            TlsClientProfile::default()
        };

    let opts = LocalClientOptions {
        server_host,
        server_port,
        sni: sni_owned,
        token,
        socks_bind: args.socks5,
        http_proxy_bind: args.http_proxy,
        insecure_tls,
        max_pad,
        junk_frames,
        early_ws_frames,
        psk,
        decoy_max,
        ws_host: args.ws_host,
        ws_origin: args.ws_origin,
        ws_user_agent: args.ws_user_agent,
        ws_accept_language: args.ws_accept_language,
        ws_extra_headers: Arc::new(extra),
        max_ws_binary,
        ws_ping_secs,
        tls_profile,
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
