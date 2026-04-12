//! Local SOCKS5 and optional HTTP CONNECT -> BibaVPN (WSS with padded payloads).
//! BibaV2 + BibaV2.1: PSK AEAD, WS ping, MTU-capped frames, custom WS headers, early noise.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use bibavpn::frame::PadMode;
use bibavpn::invite_uri::decode_invite_v1;
use bibavpn::local_client::{
    normalize_ws_path, parse_host_port, parse_ws_header, LocalClientOptions,
    DEFAULT_CLIENT_MAX_WS_BINARY, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use bibavpn::tls_util::{install_ring_crypto, TlsClientProfile};
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

    #[arg(
        long,
        conflicts_with = "from_invite",
        required_unless_present = "from_invite"
    )]
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

    /// Trust only these PEM-encoded certificates (repeatable). Server leaf must match one DER
    /// exactly. Incompatible with `--insecure`.
    #[arg(long = "pin-cert")]
    pin_cert: Vec<PathBuf>,

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

    /// Vary WS ping interval ±N percent (0–50).
    #[arg(long, default_value_t = 0)]
    ws_ping_jitter_percent: u8,

    /// Random delay 0..=N ms before each outbound WS binary (TCP tunnel + UDP mux client).
    #[arg(long, default_value_t = 0)]
    ws_binary_send_jitter_ms: u8,

    /// `max_pad` for UDP mux only (default: same as `--max-pad`).
    #[arg(long)]
    udp_max_pad: Option<u8>,

    /// `max_ws_binary` for UDP mux only (default: same as `--max-ws-binary`).
    #[arg(long)]
    udp_max_ws_binary: Option<usize>,

    /// Max seconds to wait for UDP mux reply per SOCKS UDP datagram (0 = unlimited).
    #[arg(long, default_value_t = DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS)]
    udp_mux_reply_timeout_secs: u64,

    /// TLS ClientHello profile (`biba` → rustls): default, chrome70, firefox65, firefox63,
    /// randomized, randomized-alpn, randomized-no-alpn. If omitted with `--from-invite`, uses invite field.
    #[arg(long)]
    tls_profile: Option<String>,

    /// WebSocket path (token is sent in AUTH frame). Invite may override when unset.
    #[arg(long)]
    ws_path: Option<String>,

    /// Use legacy per-connection TCP tunnels instead of one multiplexed WSS.
    #[arg(long, default_value_t = false)]
    no_mux: bool,

    /// Padding: `random` or `http-buckets`.
    #[arg(long)]
    pad_mode: Option<String>,

    /// Idle dummy padded frames on WSS (0 = off). Invite may set default when unset.
    #[arg(long)]
    dummy_interval_secs: Option<u64>,

    /// Enable parallel decoy HTTPS GETs to the server.
    #[arg(long, default_value_t = false)]
    decoy_gets: bool,

    #[arg(long, default_value_t = 30)]
    decoy_gets_interval_secs: u64,

    /// Comma-separated paths for decoy GETs (default: built-in list when empty).
    #[arg(long)]
    decoy_gets_paths: Option<String>,
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
        ws_ping_jitter_percent,
        ws_binary_send_jitter_ms,
        udp_max_pad,
        udp_max_ws_binary,
        udp_mux_reply_timeout_secs,
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
            inv.ws_ping_jitter_percent,
            inv.ws_binary_send_jitter_ms,
            inv.udp_max_pad,
            inv.udp_max_ws_binary,
            inv.udp_mux_reply_timeout_secs,
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
            args.ws_ping_jitter_percent,
            args.ws_binary_send_jitter_ms,
            args.udp_max_pad,
            args.udp_max_ws_binary,
            args.udp_mux_reply_timeout_secs,
            args.insecure,
        )
    };

    let tls_profile: TlsClientProfile = if let Some(s) = args
        .tls_profile
        .as_ref()
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
    {
        s.parse().context("tls-profile")?
    } else if let Some(ref inv) = inv_opt {
        inv.tls_profile.parse().context("invite tls_profile")?
    } else {
        TlsClientProfile::default()
    };

    let ws_path = normalize_ws_path(
        args.ws_path
            .as_deref()
            .or(inv_opt.as_ref().and_then(|i| i.ws_path.as_deref()))
            .unwrap_or("/ws"),
    );

    let use_tcp_mux = !args.no_mux;

    let pad_mode: PadMode = match args
        .pad_mode
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(s) => PadMode::from_str(s).context("--pad-mode")?,
        None => {
            if let Some(ref inv) = inv_opt {
                if let Some(ref ps) = inv.pad_mode {
                    PadMode::from_str(ps).context("invite pad_mode")?
                } else {
                    PadMode::Random
                }
            } else {
                PadMode::Random
            }
        }
    };

    let dummy_interval_secs = args
        .dummy_interval_secs
        .or(inv_opt.as_ref().and_then(|i| i.dummy_interval_secs))
        .unwrap_or(0);

    let decoy_gets_paths: Vec<String> = args
        .decoy_gets_paths
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let pinned_certs_pem = if args.pin_cert.is_empty() {
        None
    } else {
        let mut buf = Vec::new();
        for p in &args.pin_cert {
            buf.extend(
                std::fs::read(p).with_context(|| format!("read --pin-cert {}", p.display()))?,
            );
            buf.push(b'\n');
        }
        Some(buf)
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
        ws_ping_jitter_percent,
        ws_binary_send_jitter_ms,
        udp_max_pad,
        udp_max_ws_binary,
        udp_mux_reply_timeout_secs,
        tls_profile,
        pinned_certs_pem,
        ws_path,
        use_tcp_mux,
        pad_mode,
        dummy_interval_secs,
        decoy_gets: args.decoy_gets,
        decoy_gets_interval_secs: args.decoy_gets_interval_secs,
        decoy_gets_paths,
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
