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
use bibavpn::stealth_v12::{
    apply_preset_ws_jitter, merge_idle_decoy_secs, DecoyMode, DesyncMode, StealthProfile, TcpFooling,
    preset,
};
use bibavpn::tls_util::{install_ring_crypto, TlsClientProfile, TlsStack};
use bibavpn::client_policy::tls_profile_from_invite;
use clap::Parser;
use base64::Engine;
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

    /// Random delay in `min..=max` ms for each outbound WS binary (0,0 = use `ws_binary_send_jitter_ms` only).
    #[arg(long, default_value_t = 0)]
    ws_jitter_min_ms: u8,

    #[arg(long, default_value_t = 0)]
    ws_jitter_max_ms: u8,

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

    /// Padding: `adaptive` (default), `random`, or `http-buckets`.
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

    /// Biba wire protocol when not using `--from-invite`: only `3` (requires `--psk`).
    #[arg(long, default_value_t = 3)]
    proto: u8,

    /// Domain label for v3 PSK KDF (must match server `--proto-domain`). Empty = use SNI.
    #[arg(long, default_value = "")]
    proto_domain: String,

    /// REALITY mode: server's public key (base64, 32-byte X25519).
    #[arg(long)]
    reality_public_key: Option<String>,

    /// REALITY mode: short ID (hex, 16 hex chars = 8 bytes). Omit for random.
    #[arg(long)]
    reality_short_id: Option<String>,

    /// REALITY mode: front domain for SNI (e.g. vk.com); must match server target SNI.
    #[arg(long)]
    reality_target: Option<String>,

    /// TLS / JA3-style ClientHello label (same as `--tls-profile`); e.g. `chrome-132`, `firefox-136`, `safari-18`, `random`. If set, overrides `--tls-profile` and invite.
    #[arg(long)]
    fingerprint: Option<String>,

    /// Stealth bundle: `default` (v1.1.x-like), `balanced`, `aggressive` — fills pad/jitter/decoy when explicit flags are absent.
    #[arg(long)]
    stealth_profile: Option<String>,

    /// `simple` or `browser` (richer decoy headers). Omitted: from `--stealth-profile` or `simple`.
    #[arg(long)]
    decoy_mode: Option<String>,

    /// `off`, `split2`, `fakedsplit`, `disorder` (advisory on most platforms).
    #[arg(long)]
    desync_mode: Option<String>,

    /// `off`, `md5sig`, `badseq`, `badsum` (advisory; raw TCP options are not applied here).
    #[arg(long)]
    tcp_fooling: Option<String>,

    /// Request TLS record-level fragmentation (full support requires a different TLS stack / hook).
    #[arg(long, default_value_t = false)]
    tls_fragment: bool,

    /// Target parallel WSS sessions (this build: only 1; higher values are rejected on connect).
    #[arg(long, default_value_t = 1)]
    ws_parallel: u8,

    /// After N seconds without mux data, run an extra HTTPS decoy. Omit to use `--stealth-profile` (balanced/aggressive: 10s); `0` = off.
    #[arg(long)]
    idle_decoy_secs: Option<u64>,

    /// Outer WSS transport: `rustls` (default) or `boring` (BoringSSL, optional record splitting with `--tls-fragment`). Build: `--features boring-tls`.
    #[arg(long, default_value = "rustls")]
    tls_stack: String,
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
        ws_jitter_min_ms,
        ws_jitter_max_ms,
        udp_max_pad,
        udp_max_ws_binary,
        udp_mux_reply_timeout_secs,
        insecure_tls,
        proto,
        proto_domain,
    ) = if let Some(ref inv) = inv_opt {
        let (h, p) = parse_host_port(inv.server.trim()).context("invite server")?;
        let sni = args.sni.clone().unwrap_or_else(|| inv.sni.clone());
        (
            h,
            p,
            sni,
            inv.token.clone(),
            inv.max_pad,
            inv.junk_frames,
            inv.early_ws_frames,
            inv.psk.clone(),
            inv.decoy_max,
            inv.max_ws_binary,
            inv.ws_ping_secs,
            inv.ws_ping_jitter_percent,
            inv.ws_binary_send_jitter_ms,
            inv.ws_jitter_min_ms,
            inv.ws_jitter_max_ms,
            inv.udp_max_pad,
            inv.udp_max_ws_binary,
            inv.udp_mux_reply_timeout_secs,
            args.insecure || inv.insecure,
            inv.proto,
            inv
                .proto_domain
                .clone()
                .unwrap_or_default(),
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
            args.ws_jitter_min_ms,
            args.ws_jitter_max_ms,
            args.udp_max_pad,
            args.udp_max_ws_binary,
            args.udp_mux_reply_timeout_secs,
            args.insecure,
            args.proto,
            args.proto_domain.clone(),
        )
    };

    let stealth_for_merge: Option<StealthProfile> = (|| {
        let a = args
            .stealth_profile
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(s) = a {
            return StealthProfile::from_str(s);
        }
        if let Some(ref inv) = inv_opt {
            if let Some(s) = inv
                .stealth_profile
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return StealthProfile::from_str(s);
            }
        }
        Ok(None)
    })()
    .context("stealth profile")?;
    let pr_opt = stealth_for_merge.map(preset);
    let (ws_jitter_min_ms, ws_jitter_max_ms) = apply_preset_ws_jitter(
        pr_opt.as_ref(),
        ws_jitter_min_ms,
        ws_jitter_max_ms,
    );

    let invite_tls: Option<TlsClientProfile> = if let Some(ref inv) = inv_opt {
        tls_profile_from_invite(inv).context("invite TLS profile")?
    } else {
        None
    };
    let tls_profile = bibavpn::client_policy::resolve_tls_client_profile(
        args.fingerprint.as_deref(),
        args.tls_profile.as_deref(),
        stealth_for_merge,
        invite_tls,
    )
    .context("tls profile resolution")?;

    let ws_path = normalize_ws_path(
        args.ws_path
            .as_deref()
            .or(inv_opt.as_ref().and_then(|i| i.ws_path.as_deref()))
            .unwrap_or("/ws"),
    );

    let use_tcp_mux = if args.no_mux {
        false
    } else {
        inv_opt
            .as_ref()
            .map(|i| i.use_tcp_mux)
            .unwrap_or(true)
    };

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
                    pr_opt
                        .as_ref()
                        .map(|p| p.pad_mode)
                        .unwrap_or_default()
                }
            } else {
                pr_opt
                    .as_ref()
                    .map(|p| p.pad_mode)
                    .unwrap_or_default()
            }
        }
    };

    let dummy_interval_secs = args
        .dummy_interval_secs
        .or(inv_opt.as_ref().and_then(|i| i.dummy_interval_secs))
        .or_else(|| pr_opt.as_ref().map(|p| p.dummy_interval_secs))
        .unwrap_or(0);

    let decoy_gets_paths: Vec<String> = {
        let from_args: Vec<String> = args
            .decoy_gets_paths
            .as_ref()
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if !from_args.is_empty() {
            from_args
        } else if let Some(ref inv) = inv_opt {
            inv.decoy_gets_paths
                .as_deref()
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        }
    };

    let pinned_certs_pem = if !args.pin_cert.is_empty() {
        let mut buf = Vec::new();
        for p in &args.pin_cert {
            buf.extend(
                std::fs::read(p).with_context(|| format!("read --pin-cert {}", p.display()))?,
            );
            buf.push(b'\n');
        }
        Some(buf)
    } else {
        inv_opt
            .as_ref()
            .and_then(|i| {
                i.pin_cert_pem
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.as_bytes().to_vec())
            })
    };

    let reality_public_key: Option<[u8; 32]> = if let Some(pubkey_b64) = args.reality_public_key.as_ref() {
        let pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode(pubkey_b64.trim())
            .context("decode --reality-public-key (base64)")?;
        anyhow::ensure!(pubkey_bytes.len() == 32, "reality public key must be 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pubkey_bytes);
        Some(arr)
    } else if let Some(ref inv) = inv_opt {
        inv.reality_public_key_parsed()
            .context("invite reality_public_key")?
    } else {
        None
    };

    let reality_short_id: Option<[u8; 8]> = if let Some(s) = args.reality_short_id.as_ref() {
        let bytes = hex::decode(s.trim()).context("decode --reality-short-id (hex)")?;
        anyhow::ensure!(bytes.len() == 8, "short id must be 8 bytes (16 hex digits)");
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else if let Some(ref inv) = inv_opt {
        inv.reality_short_id_parsed()
            .context("invite reality_short_id")?
    } else {
        None
    };

    let reality_target: Option<String> = args
        .reality_target
        .clone()
        .or_else(|| inv_opt.as_ref().and_then(|i| i.reality_target.clone()));
    {
        let reality_any = reality_target.is_some() || reality_public_key.is_some() || reality_short_id.is_some();
        if reality_any {
            anyhow::ensure!(
                reality_target.is_some() && reality_public_key.is_some(),
                "REALITY mode requires both target and public key (CLI or biba://)"
            );
        }
    }

    let decoy_gets = if let Some(ref pr) = pr_opt {
        pr.decoy_gets
    } else if let Some(ref inv) = inv_opt {
        inv.decoy_gets
    } else {
        args.decoy_gets
    };
    let decoy_gets_interval_secs = if let Some(ref inv) = inv_opt {
        inv.decoy_gets_interval_secs
    } else {
        args.decoy_gets_interval_secs
    };
    let decoy_mode: DecoyMode = (|| -> anyhow::Result<DecoyMode> {
        if let Some(s) = args
            .decoy_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return DecoyMode::from_str(s).context("--decoy-mode");
        }
        if let Some(ref inv) = inv_opt {
            if let Some(s) = inv
                .decoy_mode
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return DecoyMode::from_str(s).context("invite decoy_mode");
            }
        }
        Ok(pr_opt.as_ref().map(|p| p.decoy_mode).unwrap_or_default())
    })()?;
    let desync_mode: DesyncMode = (|| -> anyhow::Result<DesyncMode> {
        if let Some(s) = args
            .desync_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return DesyncMode::from_str(s).context("--desync-mode");
        }
        if let Some(ref inv) = inv_opt {
            if let Some(s) = inv
                .desync_mode
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return DesyncMode::from_str(s).context("invite desync_mode");
            }
        }
        Ok(DesyncMode::default())
    })()?;
    let tcp_fooling: TcpFooling = (|| -> anyhow::Result<TcpFooling> {
        if let Some(s) = args
            .tcp_fooling
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return TcpFooling::from_str(s).context("--tcp-fooling");
        }
        if let Some(ref inv) = inv_opt {
            if let Some(s) = inv
                .tcp_fooling
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return TcpFooling::from_str(s).context("invite tcp_fooling");
            }
        }
        Ok(TcpFooling::default())
    })()?;
    let tls_stack: TlsStack = if let Some(ref inv) = inv_opt {
        inv.tls_stack
            .parse()
            .context("invite tls_stack")?
    } else {
        args.tls_stack.parse().context("--tls-stack")?
    };
    let tls_fragment = inv_opt
        .as_ref()
        .map(|i| i.tls_fragment)
        .unwrap_or(args.tls_fragment);
    let ws_parallel = inv_opt
        .as_ref()
        .map(|i| i.ws_parallel)
        .unwrap_or(args.ws_parallel);

    let socks_auth: Option<(String, String)> = if let Some(ref inv) = inv_opt {
        let u = inv
            .socks_auth_user
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let p = inv
            .socks_auth_password
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (u, p) {
            (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
            (None, None) => None,
            _ => anyhow::bail!("invite: set both socks_auth_user and socks_auth_password, or neither"),
        }
    } else {
        None
    };

    let mut extra = Vec::new();
    if let Some(ref inv) = inv_opt {
        for line in &inv.ws_headers {
            extra.push(
                parse_ws_header(line)
                    .with_context(|| format!("invite ws header {line:?}"))?,
            );
        }
    }
    for line in &args.ws_headers {
        extra.push(parse_ws_header(line)?);
    }

    let socks_bind = inv_opt
        .as_ref()
        .and_then(|i| {
            i.socks_bind
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .unwrap_or_else(|| args.socks5.clone());
    let http_proxy_bind: Option<String> = args
        .http_proxy
        .clone()
        .or_else(|| inv_opt.as_ref().and_then(|i| i.http_proxy.clone()));
    let ws_host = args
        .ws_host
        .clone()
        .or_else(|| inv_opt.as_ref().and_then(|i| i.ws_host.clone()));
    let ws_origin = args
        .ws_origin
        .clone()
        .or_else(|| inv_opt.as_ref().and_then(|i| i.ws_origin.clone()));
    let ws_user_agent = args
        .ws_user_agent
        .clone()
        .or_else(|| inv_opt.as_ref().and_then(|i| i.ws_user_agent.clone()));
    let ws_accept_language = args
        .ws_accept_language
        .clone()
        .or_else(|| inv_opt.as_ref().and_then(|i| i.ws_accept_language.clone()));
    let idle_merged = args
        .idle_decoy_secs
        .or(inv_opt.as_ref().and_then(|i| i.idle_decoy_secs));
    let idle_decoy_secs = merge_idle_decoy_secs(idle_merged, pr_opt.as_ref());

    let opts = LocalClientOptions {
        server_host,
        server_port,
        sni: sni_owned,
        token,
        socks_bind,
        socks_auth,
        http_proxy_bind,
        insecure_tls,
        max_pad,
        junk_frames,
        early_ws_frames,
        psk,
        decoy_max,
        ws_host,
        ws_origin,
        ws_user_agent,
        ws_accept_language,
        ws_extra_headers: Arc::new(extra),
        max_ws_binary,
        ws_ping_secs,
        ws_ping_jitter_percent,
        ws_binary_send_jitter_ms,
        ws_jitter_min_ms,
        ws_jitter_max_ms,
        udp_max_pad,
        udp_max_ws_binary,
        udp_mux_reply_timeout_secs,
        tls_profile,
        pinned_certs_pem,
        ws_path,
        use_tcp_mux,
        pad_mode,
        dummy_interval_secs,
        decoy_gets,
        decoy_gets_interval_secs,
        decoy_gets_paths,
        proto,
        proto_domain,
        reality_target,
        reality_public_key,
        reality_short_id,
        decoy_mode,
        desync_mode,
        tcp_fooling,
        tls_fragment,
        ws_parallel,
        idle_decoy_secs,
        stealth_profile: stealth_for_merge,
        tls_stack,
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
