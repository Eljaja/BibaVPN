//! Конфиг старта клиента в виде JSON — тот же формат, что у Android `nativeStart` / `bibavpn-jni`.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use serde::Deserialize;

use crate::local_client::{
    normalize_ws_path, parse_host_port, parse_ws_header, LocalClientOptions,
    DEFAULT_CLIENT_MAX_WS_BINARY, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use crate::tls_util::TlsClientProfile;
use crate::{decode_invite_v1, InviteV1, PadMode};

#[derive(Deserialize)]
struct StartJson {
    #[serde(default)]
    server: String,
    #[serde(default = "default_token")]
    token: String,
    sni: Option<String>,
    #[serde(default = "default_socks")]
    socks_bind: String,
    http_proxy: Option<String>,
    #[serde(default)]
    insecure: bool,
    #[serde(default = "default_max_pad")]
    max_pad: u8,
    #[serde(default)]
    junk_frames: u32,
    #[serde(default)]
    early_ws_frames: u8,
    psk: Option<String>,
    #[serde(default)]
    decoy_max: u8,
    ws_host: Option<String>,
    ws_origin: Option<String>,
    ws_user_agent: Option<String>,
    ws_accept_language: Option<String>,
    #[serde(default)]
    ws_headers: Vec<String>,
    #[serde(default = "default_max_ws_binary")]
    max_ws_binary: usize,
    #[serde(default = "default_ws_ping")]
    ws_ping_secs: u64,
    #[serde(default)]
    from_invite: Option<String>,
    #[serde(default)]
    invite_passphrase: Option<String>,
    #[serde(default)]
    tls_profile: Option<String>,
    #[serde(default)]
    ws_ping_jitter_percent: u8,
    #[serde(default)]
    ws_binary_send_jitter_ms: u8,
    #[serde(default)]
    udp_max_pad: Option<u8>,
    #[serde(default)]
    udp_max_ws_binary: Option<usize>,
    #[serde(default = "default_udp_mux_reply_timeout")]
    udp_mux_reply_timeout_secs: u64,
    #[serde(default)]
    pin_cert_pem: Option<String>,
    #[serde(default)]
    ws_path: Option<String>,
    #[serde(default = "default_true")]
    use_tcp_mux: bool,
    #[serde(default)]
    pad_mode: Option<String>,
    #[serde(default)]
    dummy_interval_secs: Option<u64>,
    #[serde(default)]
    decoy_gets: bool,
    #[serde(default = "default_decoy_interval")]
    decoy_gets_interval_secs: u64,
    #[serde(default)]
    decoy_gets_paths: Option<String>,
}

fn default_token() -> String {
    "change-me".to_string()
}

fn default_socks() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_max_pad() -> u8 {
    64
}

fn default_max_ws_binary() -> usize {
    DEFAULT_CLIENT_MAX_WS_BINARY
}

fn default_ws_ping() -> u64 {
    25
}

fn default_udp_mux_reply_timeout() -> u64 {
    DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS
}

fn default_true() -> bool {
    true
}

fn default_decoy_interval() -> u64 {
    30
}

/// Разбор JSON так же, как в Android `BibaNative.nativeStart`.
pub fn local_client_options_from_json_str(s: &str) -> anyhow::Result<LocalClientOptions> {
    let j: StartJson = serde_json::from_str(s)?;
    start_json_into_options(j)
}

/// Подставляет локальные `socks_bind` и опционально `http_proxy` (системный прокси на Windows/macOS).
pub fn local_client_options_from_json_str_with_binds(
    json: &str,
    socks_bind: String,
    http_proxy_bind: Option<String>,
) -> anyhow::Result<LocalClientOptions> {
    let mut v: serde_json::Value = serde_json::from_str(json)?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("config JSON must be an object"))?;
    obj.insert(
        "socks_bind".to_string(),
        serde_json::Value::String(socks_bind),
    );
    match http_proxy_bind {
        Some(h) => {
            obj.insert("http_proxy".to_string(), serde_json::Value::String(h));
        }
        None => {
            obj.remove("http_proxy");
        }
    }
    let s = serde_json::to_string(&v)?;
    local_client_options_from_json_str(&s)
}

fn start_json_into_options(j: StartJson) -> anyhow::Result<LocalClientOptions> {
    let invite_uri = j
        .from_invite
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let invite_pass = j
        .invite_passphrase
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let invite_pair: Option<InviteV1> = match (invite_uri, invite_pass) {
        (Some(uri), Some(pass)) => Some(decode_invite_v1(uri, pass).context("decode invite")?),
        (None, None) => None,
        _ => anyhow::bail!("invite: set both from_invite and invite_passphrase, or neither"),
    };

    let mut extra = Vec::new();
    for line in &j.ws_headers {
        extra.push(parse_ws_header(line)?);
    }

    let pinned_certs_pem = j
        .pin_cert_pem
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec());

    let (
        server_host,
        server_port,
        sni,
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
        tls_profile,
    ) = if let Some(ref inv) = invite_pair {
        let (h, p) = parse_host_port(inv.server.trim()).context("invite server")?;
        let sni = j.sni.clone().unwrap_or_else(|| inv.sni.clone());
        let tls_s = j
            .tls_profile
            .as_ref()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|s| s.to_string())
            .unwrap_or(inv.tls_profile.clone());
        let tls_profile = tls_s.parse::<TlsClientProfile>().context("tls_profile")?;
        (
            h,
            p,
            sni,
            inv.token.clone(),
            inv.max_pad,
            j.junk_frames,
            j.early_ws_frames,
            inv.psk.clone(),
            inv.decoy_max,
            inv.max_ws_binary,
            inv.ws_ping_secs,
            inv.ws_ping_jitter_percent,
            inv.ws_binary_send_jitter_ms,
            inv.udp_max_pad,
            inv.udp_max_ws_binary,
            inv.udp_mux_reply_timeout_secs,
            j.insecure || inv.insecure,
            tls_profile,
        )
    } else {
        if j.server.trim().is_empty() {
            anyhow::bail!("server is required when not using invite");
        }
        let (h, p) = parse_host_port(j.server.trim()).context("server")?;
        let sni = j.sni.clone().unwrap_or_else(|| h.clone());
        let tls_s = j
            .tls_profile
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let tls_s = if tls_s.trim().is_empty() {
            "default".to_string()
        } else {
            tls_s
        };
        let tls_profile = tls_s.parse::<TlsClientProfile>().context("tls_profile")?;
        (
            h,
            p,
            sni,
            j.token,
            j.max_pad,
            j.junk_frames,
            j.early_ws_frames,
            j.psk.clone(),
            j.decoy_max,
            j.max_ws_binary,
            j.ws_ping_secs,
            j.ws_ping_jitter_percent,
            j.ws_binary_send_jitter_ms,
            j.udp_max_pad,
            j.udp_max_ws_binary,
            j.udp_mux_reply_timeout_secs,
            j.insecure,
            tls_profile,
        )
    };

    let ws_path = normalize_ws_path(
        j.ws_path
            .as_deref()
            .or(invite_pair.as_ref().and_then(|i| i.ws_path.as_deref()))
            .unwrap_or("/ws"),
    );

    let use_tcp_mux = j.use_tcp_mux;

    let pad_mode: PadMode = match j
        .pad_mode
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(s) => PadMode::from_str(s).context("pad_mode")?,
        None => {
            if let Some(ref inv) = invite_pair {
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

    let dummy_interval_secs = j
        .dummy_interval_secs
        .or(invite_pair.as_ref().and_then(|i| i.dummy_interval_secs))
        .unwrap_or(0);

    let decoy_gets_paths: Vec<String> = j
        .decoy_gets_paths
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    Ok(LocalClientOptions {
        server_host,
        server_port,
        sni,
        token,
        socks_bind: j.socks_bind,
        http_proxy_bind: j.http_proxy,
        insecure_tls,
        max_pad,
        junk_frames,
        early_ws_frames,
        psk,
        decoy_max,
        ws_host: j.ws_host,
        ws_origin: j.ws_origin,
        ws_user_agent: j.ws_user_agent,
        ws_accept_language: j.ws_accept_language,
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
        decoy_gets: j.decoy_gets,
        decoy_gets_interval_secs: j.decoy_gets_interval_secs,
        decoy_gets_paths,
    })
}
