//! Конфиг старта клиента в виде JSON — тот же формат, что у Android `nativeStart` / крейта `bibavpn-jni` (`apps/bibavpn-jni`).

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use serde::Deserialize;
use tracing::info;

use crate::local_client::{
    normalize_ws_path, parse_host_port, parse_ws_header, LocalClientOptions,
    DEFAULT_CLIENT_MAX_WS_BINARY, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use crate::logging::{self, LogConfig, LogFormat};
use crate::stealth_v12::{DecoyMode, DesyncMode, StealthProfile, TcpFooling};
use crate::client_policy::tls_profile_from_invite;
use crate::startup_secrets::{
    client_reality_configured, require_psk, validate_resolved_token,
};
use crate::tls_util::{TlsClientProfile, TlsStack};
use crate::{decode_invite_v1, InviteV1, PadMode};

#[derive(Deserialize)]
struct StartJson {
    #[serde(default)]
    server: String,
    /// Omitted or null: use invite token when `from_invite` is set; otherwise required.
    #[serde(default)]
    token: Option<String>,
    sni: Option<String>,
    #[serde(default = "default_socks")]
    socks_bind: String,
    #[serde(default)]
    socks_auth_user: Option<String>,
    #[serde(default)]
    socks_auth_password: Option<String>,
    /// Domains that should bypass the tunnel (split routing). On full-TUN clients
    /// (mobile) these are matched via the DNS snoop; see `domain_route`.
    #[serde(default)]
    split_bypass_domains: Vec<String>,
    http_proxy: Option<String>,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    max_pad: Option<u8>,
    #[serde(default)]
    junk_frames: Option<u32>,
    #[serde(default)]
    early_ws_frames: Option<u8>,
    psk: Option<String>,
    #[serde(default)]
    decoy_max: Option<u8>,
    ws_host: Option<String>,
    ws_origin: Option<String>,
    ws_user_agent: Option<String>,
    ws_accept_language: Option<String>,
    #[serde(default)]
    ws_headers: Vec<String>,
    #[serde(default)]
    max_ws_binary: Option<usize>,
    #[serde(default)]
    ws_ping_secs: Option<u64>,
    #[serde(default)]
    from_invite: Option<String>,
    #[serde(default)]
    invite_passphrase: Option<String>,
    #[serde(default)]
    tls_profile: Option<String>,
    #[serde(default)]
    ws_ping_jitter_percent: Option<u8>,
    #[serde(default)]
    ws_binary_send_jitter_ms: Option<u8>,
    #[serde(default)]
    ws_jitter_min_ms: Option<u8>,
    #[serde(default)]
    ws_jitter_max_ms: Option<u8>,
    #[serde(default)]
    udp_max_pad: Option<u8>,
    #[serde(default)]
    udp_max_ws_binary: Option<usize>,
    #[serde(default)]
    udp_mux_reply_timeout_secs: Option<u64>,
    #[serde(default)]
    pin_cert_pem: Option<String>,
    #[serde(default)]
    ws_path: Option<String>,
    #[serde(default)]
    use_tcp_mux: Option<bool>,
    #[serde(default)]
    pad_mode: Option<String>,
    #[serde(default)]
    dummy_interval_secs: Option<u64>,
    #[serde(default)]
    decoy_gets: Option<bool>,
    #[serde(default)]
    decoy_gets_interval_secs: Option<u64>,
    #[serde(default)]
    decoy_gets_paths: Option<String>,
    #[serde(default)]
    proto: Option<u8>,
    #[serde(default)]
    proto_domain: Option<String>,
    /// `simple` or `browser` (BibaV1.2). Omit for defaults.
    #[serde(default)]
    decoy_mode: Option<String>,
    /// `off`, `split2`, `fakedsplit`, `disorder` (advisory; platform hooks are limited).
    #[serde(default)]
    desync_mode: Option<String>,
    #[serde(default)]
    tcp_fooling: Option<String>,
    /// Request TLS record / frame fragmentation (not fully implemented for rustls).
    #[serde(default)]
    tls_fragment: bool,
    /// Parallel WSS for TCP mux (1–4 when set; matches `bibavpn-client --ws-parallel`).
    #[serde(default)]
    ws_parallel: Option<u8>,
    #[serde(default)]
    mux_window_mib: crate::tcp_mux::MuxWindow,
    #[serde(default)]
    idle_decoy_secs: Option<u64>,
    #[serde(default)]
    stealth_profile: Option<String>,
    /// `rustls` (default) or `boring` (Boring build + feature on client).
    #[serde(default)]
    tls_stack: Option<String>,
    /// Same as client `--fingerprint` (e.g. `chrome-132`); takes precedence over `tls_profile` and invite.
    #[serde(default)]
    fingerprint: Option<String>,
    /// When `RUST_LOG` is unset, default filter level (Android / desktop JSON start).
    #[serde(default)]
    log_level: Option<String>,
    /// `plain` or `json`.
    #[serde(default)]
    log_format: Option<String>,
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

fn default_decoy_interval() -> u64 {
    30
}

/// Пустая/пробельная строка в JSON не должна перекрывать invite (`Some("")` раньше ломало `proto_domain` / `sni` → ACK mac mismatch на втором WSS).
fn json_or_invite_str(json_field: Option<String>, invite_field: Option<String>) -> Option<String> {
    if let Some(s) = json_field {
        let t = s.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    invite_field.and_then(|s| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    })
}

fn short_hash8(s: &str) -> String {
    let hex = blake3::hash(s.as_bytes()).to_hex().to_string();
    hex[..8].to_string()
}

/// Разбор JSON так же, как в Android `BibaNative.nativeStart`.
pub fn local_client_options_from_json_str(s: &str) -> anyhow::Result<LocalClientOptions> {
    let j: StartJson = serde_json::from_str(s)?;
    logging::init(LogConfig {
        level: logging::level_directive(j.log_level.as_deref().unwrap_or("info"))?,
        format: j
            .log_format
            .as_deref()
            .unwrap_or("plain")
            .parse::<LogFormat>()
            .context("log_format")?,
        filter: None,
    })?;
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
    // Install domain split-routing bypass list (empty = disabled).
    crate::domain_route::set_bypass_domains(&j.split_bypass_domains);
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

    let stealth_for_merge: Option<StealthProfile> = (|| -> anyhow::Result<Option<StealthProfile>> {
        if let Some(s) = j
            .stealth_profile
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Ok(Some(
                StealthProfile::from_str(s).context("stealth_profile")?,
            ));
        }
        if let Some(ref inv) = invite_pair {
            if let Some(s) = inv
                .stealth_profile
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                return Ok(Some(
                    StealthProfile::from_str(s).context("invite stealth_profile")?,
                ));
            }
        }
        Ok(None)
    })()
    .context("stealth_profile")?;
    let pr_opt: Option<crate::stealth_v12::StealthPreset> =
        stealth_for_merge.map(crate::stealth_v12::preset);

    let (
        server_host,
        server_port,
        sni,
        max_pad,
        junk_frames,
        early_ws_frames,
        decoy_max,
        max_ws_binary,
        ws_ping_secs,
        ws_ping_jitter_percent,
        ws_binary_send_jitter_ms,
        udp_max_pad,
        udp_max_ws_binary,
        udp_mux_reply_timeout_secs,
        insecure_tls,
    ) = if let Some(ref inv) = invite_pair {
        let (h, p) = parse_host_port(inv.server.trim()).context("invite server")?;
        let sni = json_or_invite_str(j.sni.clone(), Some(inv.sni.clone()))
            .unwrap_or_else(|| inv.sni.clone());
        (
            h,
            p,
            sni,
            j.max_pad.unwrap_or(inv.max_pad),
            j.junk_frames.unwrap_or(inv.junk_frames),
            j.early_ws_frames.unwrap_or(inv.early_ws_frames),
            j.decoy_max.unwrap_or(inv.decoy_max),
            j.max_ws_binary.unwrap_or(inv.max_ws_binary),
            j.ws_ping_secs.unwrap_or(inv.ws_ping_secs),
            j.ws_ping_jitter_percent
                .unwrap_or(inv.ws_ping_jitter_percent),
            j.ws_binary_send_jitter_ms
                .unwrap_or(inv.ws_binary_send_jitter_ms),
            j.udp_max_pad.or(inv.udp_max_pad),
            j.udp_max_ws_binary.or(inv.udp_max_ws_binary),
            j.udp_mux_reply_timeout_secs
                .unwrap_or(inv.udp_mux_reply_timeout_secs),
            j.insecure || inv.insecure,
        )
    } else {
        if j.server.trim().is_empty() {
            anyhow::bail!("server is required when not using invite");
        }
        let (h, p) = parse_host_port(j.server.trim()).context("server")?;
        let sni = json_or_invite_str(j.sni.clone(), None).unwrap_or_else(|| h.clone());
        (
            h,
            p,
            sni,
            j.max_pad.unwrap_or_else(default_max_pad),
            j.junk_frames.unwrap_or(0),
            j.early_ws_frames.unwrap_or(0),
            j.decoy_max.unwrap_or(0),
            j.max_ws_binary.unwrap_or_else(default_max_ws_binary),
            j.ws_ping_secs.unwrap_or_else(default_ws_ping),
            j.ws_ping_jitter_percent.unwrap_or(0),
            j.ws_binary_send_jitter_ms.unwrap_or(0),
            j.udp_max_pad,
            j.udp_max_ws_binary,
            j.udp_mux_reply_timeout_secs
                .unwrap_or_else(default_udp_mux_reply_timeout),
            j.insecure,
        )
    };

    let token = if let Some(ref inv) = invite_pair {
        let inv_t = inv.token.trim();
        match j.token.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => inv.token.clone(),
            Some(t) if t == inv_t => inv.token.clone(),
            Some(_) => {
                anyhow::bail!(
                    "JSON `token` disagrees with invite token; remove `token` from JSON or match the invite"
                );
            }
        }
    } else {
        j.token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("token is required when not using invite"))?
    };
    validate_resolved_token(&token)?;

    let psk = if let Some(ref inv) = invite_pair {
        let from_j = j
            .psk
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        match (&from_j, &inv.psk) {
            (Some(a), Some(b)) if a != b => {
                anyhow::bail!(
                    "JSON `psk` disagrees with invite `psk`; remove one field or align values"
                );
            }
            (Some(a), _) => Some(a.clone()),
            (None, _) => inv.psk.clone(),
        }
    } else {
        j.psk.clone()
    };

    let mut extra = Vec::new();
    if let Some(ref inv) = invite_pair {
        for line in &inv.ws_headers {
            extra.push(
                parse_ws_header(line)
                    .with_context(|| format!("invite ws header {line:?}"))?,
            );
        }
    }
    for line in &j.ws_headers {
        extra.push(parse_ws_header(line)?);
    }

    let pinned_certs_pem = j
        .pin_cert_pem
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.as_bytes().to_vec())
        .or_else(|| {
            invite_pair
                .as_ref()
                .and_then(|i| {
                    i.pin_cert_pem
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.as_bytes().to_vec())
                })
        });

    let base_jmin = j
        .ws_jitter_min_ms
        .or(invite_pair.as_ref().map(|i| i.ws_jitter_min_ms))
        .unwrap_or(0);
    let base_jmax = j
        .ws_jitter_max_ms
        .or(invite_pair.as_ref().map(|i| i.ws_jitter_max_ms))
        .unwrap_or(0);
    // Explicit timing (including zero) must not be overwritten by a preset.
    let explicit_jitter = j.ws_jitter_min_ms.is_some()
        || j.ws_jitter_max_ms.is_some()
        || j.ws_binary_send_jitter_ms.is_some();
    let (ws_jitter_min_ms, ws_jitter_max_ms) = crate::stealth_v12::apply_preset_ws_jitter(
        if explicit_jitter {
            None
        } else {
            pr_opt.as_ref()
        },
        base_jmin,
        base_jmax,
    );

    let ws_path = normalize_ws_path(
        j.ws_path
            .as_deref()
            .or(invite_pair.as_ref().and_then(|i| i.ws_path.as_deref()))
            .unwrap_or("/ws"),
    );

    let use_tcp_mux = j
        .use_tcp_mux
        .or(invite_pair.as_ref().map(|i| i.use_tcp_mux))
        .unwrap_or(true);

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
                    pr_opt
                        .as_ref()
                        .map(|p| p.pad_mode)
                        .unwrap_or_default()
                }
            } else {
                pr_opt.as_ref().map(|p| p.pad_mode).unwrap_or_default()
            }
        }
    };

    let dummy_interval_secs = j
        .dummy_interval_secs
        .or(invite_pair.as_ref().and_then(|i| i.dummy_interval_secs))
        .or_else(|| pr_opt.as_ref().map(|p| p.dummy_interval_secs))
        .unwrap_or(0);

    let decoy_gets_paths: Vec<String> = {
        let from_j: Vec<String> = j
            .decoy_gets_paths
            .as_ref()
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if !from_j.is_empty() {
            from_j
        } else if let Some(ref inv) = invite_pair {
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

    let proto = j
        .proto
        .unwrap_or_else(|| invite_pair.as_ref().map(|i| i.proto).unwrap_or(3));
    let proto_domain = json_or_invite_str(
        j.proto_domain.clone(),
        invite_pair.as_ref().and_then(|i| i.proto_domain.clone()),
    )
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| "default".to_string());

    let invite_tls: Option<TlsClientProfile> = match invite_pair.as_ref() {
        Some(inv) => tls_profile_from_invite(inv).context("invite tls")?,
        None => None,
    };
    let tls_profile: TlsClientProfile = crate::client_policy::resolve_tls_client_profile(
        j.fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        j.tls_profile.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        stealth_for_merge,
        invite_tls,
    )
    .context("tls_profile")?;

    let decoy_gets = if let Some(value) = j.decoy_gets {
        value
    } else if let Some(ref pr) = pr_opt {
        pr.decoy_gets
    } else if let Some(ref inv) = invite_pair {
        inv.decoy_gets
    } else {
        false
    };
    let decoy_gets_interval_secs = j.decoy_gets_interval_secs
        .or(invite_pair.as_ref().map(|i| i.decoy_gets_interval_secs))
        .unwrap_or_else(default_decoy_interval);

    let decoy_mode: DecoyMode = (|| -> anyhow::Result<DecoyMode> {
        if let Some(s) = j
            .decoy_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return DecoyMode::from_str(s).context("decoy_mode");
        }
        if let Some(ref inv) = invite_pair {
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
        if let Some(s) = j
            .desync_mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return DesyncMode::from_str(s).context("desync_mode");
        }
        if let Some(ref inv) = invite_pair {
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
        if let Some(s) = j
            .tcp_fooling
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return TcpFooling::from_str(s).context("tcp_fooling");
        }
        if let Some(ref inv) = invite_pair {
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

    let tls_stack: TlsStack = (|| -> anyhow::Result<TlsStack> {
        if let Some(s) = j
            .tls_stack
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return TlsStack::from_str(s);
        }
        if let Some(ref inv) = invite_pair {
            return inv
                .tls_stack
                .parse()
                .context("invite tls_stack");
        }
        Ok(TlsStack::Rustls)
    })()?;

    let tls_fragment = if let Some(ref inv) = invite_pair {
        inv.tls_fragment
    } else {
        j.tls_fragment
    };
    // JSON (Android `nativeStart`, CLI `--config`) must override invite: invite often embeds ws_parallel>1,
    // but the outer JSON may cap it for UDP mux / connection limits.
    let ws_parallel = match j.ws_parallel {
        Some(jp) => jp.max(1).min(4),
        None => invite_pair
            .as_ref()
            .map(|i| i.ws_parallel)
            .unwrap_or(1)
            .max(1)
            .min(4),
    };

    let socks_auth: Option<(String, String)> = {
        let u = j
            .socks_auth_user
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        let p = j
            .socks_auth_password
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        match (u, p) {
            (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
            (None, None) => {
                if let Some(ref inv) = invite_pair {
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
                        _ => anyhow::bail!(
                            "invite: set both socks_auth_user and socks_auth_password, or neither"
                        ),
                    }
                } else {
                    None
                }
            }
            _ => anyhow::bail!(
                "socks_auth: set both socks_auth_user and socks_auth_password, or omit both"
            ),
        }
    };

    let reality_target: Option<String> = invite_pair
        .as_ref()
        .and_then(|i| i.reality_target.clone());
    let reality_public_key: Option<[u8; 32]> = if let Some(ref inv) = invite_pair {
        inv.reality_public_key_parsed()
            .context("invite reality_public_key")?
    } else {
        None
    };
    let reality_short_id: Option<[u8; 8]> = if let Some(ref inv) = invite_pair {
        inv.reality_short_id_parsed()
            .context("invite reality_short_id")?
    } else {
        None
    };
    {
        let r_any = reality_target.is_some()
            || reality_public_key.is_some()
            || reality_short_id.is_some();
        if r_any {
            anyhow::ensure!(
                reality_target.is_some() && reality_public_key.is_some(),
                "REALITY mode requires both target and public key in invite (or in JSON, when added)"
            );
        }
    }

    let reality_configured =
        client_reality_configured(reality_target.as_deref(), reality_public_key.as_ref());
    require_psk(psk.as_deref(), reality_configured, false)?;

    let sni = crate::reality::effective_tls_sni(&sni, reality_target.as_deref());

    let socks_bind = invite_pair
        .as_ref()
        .and_then(|i| {
            i.socks_bind
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .unwrap_or(j.socks_bind);

    let http_proxy_bind = json_or_invite_str(
        j.http_proxy.clone(),
        invite_pair.as_ref().and_then(|i| i.http_proxy.clone()),
    );
    let ws_host = json_or_invite_str(
        j.ws_host.clone(),
        invite_pair.as_ref().and_then(|i| i.ws_host.clone()),
    );
    let ws_origin = json_or_invite_str(
        j.ws_origin.clone(),
        invite_pair.as_ref().and_then(|i| i.ws_origin.clone()),
    );
    let ws_user_agent = json_or_invite_str(
        j.ws_user_agent.clone(),
        invite_pair.as_ref().and_then(|i| i.ws_user_agent.clone()),
    );
    let ws_accept_language = json_or_invite_str(
        j.ws_accept_language.clone(),
        invite_pair.as_ref().and_then(|i| i.ws_accept_language.clone()),
    );
    let idle_merged = j
        .idle_decoy_secs
        .or(invite_pair.as_ref().and_then(|i| i.idle_decoy_secs));
    let idle_decoy_secs =
        crate::stealth_v12::merge_idle_decoy_secs(idle_merged, pr_opt.as_ref());

    let effective_proto_domain = proto_domain.trim().to_string();
    info!(
        target: "bibavpn_client",
        invite = invite_pair.is_some(),
        final_sni = %sni,
        proto_domain = %proto_domain,
        effective_proto_domain = %effective_proto_domain,
        psk_present = psk.is_some(),
        psk_hash8 = psk.as_deref().map(short_hash8).unwrap_or_else(|| "-".to_string()),
        "start_json resolved transport identity"
    );

    Ok(LocalClientOptions {
        server_host,
        server_port,
        sni,
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
        mux_window_mib: j.mux_window_mib,
        idle_decoy_secs,
        stealth_profile: stealth_for_merge,
        tls_stack,
    })
}

#[cfg(test)]
mod merge_tests {
    use super::local_client_options_from_json_str;
    use crate::stealth_v12::StealthProfile;
    use crate::tls_util::TlsClientProfile;

    const BASE: &str =
        r#"{"server":"127.0.0.1:8443","token":"t","psk":"0123456789abcdef0123456789abcdef"}"#;

    #[test]
    fn json_without_token_or_invite_fails() {
        let j = r#"{"server":"127.0.0.1:8443","psk":"0123456789abcdef0123456789abcdef"}"#;
        assert!(local_client_options_from_json_str(j).is_err());
    }

    #[test]
    fn json_denylisted_token_fails() {
        let j = r#"{"server":"127.0.0.1:8443","token":"change-me","psk":"0123456789abcdef0123456789abcdef"}"#;
        assert!(local_client_options_from_json_str(j).is_err());
    }

    #[test]
    fn json_token_without_psk_or_reality_fails() {
        let j = r#"{"server":"127.0.0.1:8443","token":"t"}"#;
        assert!(local_client_options_from_json_str(j).is_err());
    }

    #[test]
    fn invite_without_json_token_ok() {
        use crate::invite_uri::{encode_invite_v1, InviteV1};

        let inv = InviteV1 {
            v: 1,
            server: "10.0.0.2:443".into(),
            sni: "vpn.example.com".into(),
            token: "tok".into(),
            proto: 3,
            proto_domain: None,
            psk: Some("0123456789abcdef0123456789abcdef".into()),
            decoy_max: 8,
            max_pad: 64,
            max_ws_binary: 1400,
            ws_ping_secs: 25,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            udp_max_pad: None,
            udp_max_ws_binary: None,
            udp_mux_reply_timeout_secs: 130,
            insecure: true,
            tls_profile: "default".into(),
            ws_path: None,
            pad_mode: None,
            dummy_interval_secs: None,
            http_proxy: None,
            socks_bind: None,
            socks_auth_user: None,
            socks_auth_password: None,
            junk_frames: 0,
            early_ws_frames: 0,
            ws_host: None,
            ws_origin: None,
            ws_user_agent: None,
            ws_accept_language: None,
            ws_headers: vec![],
            use_tcp_mux: true,
            decoy_gets: false,
            decoy_gets_interval_secs: 30,
            decoy_gets_paths: None,
            fingerprint: None,
            stealth_profile: None,
            decoy_mode: None,
            desync_mode: None,
            tcp_fooling: None,
            tls_fragment: false,
            ws_parallel: 1,
            idle_decoy_secs: None,
            tls_stack: "rustls".into(),
            reality_target: None,
            reality_public_key: None,
            reality_short_id: None,
            pin_cert_pem: None,
            server_ack_delay_min_ms: None,
            server_ack_delay_max_ms: None,
            rtt_mask_jitter_ms: None,
            ack_profile: None,
        };
        let uri = encode_invite_v1(&inv, "passphrase-test").unwrap();
        let j = format!(
            r#"{{"from_invite":"{uri}","invite_passphrase":"passphrase-test"}}"#
        );
        let o = local_client_options_from_json_str(&j).unwrap();
        assert_eq!(o.token, "tok");
    }

    #[test]
    fn proto_domain_defaults_to_default_label() {
        let o = local_client_options_from_json_str(BASE).unwrap();
        assert_eq!(o.proto_domain, "default");
    }

    #[test]
    fn mux_window_json_defaults_and_propagates_valid_values() {
        assert_eq!(local_client_options_from_json_str(BASE).unwrap().mux_window_mib.bytes(), 1048576);
        for (value, bytes) in [(1, 1048576), (2, 2097152), (3, 3145728), (4, 4194304)] {
            let mut json: serde_json::Value = serde_json::from_str(BASE).unwrap();
            json["mux_window_mib"] = value.into();
            assert_eq!(local_client_options_from_json_str(&json.to_string()).unwrap().mux_window_mib.bytes(), bytes);
        }
    }

    #[test]
    fn mux_window_json_rejects_out_of_range_values() {
        for value in [0, 5, 255] {
            let mut json: serde_json::Value = serde_json::from_str(BASE).unwrap();
            json["mux_window_mib"] = value.into();
            assert!(local_client_options_from_json_str(&json.to_string()).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn stealth_profile_and_ws_parallel_from_json() {
        let j = format!(
            r#"{{"server":"127.0.0.1:8443","token":"t","psk":"0123456789abcdef0123456789abcdef","stealth_profile":"balanced","ws_parallel":3,"proto_domain":"lab"}}"#
        );
        let o = local_client_options_from_json_str(&j).unwrap();
        assert_eq!(o.stealth_profile, Some(StealthProfile::Balanced));
        assert_eq!(o.ws_parallel, 3);
        assert_eq!(o.proto_domain, "lab");
        assert_eq!(o.tls_profile, TlsClientProfile::Chrome132);
    }

    #[test]
    fn fingerprint_overrides_tls_profile_in_json() {
        let j = r#"{"server":"127.0.0.1:8443","token":"t","psk":"0123456789abcdef0123456789abcdef","tls_profile":"firefox-136","fingerprint":"chrome-132"}"#;
        let o = local_client_options_from_json_str(j).unwrap();
        assert_eq!(o.tls_profile, TlsClientProfile::Chrome132);
    }

    #[test]
    fn invite_requires_passphrase_pair() {
        let j = r#"{"server":"127.0.0.1:1","token":"t","from_invite":"biba://x","psk":"0123456789abcdef0123456789abcdef"}"#;
        assert!(local_client_options_from_json_str(j).is_err());
    }

    #[test]
    fn empty_json_sni_does_not_block_invite_fields() {
        use crate::invite_uri::{encode_invite_v1, InviteV1};

        let inv = InviteV1 {
            v: 1,
            server: "10.0.0.2:443".into(),
            sni: "vpn.example.com".into(),
            token: "tok".into(),
            proto: 3,
            proto_domain: None,
            psk: Some("0123456789abcdef0123456789abcdef".into()),
            decoy_max: 8,
            max_pad: 64,
            max_ws_binary: 1400,
            ws_ping_secs: 25,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            udp_max_pad: None,
            udp_max_ws_binary: None,
            udp_mux_reply_timeout_secs: 130,
            insecure: true,
            tls_profile: "default".into(),
            ws_path: None,
            pad_mode: None,
            dummy_interval_secs: None,
            http_proxy: None,
            socks_bind: None,
            socks_auth_user: None,
            socks_auth_password: None,
            junk_frames: 0,
            early_ws_frames: 0,
            ws_host: None,
            ws_origin: None,
            ws_user_agent: None,
            ws_accept_language: None,
            ws_headers: vec![],
            use_tcp_mux: true,
            decoy_gets: false,
            decoy_gets_interval_secs: 30,
            decoy_gets_paths: None,
            fingerprint: None,
            stealth_profile: None,
            decoy_mode: None,
            desync_mode: None,
            tcp_fooling: None,
            tls_fragment: false,
            ws_parallel: 1,
            idle_decoy_secs: None,
            tls_stack: "rustls".into(),
            reality_target: None,
            reality_public_key: None,
            reality_short_id: None,
            pin_cert_pem: None,
            server_ack_delay_min_ms: None,
            server_ack_delay_max_ms: None,
            rtt_mask_jitter_ms: None,
            ack_profile: None,
        };
        let uri = encode_invite_v1(&inv, "passphrase-test").unwrap();
        let j = format!(
            r#"{{"from_invite":"{uri}","invite_passphrase":"passphrase-test","sni":"","psk":"0123456789abcdef0123456789abcdef"}}"#
        );
        let o = local_client_options_from_json_str(&j).unwrap();
        assert_eq!(o.sni, "vpn.example.com");
        assert_eq!(o.server_host, "10.0.0.2");
        assert_eq!(o.server_port, 443);
    }
}

#[cfg(test)]
mod performance_precedence_tests {
    use super::*;
    #[test]
    fn explicit_performance_defaults_override_invite() {
        let inv: InviteV1 = serde_json::from_value(serde_json::json!({
            "v": 1, "server": "vpn.example:443", "sni": "vpn.example", "token": "strong-token",
            "psk": "0123456789abcdef0123456789abcdef", "insecure": false,
            "max_pad": 99, "max_ws_binary": 1400, "decoy_max": 22,
            "ws_ping_secs": 77, "ws_ping_jitter_percent": 33,
            "ws_binary_send_jitter_ms": 9, "ws_jitter_min_ms": 4, "ws_jitter_max_ms": 8,
            "udp_max_pad": 88, "udp_max_ws_binary": 2000, "udp_mux_reply_timeout_secs": 99,
            "decoy_gets": true, "decoy_gets_interval_secs": 99, "use_tcp_mux": false, "ws_parallel": 4, "stealth_profile": "balanced"
        }))
        .unwrap();
        let uri = crate::invite_uri::encode_invite_v1(&inv, "benchmark-test").unwrap();
        let json = serde_json::json!({"from_invite":uri,"invite_passphrase":"benchmark-test","max_pad":64,"max_ws_binary":262144,"decoy_max":0,"ws_ping_secs":25,"ws_ping_jitter_percent":0,"ws_binary_send_jitter_ms":0,"ws_jitter_min_ms":0,"ws_jitter_max_ms":0,"udp_max_pad":0,"udp_max_ws_binary":262144,"udp_mux_reply_timeout_secs":0,"ws_parallel":1,"use_tcp_mux":true,"decoy_gets":false,"decoy_gets_interval_secs":30});
        let o = local_client_options_from_json_str(&json.to_string()).unwrap();
        assert_eq!(o.max_pad, 64, "max_pad");
        assert_eq!(o.max_ws_binary, 262144, "max_ws_binary");
        assert_eq!(o.decoy_max, 0, "decoy_max");
        assert_eq!(o.ws_ping_secs, 25, "ws_ping_secs");
        assert_eq!(o.ws_ping_jitter_percent, 0, "ws_ping_jitter_percent");
        assert_eq!(o.ws_binary_send_jitter_ms, 0, "ws_binary_send_jitter_ms");
        assert_eq!(o.ws_jitter_min_ms, 0, "ws_jitter_min_ms");
        assert_eq!(o.ws_jitter_max_ms, 0, "ws_jitter_max_ms");
        assert_eq!(o.udp_max_pad, Some(0), "udp_max_pad");
        assert_eq!(o.udp_max_ws_binary, Some(262144), "udp_max_ws_binary");
        assert_eq!(
            o.udp_mux_reply_timeout_secs, 0,
            "udp_mux_reply_timeout_secs"
        );
        assert_eq!(o.ws_parallel, 1, "ws_parallel");
        assert_eq!(o.use_tcp_mux, true);
        assert!(!o.insecure_tls);
        assert_eq!(o.decoy_gets_interval_secs, 30);
        assert!(!o.decoy_gets);
    }

    #[test]
    fn omitted_performance_settings_preserve_invite() {
        let inv: InviteV1 = serde_json::from_value(serde_json::json!({
            "v": 1, "server": "vpn.example:443", "sni": "vpn.example", "token": "strong-token",
            "psk": "0123456789abcdef0123456789abcdef", "insecure": false,
            "max_pad": 99, "max_ws_binary": 1400, "decoy_max": 22,
            "ws_ping_secs": 77, "ws_ping_jitter_percent": 33,
            "ws_binary_send_jitter_ms": 9, "ws_jitter_min_ms": 4, "ws_jitter_max_ms": 8,
            "udp_max_pad": 88, "udp_max_ws_binary": 2000, "udp_mux_reply_timeout_secs": 99,
            "decoy_gets": true, "decoy_gets_interval_secs": 99, "use_tcp_mux": false, "ws_parallel": 4, "stealth_profile": "balanced"
        }))
        .unwrap();
        let uri = crate::invite_uri::encode_invite_v1(&inv, "benchmark-test").unwrap();
        let json = serde_json::json!({"from_invite":uri,"invite_passphrase":"benchmark-test"});
        let o = local_client_options_from_json_str(&json.to_string()).unwrap();
        assert_eq!(o.max_pad, 99);
        assert_eq!(o.max_ws_binary, 1400);
        assert_eq!(o.decoy_max, 22);
        assert_eq!(o.ws_ping_secs, 77);
        assert_eq!(o.ws_ping_jitter_percent, 33);
        assert_eq!(o.ws_binary_send_jitter_ms, 9);
        assert_eq!(o.ws_jitter_min_ms, 4);
        assert_eq!(o.ws_jitter_max_ms, 8);
        assert_eq!(o.udp_max_pad, Some(88));
        assert_eq!(o.udp_max_ws_binary, Some(2000));
        assert_eq!(o.udp_mux_reply_timeout_secs, 99);
        assert_eq!(o.ws_parallel, 4);
        assert_eq!(o.use_tcp_mux, false);
    }

    #[test]
    fn explicit_zero_jitter_disables_preset_without_invite() {
        let json = serde_json::json!({"server":"vpn.example:443", "token":"strong-token", "psk":"0123456789abcdef0123456789abcdef", "stealth_profile":"balanced", "ws_binary_send_jitter_ms":0});
        let o = local_client_options_from_json_str(&json.to_string()).unwrap();
        assert_eq!(
            (
                o.ws_jitter_min_ms,
                o.ws_jitter_max_ms,
                o.ws_binary_send_jitter_ms
            ),
            (0, 0, 0)
        );
        assert_eq!(o.max_ws_binary, DEFAULT_CLIENT_MAX_WS_BINARY);
        assert_eq!(o.max_pad, 64);
        assert_eq!(o.ws_ping_secs, 25);
        assert_eq!(o.ws_parallel, 1);
        assert!(o.use_tcp_mux);
    }
}
