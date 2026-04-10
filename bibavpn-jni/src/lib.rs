//! Android JNI: start/stop the embedded SOCKS5 → BibaVPN client (same protocol as `bibavpn-client`).

use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Context;
use bibavpn::local_client::{
    LocalClientOptions, DEFAULT_CLIENT_MAX_WS_BINARY, DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
    parse_host_port, parse_ws_header,
};
use bibavpn::tls_util::install_ring_crypto;
use bibavpn::TlsClientProfile;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::watch;

struct NativeState {
    shutdown_tx: Option<watch::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

static STATE: Mutex<Option<NativeState>> = Mutex::new(None);

static RING_ONCE: OnceLock<()> = OnceLock::new();
static TRACING_ONCE: OnceLock<()> = OnceLock::new();

fn ensure_ring() {
    RING_ONCE.get_or_init(|| {
        install_ring_crypto();
    });
}

fn ensure_tracing() {
    TRACING_ONCE.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

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
    /// Overrides invite `tls_profile` when non-empty.
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
    /// PEM string (`CERTIFICATE` blocks). Leaf must match; mutually exclusive with `insecure`.
    #[serde(default)]
    pin_cert_pem: Option<String>,
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

fn opts_from_json(s: &str) -> anyhow::Result<LocalClientOptions> {
    let j: StartJson = serde_json::from_str(s)?;
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

    if invite_uri.is_some() != invite_pass.is_some() {
        anyhow::bail!("invite: set both from_invite and invite_passphrase, or neither");
    }

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
    ) = if let (Some(uri), Some(pass)) = (invite_uri, invite_pass) {
        let inv = bibavpn::decode_invite_v1(uri, pass).context("decode invite")?;
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
            inv.token,
            inv.max_pad,
            j.junk_frames,
            j.early_ws_frames,
            inv.psk,
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
    })
}

fn jni_err(env: &mut JNIEnv, msg: impl AsRef<str>) -> jstring {
    env.new_string(msg.as_ref()).expect("jstring").into_raw()
}

#[no_mangle]
pub extern "system" fn Java_dev_bibavpn_core_BibaNative_nativeDecodeInvite(
    mut env: JNIEnv,
    _class: JClass,
    uri: JString,
    passphrase: JString,
) -> jstring {
    ensure_ring();
    let uri_s: String = match env.get_string(&uri) {
        Ok(s) => s.into(),
        Err(e) => {
            return env
                .new_string(json!({"ok": false, "error": format!("uri: {e}")}).to_string())
                .expect("jstring")
                .into_raw();
        }
    };
    let pass_s: String = match env.get_string(&passphrase) {
        Ok(s) => s.into(),
        Err(e) => {
            return env
                .new_string(json!({"ok": false, "error": format!("passphrase: {e}")}).to_string())
                .expect("jstring")
                .into_raw();
        }
    };

    let payload = match bibavpn::decode_invite_v1(&uri_s, &pass_s) {
        Ok(inv) => json!({
            "ok": true,
            "server": inv.server,
            "sni": inv.sni,
            "token": inv.token,
            "psk": inv.psk,
            "decoy_max": inv.decoy_max,
            "max_pad": inv.max_pad,
            "max_ws_binary": inv.max_ws_binary,
            "ws_ping_secs": inv.ws_ping_secs,
            "ws_ping_jitter_percent": inv.ws_ping_jitter_percent,
            "ws_binary_send_jitter_ms": inv.ws_binary_send_jitter_ms,
            "udp_max_pad": inv.udp_max_pad,
            "udp_max_ws_binary": inv.udp_max_ws_binary,
            "udp_mux_reply_timeout_secs": inv.udp_mux_reply_timeout_secs,
            "insecure": inv.insecure,
            "tls_profile": inv.tls_profile,
        })
        .to_string(),
        Err(e) => json!({
            "ok": false,
            "error": format!("{e:#}"),
        })
        .to_string(),
    };

    env.new_string(payload).expect("jstring").into_raw()
}

#[no_mangle]
pub extern "system" fn Java_dev_bibavpn_core_BibaNative_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
) -> jstring {
    ensure_ring();
    ensure_tracing();

    let json: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(e) => return jni_err(&mut env, format!("config string: {e}")),
    };

    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return jni_err(&mut env, "state mutex poisoned"),
    };

    if guard.is_some() {
        return jni_err(&mut env, "already running");
    }

    let opts = match opts_from_json(&json) {
        Ok(o) => o,
        Err(e) => return jni_err(&mut env, format!("{e:#}")),
    };

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let thread = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("tokio runtime: {e}");
                return;
            }
        };
        if let Err(e) = rt.block_on(bibavpn::local_client::run_local_client(
            opts,
            shutdown_rx,
            Some(ready_tx),
        )) {
            tracing::error!("client: {e:#}");
        }
    });

    *guard = Some(NativeState {
        shutdown_tx: Some(shutdown_tx),
        thread: Some(thread),
    });
    drop(guard);

    match ready_rx.recv_timeout(std::time::Duration::from_secs(20)) {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => {
            let msg = match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => {
                    "SOCKS: таймаут ожидания bind (20 с)"
                }
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    "SOCKS: клиент не поднял порт (см. лог)"
                }
            };
            let mut guard = match STATE.lock() {
                Ok(g) => g,
                Err(_) => return jni_err(&mut env, msg),
            };
            if let Some(mut s) = guard.take() {
                if let Some(tx) = s.shutdown_tx.take() {
                    let _ = tx.send(true);
                }
                if let Some(h) = s.thread.take() {
                    let _ = h.join();
                }
            }
            jni_err(&mut env, msg)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_bibavpn_core_BibaNative_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return jni_err(&mut env, "state mutex poisoned"),
    };

    let mut s = match guard.take() {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    if let Some(tx) = s.shutdown_tx.take() {
        let _ = tx.send(true);
    }
    if let Some(h) = s.thread.take() {
        let _ = h.join();
    }

    std::ptr::null_mut()
}
