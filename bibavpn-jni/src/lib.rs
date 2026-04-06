//! Android JNI: start/stop the embedded SOCKS5 → BibaVPN client (same protocol as `bibavpn-client`).

use std::sync::{Arc, Mutex, OnceLock};

use bibavpn::local_client::{
    LocalClientOptions, DEFAULT_CLIENT_MAX_WS_BINARY, parse_host_port, parse_ws_header,
};
use bibavpn::tls_util::install_ring_crypto;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use serde::Deserialize;
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

fn opts_from_json(s: &str) -> anyhow::Result<LocalClientOptions> {
    let j: StartJson = serde_json::from_str(s)?;
    let (server_host, server_port) = parse_host_port(&j.server)?;
    let sni = j.sni.unwrap_or_else(|| server_host.clone());

    let mut extra = Vec::new();
    for line in &j.ws_headers {
        extra.push(parse_ws_header(line)?);
    }

    Ok(LocalClientOptions {
        server_host,
        server_port,
        sni,
        token: j.token,
        socks_bind: j.socks_bind,
        http_proxy_bind: j.http_proxy,
        insecure_tls: j.insecure,
        max_pad: j.max_pad,
        junk_frames: j.junk_frames,
        early_ws_frames: j.early_ws_frames,
        psk: j.psk,
        decoy_max: j.decoy_max,
        ws_host: j.ws_host,
        ws_origin: j.ws_origin,
        ws_user_agent: j.ws_user_agent,
        ws_accept_language: j.ws_accept_language,
        ws_extra_headers: Arc::new(extra),
        max_ws_binary: j.max_ws_binary,
        ws_ping_secs: j.ws_ping_secs,
    })
}

fn jni_err(env: &mut JNIEnv, msg: impl AsRef<str>) -> jstring {
    env.new_string(msg.as_ref()).expect("jstring").into_raw()
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

    // Ждём bind SOCKS (иначе tun2socks подключается к закрывающейся TCP-пробе или рано — Go может os.Exit и убить процесс).
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
