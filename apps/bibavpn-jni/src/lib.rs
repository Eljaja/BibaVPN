//! Android JNI: start/stop the embedded SOCKS5 → BibaVPN client (same protocol as `bibavpn-client`).

mod client_slot;

use std::sync::{LazyLock, Mutex, OnceLock};

use bibavpn::start_json_config::local_client_options_from_json_str;
use bibavpn::tls_util::install_ring_crypto;
use client_slot::{ClientSlotManager, PRODUCTION_JOIN_TIMEOUT};
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use serde_json::json;
use tokio::sync::watch;

#[cfg(target_os = "android")]
fn clear_outbound_protect_hook() {
    bibavpn::outbound_protect::set_hook(None);
}

#[cfg(not(target_os = "android"))]
fn clear_outbound_protect_hook() {}

static STATE: LazyLock<Mutex<ClientSlotManager>> = LazyLock::new(|| {
    Mutex::new(ClientSlotManager::new(PRODUCTION_JOIN_TIMEOUT))
});

static RING_ONCE: OnceLock<()> = OnceLock::new();
static TRACING_ONCE: OnceLock<()> = OnceLock::new();

/// Класс приложения нельзя резолвить через FindClass из потоков, порождённых Rust/tokio — только boot classpath.
/// Кэшируем GlobalRef при входе с Java-стороны ([`Java_dev_bibavpn_core_BibaNative_nativeStart`]).
#[cfg(target_os = "android")]
static VPN_PROTECT_CLASS: Mutex<Option<jni::objects::GlobalRef>> = Mutex::new(None);

fn ensure_ring() {
    RING_ONCE.get_or_init(|| {
        install_ring_crypto();
    });
}

fn ensure_tracing() {
    TRACING_ONCE.get_or_init(|| {
        #[cfg(target_os = "android")]
        {
            use std::io::Write;
            use tracing_subscriber::EnvFilter;
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Debug)
                    .with_tag("BibaRust"),
            );
            struct LogWriter;
            impl Write for LogWriter {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    let s = String::from_utf8_lossy(buf);
                    for line in s.trim_end().lines() {
                        log::info!("{line}");
                    }
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
                )
                .with_ansi(false)
                .with_writer(|| LogWriter)
                .try_init();
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .try_init();
        }
    });
}

#[cfg(target_os = "android")]
fn cache_vpn_protect_class(env: &mut JNIEnv) -> jni::errors::Result<()> {
    let mut slot = VPN_PROTECT_CLASS.lock().unwrap();
    if slot.is_none() {
        let cls = env.find_class("dev/bibavpn/core/VpnProtect")?;
        *slot = Some(env.new_global_ref(&cls)?);
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn jni_protect_socket(jvm: &jni::JavaVM, fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    use jni::objects::JValue;
    let mut env = jvm
        .attach_current_thread()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("jni attach: {e}")))?;
    let local = {
        let guard = VPN_PROTECT_CLASS.lock().unwrap();
        let gref = guard.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "VpnProtect class not cached (nativeStart order?)",
            )
        })?;
        env.new_local_ref(gref.as_obj()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("VpnProtect local ref: {e}"),
            )
        })?
    };
    let jclass = JClass::from(local);
    let v = env
        .call_static_method(
            &jclass,
            "protectFd",
            "(I)Z",
            &[JValue::Int(fd as jni::sys::jint)],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("protectFd: {e}")))?;
    let ok = v
        .z()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{e}")))?;
    if !ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "VpnProtect.protectFd returned false",
        ));
    }
    Ok(())
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
        Ok(inv) => {
            let mut out = serde_json::Map::new();
            out.insert("ok".to_string(), json!(true));
            match serde_json::to_value(&inv) {
                Ok(serde_json::Value::Object(m)) => {
                    for (k, v) in m {
                        out.insert(k, v);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    return env
                        .new_string(
                            json!({ "ok": false, "error": format!("invite json: {e}") }).to_string(),
                        )
                        .expect("jstring")
                        .into_raw();
                }
            }
            serde_json::Value::Object(out).to_string()
        }
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
    let json_fingerprint = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        json.as_bytes().hash(&mut h);
        h.finish()
    };
    tracing::info!(
        json_len = json.len(),
        json_fingerprint = json_fingerprint,
        "nativeStart: enter"
    );

    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return jni_err(&mut env, "state mutex poisoned"),
    };

    if let Err(msg) = guard.try_prepare_start(clear_outbound_protect_hook) {
        tracing::warn!("nativeStart: {msg}");
        return jni_err(&mut env, msg);
    }

    let opts = match local_client_options_from_json_str(&json) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("nativeStart: parse config: {e:#}");
            return jni_err(&mut env, format!("{e:#}"));
        }
    };
    tracing::info!(
        socks_bind = %opts.socks_bind,
        server_host = %opts.server_host,
        "nativeStart: parsed, spawning client"
    );

    #[cfg(target_os = "android")]
    {
        use std::sync::Arc;
        if let Err(e) = cache_vpn_protect_class(&mut env) {
            return jni_err(&mut env, format!("cache VpnProtect: {e}"));
        }
        let jvm = match env.get_java_vm() {
            Ok(j) => Arc::new(j),
            Err(e) => return jni_err(&mut env, format!("java_vm: {e}")),
        };
        let jvm_cb = jvm.clone();
        bibavpn::outbound_protect::set_hook(Some(std::sync::Arc::new(move |fd| {
            jni_protect_socket(jvm_cb.as_ref(), fd)
        })));
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Never sent on: the receiver observes the *drop* of this sender, which
    // happens when the closure below returns — after the runtime is dropped.
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let _done_tx = done_tx;
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

    guard.install_live(shutdown_tx, thread, done_rx);
    drop(guard);

    tracing::info!("nativeStart: waiting SOCKS bind (20s timeout)");
    match ready_rx.recv_timeout(std::time::Duration::from_secs(20)) {
        Ok(()) => {
            tracing::info!("nativeStart: SOCKS ready");
            std::ptr::null_mut()
        }
        Err(e) => {
            let msg = match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => "SOCKS: таймаут ожидания bind (20 с)",
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    "SOCKS: клиент не поднял порт (см. лог)"
                }
            };
            tracing::error!("nativeStart: SOCKS not ready: {msg}");
            let mut guard = match STATE.lock() {
                Ok(g) => g,
                Err(_) => return jni_err(&mut env, msg),
            };
            guard.abort_pending_start(clear_outbound_protect_hook);
            jni_err(&mut env, msg)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_bibavpn_core_BibaNative_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    ensure_tracing();
    tracing::info!("nativeStop: enter");
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return jni_err(&mut env, "state mutex poisoned"),
    };

    if guard.is_idle() {
        tracing::info!("nativeStop: idle (no client)");
        return std::ptr::null_mut();
    }

    guard.stop(clear_outbound_protect_hook);

    tracing::info!("nativeStop: done");
    std::ptr::null_mut()
}
