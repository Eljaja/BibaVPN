//! Android JNI: start/stop the embedded SOCKS5 → BibaVPN client (same protocol as `bibavpn-client`).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, MutexGuard, OnceLock};

use bibavpn::start_json_config::local_client_options_from_json_str;
use bibavpn::tls_util::install_ring_crypto;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use serde_json::json;
use tokio::sync::watch;

struct NativeState {
    shutdown_tx: Option<watch::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Closed by the client thread's own sender when its body (and therefore the
    /// tokio runtime drop) has finished. Gives [`stop_client_bounded`] the timed
    /// join that `JoinHandle` does not offer.
    done_rx: Option<std::sync::mpsc::Receiver<()>>,
}

/// How long a stop waits for the client thread before detaching it.
/// Mirrors the desktop bound in `ActiveVpn::stop` (`timeout(5s, handle)`).
const STOP_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const PANIC_ERR: &str = "internal panic";

/// Signal shutdown and wait for the client thread, but never longer than
/// [`STOP_JOIN_TIMEOUT`].
///
/// On Android this runs on the service teardown path, which reaches the main
/// thread: an unbounded `join()` there is an ANR. Dropping the runtime waits for
/// outstanding `spawn_blocking` work (e.g. `lookup_host`/getaddrinfo on a dead
/// mobile network), so the wait has to be bounded. The shutdown signal has
/// already been sent, so a detached thread still winds down on its own.
fn stop_client_bounded(s: &mut NativeState) {
    if let Some(tx) = s.shutdown_tx.take() {
        let _ = tx.send(true);
    }
    let handle = s.thread.take();
    let Some(rx) = s.done_rx.take() else {
        // No completion channel (older state): fall back to a plain join.
        if let Some(h) = handle {
            let _ = h.join();
        }
        return;
    };
    match rx.recv_timeout(STOP_JOIN_TIMEOUT) {
        // Sender dropped: the thread body returned, so `join` is immediate.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            if let Some(h) = handle {
                let _ = h.join();
            }
        }
        // Nobody ever sends on this channel; treat anything else as "still
        // running" and detach rather than risk blocking the caller.
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            tracing::warn!(
                "stop: client thread still running after {:?}; detaching (shutdown already signalled)",
                STOP_JOIN_TIMEOUT
            );
            drop(handle);
        }
    }
}

static STATE: Mutex<Option<NativeState>> = Mutex::new(None);

static RING_ONCE: OnceLock<()> = OnceLock::new();
static TRACING_ONCE: OnceLock<()> = OnceLock::new();

/// Класс приложения нельзя резолвить через FindClass из потоков, порождённых Rust/tokio — только boot classpath.
/// Кэшируем GlobalRef при входе с Java-стороны ([`Java_dev_bibavpn_core_BibaNative_nativeStart`]).
#[cfg(target_os = "android")]
static VPN_PROTECT_CLASS: Mutex<Option<jni::objects::GlobalRef>> = Mutex::new(None);

fn lock_state() -> MutexGuard<'static, Option<NativeState>> {
    STATE.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(target_os = "android")]
fn lock_vpn_protect_class() -> MutexGuard<'static, Option<jni::objects::GlobalRef>> {
    VPN_PROTECT_CLASS.lock().unwrap_or_else(|p| p.into_inner())
}

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

/// Build a non-null JSON error payload for [`nativeDecodeInvite`].
fn decode_invite_error_json(error: &str) -> String {
    json!({"ok": false, "error": error}).to_string()
}

/// Outcome of attempting to allocate a JNI error `jstring` (pure Rust; testable without a JVM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JniStringAlloc {
    /// `new_string` succeeded; caller should return the raw `jstring`.
    Ok,
    /// `new_string` failed; caller must throw and return null.
    ThrowAndNull,
}

/// Sanitize UTF-8 for JNI `NewString`: interior NUL bytes are replaced so allocation cannot fail
/// for that reason.
fn sanitize_jni_utf8(s: &str) -> String {
    if s.as_bytes().contains(&0) {
        s.replace('\0', "\u{FFFD}")
    } else {
        s.to_owned()
    }
}

/// Map a `new_string` result to a panic-free outcome (unit-tested with a mock allocator).
fn map_jni_string_alloc<E>(result: Result<(), E>) -> JniStringAlloc {
    match result {
        Ok(()) => JniStringAlloc::Ok,
        Err(_) => JniStringAlloc::ThrowAndNull,
    }
}

fn jni_alloc_failed(env: &mut JNIEnv) -> jstring {
    let _ = env.throw_new(
        "java/lang/RuntimeException",
        "failed to allocate JNI error string",
    );
    std::ptr::null_mut()
}

/// Allocate a JNI string or throw `RuntimeException` and return null on failure.
fn jni_new_string_or_throw(env: &mut JNIEnv, s: &str) -> jstring {
    let created = env.new_string(s);
    match map_jni_string_alloc(created.as_ref().map(|_| ())) {
        JniStringAlloc::Ok => match created {
            Ok(js) => js.into_raw(),
            Err(_) => jni_alloc_failed(env),
        },
        JniStringAlloc::ThrowAndNull => jni_alloc_failed(env),
    }
}

/// Return a `jstring` for an error message, or throw `RuntimeException` if allocation fails.
fn jni_err(env: &mut JNIEnv, msg: impl AsRef<str>) -> jstring {
    jni_new_string_or_throw(env, &sanitize_jni_utf8(msg.as_ref()))
}

/// Return a non-null `jstring` with `{"ok":false,"error":…}` JSON.
fn jni_json_err(env: &mut JNIEnv, error: impl AsRef<str>) -> jstring {
    jni_err(env, decode_invite_error_json(error.as_ref()))
}

#[cfg(target_os = "android")]
fn cache_vpn_protect_class(env: &mut JNIEnv) -> jni::errors::Result<()> {
    let mut slot = lock_vpn_protect_class();
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
        let guard = lock_vpn_protect_class();
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

fn decode_invite_payload(uri_s: &str, pass_s: &str) -> String {
    match bibavpn::decode_invite_v1(uri_s, pass_s) {
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
                    return decode_invite_error_json(&format!("invite json: {e}"));
                }
            }
            serde_json::Value::Object(out).to_string()
        }
        Err(e) => decode_invite_error_json(&format!("{e:#}")),
    }
}

fn native_decode_invite_impl(
    env: &mut JNIEnv,
    _class: JClass,
    uri: JString,
    passphrase: JString,
) -> jstring {
    ensure_ring();
    let uri_s: String = match env.get_string(&uri) {
        Ok(s) => s.into(),
        Err(e) => return jni_json_err(env, format!("uri: {e}")),
    };
    let pass_s: String = match env.get_string(&passphrase) {
        Ok(s) => s.into(),
        Err(e) => return jni_json_err(env, format!("passphrase: {e}")),
    };

    jni_err(env, decode_invite_payload(&uri_s, &pass_s))
}

#[no_mangle]
pub extern "system" fn Java_dev_bibavpn_core_BibaNative_nativeDecodeInvite(
    mut env: JNIEnv,
    class: JClass,
    uri: JString,
    passphrase: JString,
) -> jstring {
    match catch_unwind(AssertUnwindSafe(|| {
        native_decode_invite_impl(&mut env, class, uri, passphrase)
    })) {
        Ok(r) => r,
        Err(_) => jni_json_err(&mut env, PANIC_ERR),
    }
}

fn native_start_impl(env: &mut JNIEnv, _class: JClass, config_json: JString) -> jstring {
    ensure_ring();
    ensure_tracing();

    let json: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(e) => return jni_err(env, format!("config string: {e}")),
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

    let mut guard = lock_state();

    if guard.is_some() {
        let thread_done = guard
            .as_ref()
            .and_then(|s| s.thread.as_ref().map(|t| t.is_finished()))
            .unwrap_or(true);
        if thread_done {
            #[cfg(target_os = "android")]
            {
                bibavpn::outbound_protect::set_hook(None);
            }
            if let Some(mut s) = guard.take() {
                stop_client_bounded(&mut s);
            }
        } else {
            tracing::warn!("nativeStart: already running");
            return jni_err(env, "already running");
        }
    }

    let opts = match local_client_options_from_json_str(&json) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("nativeStart: parse config: {e:#}");
            return jni_err(env, format!("{e:#}"));
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
        if let Err(e) = cache_vpn_protect_class(env) {
            return jni_err(env, format!("cache VpnProtect: {e}"));
        }
        let jvm = match env.get_java_vm() {
            Ok(j) => Arc::new(j),
            Err(e) => return jni_err(env, format!("java_vm: {e}")),
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

    *guard = Some(NativeState {
        shutdown_tx: Some(shutdown_tx),
        thread: Some(thread),
        done_rx: Some(done_rx),
    });
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
            let mut guard = lock_state();
            if let Some(mut s) = guard.take() {
                stop_client_bounded(&mut s);
            }
            #[cfg(target_os = "android")]
            {
                bibavpn::outbound_protect::set_hook(None);
            }
            jni_err(env, msg)
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_bibavpn_core_BibaNative_nativeStart(
    mut env: JNIEnv,
    class: JClass,
    config_json: JString,
) -> jstring {
    match catch_unwind(AssertUnwindSafe(|| {
        native_start_impl(&mut env, class, config_json)
    })) {
        Ok(r) => r,
        Err(_) => jni_err(&mut env, PANIC_ERR),
    }
}

fn native_stop_impl(_env: &mut JNIEnv, _class: JClass) -> jstring {
    ensure_tracing();
    tracing::info!("nativeStop: enter");
    let mut guard = lock_state();

    let mut s = match guard.take() {
        Some(s) => s,
        None => {
            tracing::info!("nativeStop: idle (no client)");
            return std::ptr::null_mut();
        }
    };

    stop_client_bounded(&mut s);

    #[cfg(target_os = "android")]
    {
        bibavpn::outbound_protect::set_hook(None);
    }

    tracing::info!("nativeStop: done");
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "system" fn Java_dev_bibavpn_core_BibaNative_nativeStop(
    mut env: JNIEnv,
    class: JClass,
) -> jstring {
    match catch_unwind(AssertUnwindSafe(|| native_stop_impl(&mut env, class))) {
        Ok(r) => r,
        Err(_) => jni_err(&mut env, PANIC_ERR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn catch_panic_sentinel() -> &'static str {
        match catch_unwind(|| {
            panic!("simulated extern body");
        }) {
            Ok(_) => "unexpected success",
            Err(_) => PANIC_ERR,
        }
    }

    #[test]
    fn catch_unwind_returns_panic_sentinel() {
        assert_eq!(catch_panic_sentinel(), PANIC_ERR);
    }

    #[test]
    fn decode_invite_error_json_shape() {
        let s = decode_invite_error_json("bad invite");
        let v: serde_json::Value = serde_json::from_str(&s).expect("json");
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "bad invite");
    }

    #[test]
    fn sanitize_jni_utf8_table() {
        let cases: &[(&str, &str)] = &[
            ("plain", "plain"),
            ("bad\0invite", "bad\u{FFFD}invite"),
            ("\0", "\u{FFFD}"),
            ("no-nul-here", "no-nul-here"),
        ];
        for (input, want) in cases {
            assert_eq!(sanitize_jni_utf8(input), *want, "input={input:?}");
        }
    }

    #[test]
    fn map_jni_string_alloc_table() {
        let cases: &[(Result<(), u8>, JniStringAlloc)] = &[
            (Ok(()), JniStringAlloc::Ok),
            (Err(1), JniStringAlloc::ThrowAndNull),
        ];
        for (result, want) in cases {
            assert_eq!(map_jni_string_alloc(*result), *want);
        }
    }

    #[test]
    fn state_mutex_recovers_from_poison() {
        let m = Arc::new(Mutex::new(0_i32));
        let poisoner = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock().expect("lock");
            panic!("poison mutex");
        })
        .join();
        assert!(m.is_poisoned());
        let mut guard = m.lock().unwrap_or_else(|p| p.into_inner());
        *guard = 42;
        drop(guard);
        let guard = m.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(*guard, 42);
    }
}
