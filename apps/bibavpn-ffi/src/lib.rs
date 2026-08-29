//! C ABI for embedding `bibavpn::local_client` in an iOS Network Extension (static library).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, MutexGuard, OnceLock};

use bibavpn::start_json_config::local_client_options_from_json_str;
use bibavpn::tls_util::install_ring_crypto;
use serde_json::json;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

const FFI_PANIC_CODE: c_int = -99;
const PANIC_ERR: &str = "internal panic";

struct NativeState {
    shutdown_tx: Option<watch::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

static STATE: Mutex<Option<NativeState>> = Mutex::new(None);

static RING_ONCE: OnceLock<()> = OnceLock::new();
static TRACING_ONCE: OnceLock<()> = OnceLock::new();

fn lock_state() -> MutexGuard<'static, Option<NativeState>> {
    STATE.lock().unwrap_or_else(|p| p.into_inner())
}

fn ensure_ring() {
    RING_ONCE.get_or_init(|| {
        install_ring_crypto();
    });
}

fn ensure_tracing() {
    TRACING_ONCE.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_ansi(false)
            .try_init();
    });
}

unsafe fn c_str_to_string(ptr: *const c_char, ctx: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{ctx}: null pointer"));
    }
    let cs = unsafe { CStr::from_ptr(ptr) };
    cs.to_str()
        .map(|s| s.to_owned())
        .map_err(|e| format!("{ctx}: invalid UTF-8: {e}"))
}

unsafe fn set_err(err_out: *mut *mut c_char, msg: String) {
    if err_out.is_null() {
        return;
    }
    unsafe {
        *err_out = leak_cstring(msg);
    }
}

fn decode_invite_error_json(error: &str) -> String {
    json!({"ok": false, "error": error}).to_string()
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

fn leak_cstring_fallback() -> *mut c_char {
    const FALLBACK: &str = r#"{"ok":false,"error":"internal nul in json"}"#;
    match CString::new(FALLBACK) {
        Ok(c) => c.into_raw(),
        // FALLBACK has no interior NUL; this arm is unreachable.
        Err(_) => std::ptr::null_mut(),
    }
}

fn leak_cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => leak_cstring_fallback(),
    }
}

fn bibavpn_ffi_start_impl(
    config_json_utf8: *const c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    if !err_out.is_null() {
        unsafe {
            *err_out = std::ptr::null_mut();
        }
    }

    ensure_ring();
    ensure_tracing();

    let json = match unsafe { c_str_to_string(config_json_utf8, "config_json") } {
        Ok(s) => s,
        Err(e) => {
            unsafe { set_err(err_out, e) };
            return -1;
        }
    };

    tracing::info!(json_len = json.len(), "bibavpn_ffi_start");

    let mut guard = lock_state();

    if guard.is_some() {
        let thread_done = guard
            .as_ref()
            .and_then(|s| s.thread.as_ref().map(|t| t.is_finished()))
            .unwrap_or(true);
        if thread_done {
            if let Some(mut s) = guard.take() {
                if let Some(tx) = s.shutdown_tx.take() {
                    let _ = tx.send(true);
                }
                if let Some(h) = s.thread.take() {
                    let _ = h.join();
                }
            }
        } else {
            tracing::warn!("bibavpn_ffi_start: already running");
            unsafe { set_err(err_out, "already running".into()) };
            return -3;
        }
    }

    let opts = match local_client_options_from_json_str(&json) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("bibavpn_ffi_start: parse: {e:#}");
            unsafe { set_err(err_out, format!("{e:#}")) };
            return -4;
        }
    };

    tracing::info!(
        socks_bind = %opts.socks_bind,
        server_host = %opts.server_host,
        "bibavpn_ffi_start: spawning client"
    );

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
        Ok(()) => {
            tracing::info!("bibavpn_ffi_start: SOCKS ready");
            0
        }
        Err(e) => {
            let msg = match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => {
                    "SOCKS: bind timeout (20s)".to_string()
                }
                std::sync::mpsc::RecvTimeoutError::Disconnected => {
                    "SOCKS: client failed before bind".to_string()
                }
            };
            tracing::error!("bibavpn_ffi_start: {msg}");
            let mut guard = lock_state();
            if let Some(mut s) = guard.take() {
                if let Some(tx) = s.shutdown_tx.take() {
                    let _ = tx.send(true);
                }
                if let Some(h) = s.thread.take() {
                    let _ = h.join();
                }
            }
            unsafe { set_err(err_out, msg) };
            -5
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn bibavpn_ffi_start(
    config_json_utf8: *const c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    match catch_unwind(AssertUnwindSafe(|| {
        bibavpn_ffi_start_impl(config_json_utf8, err_out)
    })) {
        Ok(code) => code,
        Err(_) => {
            set_err(err_out, PANIC_ERR.into());
            FFI_PANIC_CODE
        }
    }
}

fn bibavpn_ffi_stop_impl() {
    ensure_tracing();
    tracing::info!("bibavpn_ffi_stop");
    let mut guard = lock_state();

    let mut s = match guard.take() {
        Some(s) => s,
        None => return,
    };

    if let Some(tx) = s.shutdown_tx.take() {
        let _ = tx.send(true);
    }
    if let Some(h) = s.thread.take() {
        let _ = h.join();
    }
}

#[no_mangle]
pub extern "C" fn bibavpn_ffi_stop() {
    let _ = catch_unwind(AssertUnwindSafe(bibavpn_ffi_stop_impl));
}

fn bibavpn_ffi_decode_invite_impl(
    uri_utf8: *const c_char,
    passphrase_utf8: *const c_char,
) -> *mut c_char {
    ensure_ring();

    let uri_s = match unsafe { c_str_to_string(uri_utf8, "uri") } {
        Ok(s) => s,
        Err(e) => return leak_cstring(decode_invite_error_json(&e)),
    };
    let pass_s = match unsafe { c_str_to_string(passphrase_utf8, "passphrase") } {
        Ok(s) => s,
        Err(e) => return leak_cstring(decode_invite_error_json(&e)),
    };

    leak_cstring(decode_invite_payload(&uri_s, &pass_s))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn bibavpn_ffi_decode_invite(
    uri_utf8: *const c_char,
    passphrase_utf8: *const c_char,
) -> *mut c_char {
    match catch_unwind(AssertUnwindSafe(|| {
        bibavpn_ffi_decode_invite_impl(uri_utf8, passphrase_utf8)
    })) {
        Ok(ptr) => ptr,
        Err(_) => leak_cstring(decode_invite_error_json(PANIC_ERR)),
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn bibavpn_ffi_string_free(s: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if s.is_null() {
            return;
        }
        unsafe {
            let _ = CString::from_raw(s);
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn catch_start_panic_sentinel() -> c_int {
        match catch_unwind(|| {
            panic!("simulated extern body");
        }) {
            Ok(_) => 0,
            Err(_) => FFI_PANIC_CODE,
        }
    }

    #[test]
    fn catch_unwind_returns_minus_99_sentinel() {
        assert_eq!(catch_start_panic_sentinel(), -99);
    }

    #[test]
    fn decode_invite_panic_sentinel_is_error_json() {
        let ptr = leak_cstring(decode_invite_error_json(PANIC_ERR));
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf-8");
        let v: serde_json::Value = serde_json::from_str(s).expect("json");
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], PANIC_ERR);
        unsafe {
            bibavpn_ffi_string_free(ptr);
        }
    }

    #[test]
    fn leak_cstring_interior_nul_does_not_panic() {
        let ptr = leak_cstring(String::from("a\0b"));
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf-8");
        assert_eq!(s, r#"{"ok":false,"error":"internal nul in json"}"#);
        unsafe {
            bibavpn_ffi_string_free(ptr);
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
