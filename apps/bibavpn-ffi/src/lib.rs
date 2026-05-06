//! C ABI for embedding `bibavpn::local_client` in an iOS Network Extension (static library).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, OnceLock};

use bibavpn::start_json_config::local_client_options_from_json_str;
use bibavpn::tls_util::install_ring_crypto;
use serde_json::json;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

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
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info")),
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
    match CString::new(msg) {
        Ok(c) => unsafe {
            *err_out = c.into_raw();
        },
        Err(_) => unsafe {
            *err_out = std::ptr::null_mut();
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn bibavpn_ffi_start(
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

    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => {
            unsafe { set_err(err_out, "state mutex poisoned".into()) };
            return -2;
        }
    };

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
            let mut guard = match STATE.lock() {
                Ok(g) => g,
                Err(_) => {
                    unsafe { set_err(err_out, msg) };
                    return -5;
                }
            };
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
pub extern "C" fn bibavpn_ffi_stop() {
    ensure_tracing();
    tracing::info!("bibavpn_ffi_stop");
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

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
pub unsafe extern "C" fn bibavpn_ffi_decode_invite(
    uri_utf8: *const c_char,
    passphrase_utf8: *const c_char,
) -> *mut c_char {
    ensure_ring();

    let uri_s = match unsafe { c_str_to_string(uri_utf8, "uri") } {
        Ok(s) => s,
        Err(e) => return leak_cstring(json!({"ok": false, "error": e}).to_string()),
    };
    let pass_s = match unsafe { c_str_to_string(passphrase_utf8, "passphrase") } {
        Ok(s) => s,
        Err(e) => return leak_cstring(json!({"ok": false, "error": e}).to_string()),
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
                    return leak_cstring(
                        json!({ "ok": false, "error": format!("invite json: {e}") }).to_string(),
                    );
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

    leak_cstring(payload)
}

fn leak_cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new(r#"{"ok":false,"error":"internal nul in json"}"#)
            .unwrap()
            .into_raw(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn bibavpn_ffi_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}
