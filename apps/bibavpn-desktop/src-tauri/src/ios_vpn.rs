//! iOS system VPN via [`NETunnelProviderManager`] — Swift bridge in `ios-bibavpn-extras/host-sources/BibaVpnAppleBridge.swift`.
//!
//! Вызовы в отдельном потоке + таймаут на канале (как Android JNI), чтобы не блокировать поток Tauri/UI и не зависнуть навсегда при сбое NetworkExtension.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::mpsc;
use std::time::Duration;

pub fn request_connect(_app: &tauri::AppHandle, json: &str) -> Result<(), String> {
    let json = json.to_string();
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let out: Result<(), String> = (|| {
            let c = CString::new(json).map_err(|e| e.to_string())?;
            unsafe {
                let err = bibavpn_ios_tunnel_connect(c.as_ptr());
                if err.is_null() {
                    Ok(())
                } else {
                    let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
                    libc::free(err.cast());
                    Err(msg)
                }
            }
        })();
        let _ = tx.send(out);
    });
    rx.recv_timeout(Duration::from_secs(130))
        .map_err(|_| "таймаут VPN connect (iOS)".to_string())
        .and_then(|r| r)
}

pub fn request_disconnect(_app: &tauri::AppHandle) -> Result<(), String> {
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        unsafe {
            bibavpn_ios_tunnel_disconnect();
        }
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(45)).map_err(|_| {
        "таймаут VPN disconnect (iOS)".to_string()
    })?;
    Ok(())
}

pub fn tunnel_is_active(_app: &tauri::AppHandle) -> Result<bool, String> {
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let v = unsafe { bibavpn_ios_tunnel_is_active() };
        let _ = tx.send(v);
    });
    rx.recv_timeout(Duration::from_secs(18))
        .map_err(|_| "таймаут tunnel_is_active (iOS)".to_string())
}

pub fn tunnel_session_elapsed_ms(_app: &tauri::AppHandle) -> Result<u64, String> {
    // Swift только читает UserDefaults — короткий вызов, семафор не нужен.
    Ok(unsafe { bibavpn_ios_tunnel_session_elapsed_ms() })
}

extern "C" {
    fn bibavpn_ios_tunnel_connect(json: *const c_char) -> *mut c_char;
    fn bibavpn_ios_tunnel_disconnect();
    fn bibavpn_ios_tunnel_is_active() -> bool;
    fn bibavpn_ios_tunnel_session_elapsed_ms() -> u64;
}
