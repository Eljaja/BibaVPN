//! iOS system VPN via [`NETunnelProviderManager`] — Swift bridge in `ios-bibavpn-extras/host-sources/BibaVpnAppleBridge.swift`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub fn request_connect(_app: &tauri::AppHandle, json: &str) -> Result<(), String> {
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
}

pub fn request_disconnect(_app: &tauri::AppHandle) -> Result<(), String> {
    unsafe {
        bibavpn_ios_tunnel_disconnect();
    }
    Ok(())
}

pub fn tunnel_is_active(_app: &tauri::AppHandle) -> Result<bool, String> {
    Ok(unsafe { bibavpn_ios_tunnel_is_active() })
}

pub fn tunnel_session_elapsed_ms(_app: &tauri::AppHandle) -> Result<u64, String> {
    Ok(unsafe { bibavpn_ios_tunnel_session_elapsed_ms() })
}

extern "C" {
    fn bibavpn_ios_tunnel_connect(json: *const c_char) -> *mut c_char;
    fn bibavpn_ios_tunnel_disconnect();
    fn bibavpn_ios_tunnel_is_active() -> bool;
    fn bibavpn_ios_tunnel_session_elapsed_ms() -> u64;
}
