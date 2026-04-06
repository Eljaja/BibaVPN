//! Windows WinInet registry proxy (same keys as most “system proxy” UIs).

use std::io;
use winreg::enums::*;
use winreg::RegKey;
use windows::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};

#[derive(Debug, Clone)]
pub struct ProxyBackup {
    pub enable: u32,
    pub server: Option<String>,
    pub override_val: Option<String>,
}

fn internet_settings_key(write: bool) -> io::Result<RegKey> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let sub = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    if write {
        hkcu.create_subkey(sub).map(|(k, _)| k)
    } else {
        hkcu.open_subkey(sub)
    }
}

pub fn read_backup() -> io::Result<ProxyBackup> {
    let key = internet_settings_key(false)?;
    let enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let server: String = key.get_value("ProxyServer").unwrap_or_default();
    let override_val: String = key.get_value("ProxyOverride").unwrap_or_default();
    Ok(ProxyBackup {
        enable,
        server: if server.is_empty() {
            None
        } else {
            Some(server)
        },
        override_val: if override_val.is_empty() {
            None
        } else {
            Some(override_val)
        },
    })
}

fn notify_changed() -> Result<(), String> {
    unsafe {
        InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
            .map_err(|e| format!("InternetSetOptionW(SETTINGS_CHANGED): {e}"))?;
        InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
            .map_err(|e| format!("InternetSetOptionW(REFRESH): {e}"))?;
    }
    Ok(())
}

/// WinInet `ProxyServer`: HTTP/HTTPS → локальный CONNECT-прокси; `socks` → SOCKS5 (TCP + UDP ASSOCIATE).
pub fn apply_proxy(http_host_port: &str, socks_host_port: &str) -> Result<(), String> {
    let proxy_server = format!(
        "http={http_host_port};https={http_host_port};socks={socks_host_port}"
    );
    let key = internet_settings_key(true).map_err(|e| e.to_string())?;
    key.set_value("ProxyEnable", &1u32)
        .map_err(|e| format!("ProxyEnable: {e}"))?;
    key.set_value("ProxyServer", &proxy_server)
        .map_err(|e| format!("ProxyServer: {e}"))?;
    notify_changed()
}

pub fn restore(backup: &ProxyBackup) -> Result<(), String> {
    let key = internet_settings_key(true).map_err(|e| e.to_string())?;
    key.set_value("ProxyEnable", &backup.enable)
        .map_err(|e| format!("ProxyEnable: {e}"))?;
    match &backup.server {
        Some(s) if !s.is_empty() => {
            key.set_value("ProxyServer", s)
                .map_err(|e| format!("ProxyServer: {e}"))?;
        }
        _ => {
            let _ = key.delete_value("ProxyServer");
        }
    }
    match &backup.override_val {
        Some(o) if !o.is_empty() => {
            key.set_value("ProxyOverride", o)
                .map_err(|e| format!("ProxyOverride: {e}"))?;
        }
        _ => {
            let _ = key.delete_value("ProxyOverride");
        }
    }
    notify_changed()
}
