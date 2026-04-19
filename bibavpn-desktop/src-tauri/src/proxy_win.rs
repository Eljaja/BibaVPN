//! Windows WinInet registry proxy (same keys as most “system proxy” UIs).

use std::io;
use windows::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use winreg::enums::*;
use winreg::RegKey;

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

/// WinInet: prior `ProxyOverride`, обязательный loopback/WebView, плюс split-tunnel домены (прямой выход).
fn merge_proxy_override(
    existing: Option<&str>,
    split_tunnel_hosts: &[String],
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(e) = existing {
        for p in e.split(';') {
            let t = p.trim();
            if !t.is_empty() {
                parts.push(t.to_string());
            }
        }
    }
    for h in split_tunnel_hosts {
        let t = h.trim();
        if !t.is_empty() && !parts.iter().any(|p| p.eq_ignore_ascii_case(t)) {
            parts.push(t.to_string());
        }
    }
    for req in ["<-loopback>", "localhost", "127.0.0.1", "tauri.localhost"] {
        if !parts.iter().any(|p| p.eq_ignore_ascii_case(req)) {
            parts.push(req.to_string());
        }
    }
    parts.join(";")
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

/// WinInet `ProxyServer`: only advertise local HTTP/HTTPS CONNECT on Windows.
/// Many Windows clients treat `socks=` in Internet Settings as SOCKS4, while BibaVPN only serves
/// SOCKS5 on the local port. Keeping `socks=` here causes browsers/background services to hit the
/// SOCKS listener with version 4 and fail before the tunnel is even involved.
///
/// `prior_proxy_override` — значение `ProxyOverride` до применения (из [`read_backup`]); сохраняется и дополняется.
/// `split_tunnel_hosts` — домены в обход прокси (как исключения в Android split-tunnel).
pub fn apply_proxy(
    http_host_port: &str,
    _socks_host_port: &str,
    prior_proxy_override: Option<&str>,
    split_tunnel_hosts: &[String],
) -> Result<(), String> {
    let proxy_server = format!("http={http_host_port};https={http_host_port}");
    let key = internet_settings_key(true).map_err(|e| e.to_string())?;
    let merged_override = merge_proxy_override(prior_proxy_override, split_tunnel_hosts);
    key.set_value("ProxyEnable", &1u32)
        .map_err(|e| format!("ProxyEnable: {e}"))?;
    key.set_value("ProxyServer", &proxy_server)
        .map_err(|e| format!("ProxyServer: {e}"))?;
    key.set_value("ProxyOverride", &merged_override)
        .map_err(|e| format!("ProxyOverride: {e}"))?;
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
