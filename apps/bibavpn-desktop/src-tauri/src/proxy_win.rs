//! Windows WinInet registry proxy (same keys as most “system proxy” UIs).

use std::io;
use tracing::warn;
use windows::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows::{
    core::w,
    Win32::Foundation::{LPARAM, LRESULT, WPARAM},
    Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    },
};
use winreg::enums::*;
use winreg::RegKey;

#[derive(Debug, Clone)]
pub struct ProxyBackup {
    pub enable: u32,
    pub server: Option<String>,
    pub override_val: Option<String>,
    /// WPAD «автоопределение» (WinInet `AutoDetect`).
    pub auto_detect: u32,
    /// URL сценария настройки прокси (PAC), WinInet `AutoConfigURL`.
    pub auto_config_url: Option<String>,
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
    let auto_detect: u32 = key.get_value("AutoDetect").unwrap_or(0);
    let auto_config_raw: String = key.get_value("AutoConfigURL").unwrap_or_default();
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
        auto_detect,
        auto_config_url: if auto_config_raw.is_empty() {
            None
        } else {
            Some(auto_config_raw)
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
    // Steam: loopback IPC + client bootstrap CDN. WinInet `*.steamstatic.com` often does NOT match
    // `client-update.fastly.steamstatic.com` (multi-label); without bypass, bootstrap gets http error 0 and
    // web UI websocket handshakes fail.
    for req in [
        "<-loopback>",
        "localhost",
        "127.0.0.1",
        "tauri.localhost",
        "steamloopback.host",
        "*.steamloopback.host",
        "client-update.steamstatic.com",
        "client-update.akamai.steamstatic.com",
        "client-update.fastly.steamstatic.com",
    ] {
        if !parts.iter().any(|p| p.eq_ignore_ascii_case(req)) {
            parts.push(req.to_string());
        }
    }
    parts.join(";")
}

/// Уведомляет приложения об изменении WinInet / прокси (часть клиентов игнорирует только `InternetSetOptionW`).
fn broadcast_proxy_settings_changed() {
    unsafe {
        let section = w!("Internet Settings");
        let lr = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(section.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            250,
            None,
        );
        if lr == LRESULT(0) {
            warn!(
                target: "bibavpn_desktop",
                "WM_SETTINGCHANGE (Internet Settings): SendMessageTimeoutW вернул 0"
            );
        }
    }
}

fn notify_changed() -> Result<(), String> {
    unsafe {
        InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
            .map_err(|e| format!("InternetSetOptionW(SETTINGS_CHANGED): {e}"))?;
        InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
            .map_err(|e| format!("InternetSetOptionW(REFRESH): {e}"))?;
    }
    broadcast_proxy_settings_changed();
    Ok(())
}

/// Формат из [`apply_proxy`]: `http=127.0.0.1:PORT;https=127.0.0.1:PORT`.
fn is_biba_manual_proxy(proxy_server: &str) -> bool {
    let parts = proxy_server
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if parts.len() != 2 {
        return false;
    }
    let Some(http_hp) = parts[0].strip_prefix("http=") else {
        return false;
    };
    let Some(https_hp) = parts[1].strip_prefix("https=") else {
        return false;
    };
    let http_hp = http_hp.trim();
    let https_hp = https_hp.trim();
    if http_hp != https_hp {
        return false;
    }
    let Some((host, port)) = http_hp.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().is_err() {
        return false;
    }
    matches!(
        host.trim().to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost"
    )
}

/// Если в памяти нет бэкапа или реестр застрял, отключаем только «наш» ручной прокси на loopback.
pub fn disable_if_residual_biba_proxy() -> Result<(), String> {
    let key_ro = internet_settings_key(false).map_err(|e| e.to_string())?;
    let enable: u32 = key_ro.get_value("ProxyEnable").unwrap_or(0);
    if enable == 0 {
        return Ok(());
    }
    let server: String = key_ro.get_value("ProxyServer").unwrap_or_default();
    if !is_biba_manual_proxy(&server) {
        return Ok(());
    }
    let key = internet_settings_key(true).map_err(|e| e.to_string())?;
    key.set_value("ProxyEnable", &0u32)
        .map_err(|e| format!("ProxyEnable: {e}"))?;
    let _ = key.delete_value("ProxyServer");
    notify_changed()
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
    // На время VPN отключаем PAC/WPAD — иначе часть стека продолжает обходить ручной прокси.
    key.set_value("AutoDetect", &0u32)
        .map_err(|e| format!("AutoDetect: {e}"))?;
    let _ = key.delete_value("AutoConfigURL");
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
    key.set_value("AutoDetect", &backup.auto_detect)
        .map_err(|e| format!("AutoDetect: {e}"))?;
    match &backup.auto_config_url {
        Some(s) if !s.is_empty() => {
            key.set_value("AutoConfigURL", s)
                .map_err(|e| format!("AutoConfigURL: {e}"))?;
        }
        _ => {
            let _ = key.delete_value("AutoConfigURL");
        }
    }
    notify_changed()
}
