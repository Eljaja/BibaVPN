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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyBackup {
    pub enable: u32,
    pub server: Option<String>,
    pub override_val: Option<String>,
    /// WPAD «автоопределение» (WinInet `AutoDetect`).
    pub auto_detect: u32,
    /// URL сценария настройки прокси (PAC), WinInet `AutoConfigURL`.
    pub auto_config_url: Option<String>,
}

/// WinInet stores proxy lists in the registry; very long `ProxyOverride`
/// values are truncated by the stack and can break proxy selection. Keep the
/// required bypass entries and drop split-tunnel extras first.
const MAX_PROXY_OVERRIDE_LEN: usize = 2048;

const REQUIRED_OVERRIDE: &[&str] = &[
    "<-loopback>",
    "<local>",
    "localhost",
    "127.0.0.1",
    "10.*",
    "192.168.*",
    "169.254.*",
    "100.*",
    "172.16.*",
    "172.17.*",
    "172.18.*",
    "172.19.*",
    "172.20.*",
    "172.21.*",
    "172.22.*",
    "172.23.*",
    "172.24.*",
    "172.25.*",
    "172.26.*",
    "172.27.*",
    "172.28.*",
    "172.29.*",
    "172.30.*",
    "172.31.*",
    "tauri.localhost",
    "steamloopback.host",
    "*.steamloopback.host",
    "client-update.steamstatic.com",
    "client-update.akamai.steamstatic.com",
    "client-update.fastly.steamstatic.com",
];

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
fn merge_proxy_override(existing: Option<&str>, split_tunnel_hosts: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(e) = existing {
        for p in e.split(';') {
            let t = p.trim();
            if !t.is_empty() && !parts.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                parts.push(t.to_string());
            }
        }
    }
    // Required entries go before split-tunnel extras so the length cap can drop
    // only optional domains.
    for req in REQUIRED_OVERRIDE {
        if !parts.iter().any(|p| p.eq_ignore_ascii_case(req)) {
            parts.push((*req).to_string());
        }
    }
    let protected = parts.len();
    for h in split_tunnel_hosts {
        let t = h.trim();
        if !t.is_empty() && !parts.iter().any(|p| p.eq_ignore_ascii_case(t)) {
            parts.push(t.to_string());
        }
    }
    trim_proxy_override(parts, protected)
}

fn trim_proxy_override(mut parts: Vec<String>, protected: usize) -> String {
    let mut total: usize = parts.iter().map(|p| p.len() + 1).sum();
    // Drop optional split-tunnel entries from the end until the value fits.
    while total > MAX_PROXY_OVERRIDE_LEN && parts.len() > protected {
        if let Some(removed) = parts.pop() {
            total = total.saturating_sub(removed.len() + 1);
        }
    }
    let joined = parts.join(";");
    if joined.len() <= MAX_PROXY_OVERRIDE_LEN {
        return joined;
    }
    // Pathological pre-existing list: cut at a list boundary (never mid-value).
    let mut end = MAX_PROXY_OVERRIDE_LEN;
    while end > 0 && !joined.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &joined[..end];
    match cut.rfind(';') {
        Some(i) if i > 0 => cut[..i].to_string(),
        _ => cut.to_string(),
    }
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
    // The caller stores the pre-connect snapshot separately, but `apply_proxy`
    // has no access to it here: take our own first so a mid-way registry error
    // rolls back instead of leaving `ProxyEnable=1` with no tunnel behind it.
    let snapshot = read_backup().map_err(|e| e.to_string())?;
    let prior = prior_proxy_override.or(snapshot.override_val.as_deref());
    match apply_proxy_inner(http_host_port, prior, split_tunnel_hosts) {
        Ok(()) => Ok(()),
        Err(e) => match write_backup(&snapshot, true, true) {
            Ok(()) => Err(e),
            Err(re) => Err(format!("{e}; откат настроек прокси: {re}")),
        },
    }
}

fn apply_proxy_inner(
    http_host_port: &str,
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

/// Restore only fields that are still ours (the Biba loopback proxy / the
/// PAC values we cleared) or already equal to the snapshot. A manual proxy the
/// user configured while connected is left untouched.
pub fn restore(backup: &ProxyBackup) -> Result<(), String> {
    let current = read_backup().map_err(|e| e.to_string())?;
    let manual_ours =
        current.enable != 0 && current.server.as_deref().is_some_and(is_biba_manual_proxy);
    let manual_unchanged = current.enable == backup.enable
        && current.server == backup.server
        && current.override_val == backup.override_val;
    let pac_ours = current.auto_detect == 0 && current.auto_config_url.is_none();
    let pac_unchanged = current.auto_detect == backup.auto_detect
        && current.auto_config_url == backup.auto_config_url;

    let restore_manual = manual_ours || manual_unchanged;
    let restore_pac = pac_ours || pac_unchanged;
    if !restore_manual && !restore_pac {
        return Ok(());
    }
    write_backup(backup, restore_manual, restore_pac)
}

fn write_backup(
    backup: &ProxyBackup,
    restore_manual: bool,
    restore_pac: bool,
) -> Result<(), String> {
    let key = internet_settings_key(true).map_err(|e| e.to_string())?;
    if restore_manual {
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
    }
    if restore_pac {
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
    }
    notify_changed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_proxy_override_includes_private_wildcards() {
        let merged = merge_proxy_override(None, &[]);
        assert!(merged.to_ascii_lowercase().contains("<local>"));
        assert!(merged.contains("10.*"));
        assert!(merged.contains("192.168.*"));
        assert!(merged.contains("172.16.*"));
        assert!(merged.contains("172.31.*"));
    }

    #[test]
    fn merge_proxy_override_deduplicates_case_insensitively() {
        let merged = merge_proxy_override(Some("example.com;EXAMPLE.COM"), &[]);
        assert_eq!(merged.matches("example.com").count(), 1); // lower-case needle only matches first
        assert_eq!(
            merged.to_ascii_lowercase().matches("example.com").count(),
            1
        );
    }

    #[test]
    fn merge_proxy_override_drops_optional_entries_over_cap() {
        let split: Vec<String> = (0..500)
            .map(|i| format!("very-long-split-tunnel-host-{i}.example.com"))
            .collect();
        let merged = merge_proxy_override(None, &split);
        assert!(merged.len() <= MAX_PROXY_OVERRIDE_LEN);
        assert!(merged.contains("<local>"));
        assert!(merged.contains("client-update.fastly.steamstatic.com"));
    }
}
