//! Split-tunnel: домены в обход системного HTTP-прокси (Windows ProxyOverride / macOS bypass).
//! Списки доменов берутся из API [`crate::bypass_domains`] (не захардкожены в репозитории).

use crate::bypass_domains;
use crate::config::TunnelProfile;

/// Домены для WinInet ProxyOverride / macOS bypass (без обязательных loopback — их добавляет платформа).
pub fn bypass_domains_for_profile(profile: &TunnelProfile) -> Vec<String> {
    if !profile.split_tunnel_enabled {
        return Vec::new();
    }
    bypass_domains::domains_for_preset_ids(&profile.split_tunnel_preset_ids)
}

/// Android: домены из пресетов API (те же, что WinInet/macOS bypass) для `excludeRoute` на API 33+.
pub fn android_split_domains_for_profile(profile: &TunnelProfile) -> Vec<String> {
    if !profile.split_tunnel_enabled {
        return Vec::new();
    }
    bypass_domains::domains_for_preset_ids(&profile.split_tunnel_preset_ids)
}

/// Android: пакеты из пресетов API + ручной список из профиля.
pub fn android_split_packages_for_profile(profile: &TunnelProfile) -> Vec<String> {
    if !profile.split_tunnel_enabled {
        return Vec::new();
    }
    let mut out = bypass_domains::android_packages_for_preset_ids(&profile.split_tunnel_preset_ids);
    for pkg in &profile.android_manual_split_packages {
        let k = pkg.trim();
        if !k.is_empty() && !out.iter().any(|x| x == k) {
            out.push(k.to_string());
        }
    }
    out.sort();
    out
}
