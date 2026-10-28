//! Split-tunnel: домены в обход системного HTTP-прокси
//! (Windows ProxyOverride / macOS bypass / Linux GSettings `ignore-hosts`).
//! Списки доменов — из API / disk cache / compile-time embed ([`crate::bypass_domains`]).

use crate::bypass_domains;
use crate::config::TunnelProfile;

/// Hard caps so a malformed/oversized preset cannot make OS proxy lists or the
/// Android start JSON arbitrarily large.
const MAX_SPLIT_DOMAINS: usize = 4_096;
const MAX_SPLIT_PACKAGES: usize = 512;

fn normalized_domains(ids: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in bypass_domains::cached_domains_for_preset_ids(ids) {
        if out.len() >= MAX_SPLIT_DOMAINS {
            break;
        }
        if let Some(n) = bypass_domains::normalize_domain(&d) {
            if !out.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                out.push(n);
            }
        }
    }
    out
}

fn push_package(out: &mut Vec<String>, raw: &str) {
    if out.len() >= MAX_SPLIT_PACKAGES {
        return;
    }
    let Some(k) = bypass_domains::normalize_android_package(raw) else {
        return;
    };
    if !out.iter().any(|x| x == &k) {
        out.push(k);
    }
}

/// Домены для WinInet ProxyOverride / macOS bypass / Linux ignore-hosts
/// (без обязательных loopback — их добавляет платформа).
pub fn bypass_domains_for_profile(profile: &TunnelProfile) -> Vec<String> {
    if !profile.split_tunnel_enabled {
        return Vec::new();
    }
    normalized_domains(&profile.split_tunnel_preset_ids)
}

/// Android: домены из пресетов API → `split_bypass_domains` в start JSON (SOCKS/SNI в туннеле).
pub fn android_split_domains_for_profile(profile: &TunnelProfile) -> Vec<String> {
    if !profile.split_tunnel_enabled {
        return Vec::new();
    }
    normalized_domains(&profile.split_tunnel_preset_ids)
}

/// Android: пакеты из пресетов API + ручной список + `android_split_tunnel_packages` из профиля.
pub fn android_split_packages_for_profile(profile: &TunnelProfile) -> Vec<String> {
    if !profile.split_tunnel_enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pkg in
        bypass_domains::cached_android_packages_for_preset_ids(&profile.split_tunnel_preset_ids)
    {
        push_package(&mut out, &pkg);
    }
    for pkg in profile
        .android_manual_split_packages
        .iter()
        .chain(&profile.android_split_tunnel_packages)
    {
        push_package(&mut out, pkg);
    }
    out.sort();
    out
}

#[cfg(test)]
mod android_split_packages_tests {
    use super::*;
    use crate::config::TunnelProfile;

    #[test]
    fn legacy_only_android_split_tunnel_packages() {
        let mut p = TunnelProfile {
            ..TunnelProfile::default()
        };
        p.split_tunnel_enabled = true;
        p.android_split_tunnel_packages = vec!["com.legacy.app".to_string()];
        let out = android_split_packages_for_profile(&p);
        assert_eq!(out, vec!["com.legacy.app".to_string()]);
    }

    #[test]
    fn manual_and_merged_no_duplicates() {
        let mut p = TunnelProfile {
            ..TunnelProfile::default()
        };
        p.split_tunnel_enabled = true;
        p.android_split_tunnel_packages = vec!["com.a".to_string(), "com.b".to_string()];
        p.android_manual_split_packages = vec!["com.b".to_string(), "com.c".to_string()];
        let out = android_split_packages_for_profile(&p);
        assert_eq!(
            out,
            vec![
                "com.a".to_string(),
                "com.b".to_string(),
                "com.c".to_string(),
            ]
        );
    }

    #[test]
    fn split_disabled_returns_empty() {
        let mut p = TunnelProfile {
            ..TunnelProfile::default()
        };
        p.split_tunnel_enabled = false;
        p.android_split_tunnel_packages = vec!["com.legacy.app".to_string()];
        p.android_manual_split_packages = vec!["com.manual.app".to_string()];
        let out = android_split_packages_for_profile(&p);
        assert!(out.is_empty());
    }

    #[test]
    fn trim_and_skip_empty_in_android_split_tunnel_packages() {
        let mut p = TunnelProfile {
            ..TunnelProfile::default()
        };
        p.split_tunnel_enabled = true;
        p.android_split_tunnel_packages =
            vec!["  com.foo  ".to_string(), "".to_string(), "   ".to_string()];
        let out = android_split_packages_for_profile(&p);
        assert_eq!(out, vec!["com.foo".to_string()]);
    }

    #[test]
    fn invalid_android_packages_are_dropped() {
        let mut p = TunnelProfile {
            ..TunnelProfile::default()
        };
        p.split_tunnel_enabled = true;
        p.android_manual_split_packages = vec![
            "com.ok.app".into(),
            "bad package".into(),
            "x;y".into(),
            "пакет".into(),
            "com/ok".into(),
        ];
        assert_eq!(
            android_split_packages_for_profile(&p),
            vec!["com.ok.app".to_string()]
        );
    }

    #[test]
    fn android_package_count_is_capped() {
        let mut p = TunnelProfile {
            ..TunnelProfile::default()
        };
        p.split_tunnel_enabled = true;
        p.android_manual_split_packages = (0..(MAX_SPLIT_PACKAGES + 50))
            .map(|i| format!("com.example.app{i}"))
            .collect();
        let out = android_split_packages_for_profile(&p);
        assert_eq!(out.len(), MAX_SPLIT_PACKAGES);
    }
}
