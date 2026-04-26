//! Single place for **TLS profile resolution** and related priority rules (CLI / JSON / invite / presets).
//! Keep this in sync with `client.rs` and `start_json_config.rs`.

use crate::invite_uri::InviteV1;
use crate::stealth_v12::{preset, StealthProfile};
use crate::tls_util::TlsClientProfile;

/// Priority: `fingerprint` (CLI) → explicit `tls_profile` (CLI/JSON) → `stealth_profile` preset →
/// invite / JSON-embedded `tls_profile` → BibaV1.2 default (Chrome 132+ label).
pub fn resolve_tls_client_profile(
    fingerprint: Option<&str>,
    cli_or_json_tls: Option<&str>,
    stealth: Option<StealthProfile>,
    invite_or_embedded: Option<TlsClientProfile>,
) -> anyhow::Result<TlsClientProfile> {
    if let Some(s) = fingerprint.map(str::trim).filter(|s| !s.is_empty()) {
        return TlsClientProfile::from_fingerprint_str(s);
    }
    if let Some(s) = cli_or_json_tls.map(str::trim).filter(|s| !s.is_empty()) {
        return s.parse();
    }
    if let Some(p) = stealth {
        return Ok(preset(p).tls_profile);
    }
    if let Some(t) = invite_or_embedded {
        return Ok(t);
    }
    Ok(TlsClientProfile::Chrome132)
}

/// TLS client profile from `biba://` fields: `fingerprint` wins over `tls_profile` when set.
pub fn tls_profile_from_invite(inv: &InviteV1) -> anyhow::Result<Option<TlsClientProfile>> {
    if let Some(f) = inv
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(TlsClientProfile::from_fingerprint_str(f)?));
    }
    let t = inv.tls_profile.trim();
    if t.is_empty() {
        return Ok(None);
    }
    Ok(Some(t.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_fingerprint_wins() {
        let t = resolve_tls_client_profile(
            Some("random"),
            Some("default"),
            Some(StealthProfile::Balanced),
            None,
        )
        .unwrap();
        assert_eq!(t, TlsClientProfile::Randomized);
    }

    #[test]
    fn cli_tls_before_stealth() {
        let t = resolve_tls_client_profile(
            None,
            Some("firefox-136"),
            Some(StealthProfile::Balanced),
            None,
        )
        .unwrap();
        assert_eq!(t, TlsClientProfile::Firefox136);
    }

    #[test]
    fn stealth_before_invite() {
        let t = resolve_tls_client_profile(
            None,
            None,
            Some(StealthProfile::Balanced),
            Some(TlsClientProfile::Default),
        )
        .unwrap();
        assert_eq!(t, TlsClientProfile::Chrome132);
    }

    #[test]
    fn all_none_is_chrome132() {
        let t = resolve_tls_client_profile(
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(t, TlsClientProfile::Chrome132);
    }

    #[test]
    fn invite_default_when_no_higher_layer() {
        let t = resolve_tls_client_profile(
            None,
            None,
            None,
            Some(TlsClientProfile::Default),
        )
        .unwrap();
        assert_eq!(t, TlsClientProfile::Default);
    }

    #[test]
    fn empty_fingerprint_falls_through() {
        let t = resolve_tls_client_profile(
            None,
            None,
            Some(StealthProfile::Aggressive),
            None,
        )
        .unwrap();
        assert_eq!(t, TlsClientProfile::Chrome132);
    }
}
