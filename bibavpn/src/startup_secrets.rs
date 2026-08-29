//! Startup validation for tunnel secrets (token denylist, PSK requirements).

use anyhow::{bail, Context};
use tracing::warn;

/// Lab-only default when `--token` is omitted with `--lab`.
pub const LAB_DEFAULT_TOKEN: &str = "change-me";

/// Returns true when `token` is empty/whitespace or matches a denylisted value (case-insensitive).
pub fn is_token_denylisted(token: &str) -> bool {
    let t = token.trim();
    if t.is_empty() {
        return true;
    }
    matches!(
        t.to_ascii_lowercase().as_str(),
        "change-me" | "changeme" | "test"
    )
}

/// Resolve `--token` for CLI binaries. With `--lab`, missing token becomes [`LAB_DEFAULT_TOKEN`]
/// and the denylist is skipped.
pub fn resolve_cli_token(token: Option<&str>, lab: bool) -> anyhow::Result<String> {
    if lab {
        if let Some(raw) = token {
            let t = raw.trim();
            if t.is_empty() {
                return Ok(LAB_DEFAULT_TOKEN.to_string());
            }
            return Ok(t.to_string());
        }
        return Ok(LAB_DEFAULT_TOKEN.to_string());
    }

    let raw = token.context("--token is required (or use --lab for local demos only)")?;
    let t = raw.trim();
    if t.is_empty() {
        bail!("--token must not be empty");
    }
    if is_token_denylisted(t) {
        bail!(
            "--token must not be a well-known placeholder (denylisted: change-me, changeme, test)"
        );
    }
    Ok(t.to_string())
}

/// Validate a resolved token (JSON start and post-invite merge). No lab bypass.
pub fn validate_resolved_token(token: &str) -> anyhow::Result<()> {
    let t = token.trim();
    if t.is_empty() {
        bail!("token is required");
    }
    if is_token_denylisted(t) {
        bail!(
            "token must not be a well-known placeholder (denylisted: change-me, changeme, test)"
        );
    }
    Ok(())
}

fn non_empty_str(s: Option<&str>) -> bool {
    s.map(str::trim).is_some_and(|t| !t.is_empty())
}

/// Server REALITY is fully configured when both target and private key are non-empty.
pub fn server_reality_configured(
    reality_target: Option<&str>,
    reality_private_key: Option<&str>,
) -> bool {
    non_empty_str(reality_target) && non_empty_str(reality_private_key)
}

/// Client REALITY is fully configured when target and public key are both set.
pub fn client_reality_configured(
    reality_target: Option<&str>,
    reality_public_key: Option<&[u8; 32]>,
) -> bool {
    non_empty_str(reality_target) && reality_public_key.is_some()
}

/// Require a non-empty PSK at process start unless REALITY is fully configured or `--lab`.
pub fn require_psk(
    psk: Option<&str>,
    reality_fully_configured: bool,
    lab: bool,
) -> anyhow::Result<()> {
    let psk_present = psk.map(str::trim).is_some_and(|s| !s.is_empty());
    if psk_present || lab || reality_fully_configured {
        Ok(())
    } else {
        bail!("--psk is required unless REALITY is fully configured or --lab is set");
    }
}

/// One-time WARN when `--lab` is enabled.
pub fn log_lab_mode_enabled() {
    warn!(
        target: "bibavpn_security",
        "lab mode enabled: well-known tokens allowed and PSK may be omitted when REALITY is configured"
    );
}

/// WARN when REALITY is on but PSK is absent (v3 / UDP mux still need PSK at runtime).
pub fn log_reality_without_psk() {
    warn!(
        target: "bibavpn_security",
        "REALITY is configured but PSK is absent; v3 HELLO and UDP mux still require --psk"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist_blocks_placeholders_and_empty() {
        for t in ["change-me", "CHANGE-ME", "changeme", "test", " test ", "", "   "] {
            assert!(is_token_denylisted(t), "expected denied: {t:?}");
        }
    }

    #[test]
    fn denylist_allows_short_and_compose_tokens() {
        for t in [
            "t",
            "tok",
            "test-token",
            "testtok",
            "wsl-test-token",
            "docker-compose-biba",
        ] {
            assert!(!is_token_denylisted(t), "expected allowed: {t:?}");
        }
    }

    #[test]
    fn resolve_cli_token_missing_without_lab() {
        assert!(resolve_cli_token(None, false).is_err());
    }

    #[test]
    fn resolve_cli_token_missing_with_lab() {
        assert_eq!(
            resolve_cli_token(None, true).unwrap(),
            LAB_DEFAULT_TOKEN
        );
    }

    #[test]
    fn resolve_cli_token_change_me_without_lab() {
        assert!(resolve_cli_token(Some("change-me"), false).is_err());
    }

    #[test]
    fn resolve_cli_token_change_me_with_lab() {
        assert_eq!(
            resolve_cli_token(Some("change-me"), true).unwrap(),
            "change-me"
        );
    }

    #[test]
    fn require_psk_missing_without_reality_or_lab() {
        assert!(require_psk(None, false, false).is_err());
        assert!(require_psk(Some("  "), false, false).is_err());
    }

    #[test]
    fn require_psk_ok_with_reality_or_lab_or_present() {
        require_psk(None, true, false).unwrap();
        require_psk(None, false, true).unwrap();
        require_psk(Some("secret"), false, false).unwrap();
    }

    #[test]
    fn server_reality_configured_requires_both_fields() {
        assert!(!server_reality_configured(Some("vk.com:443"), None));
        assert!(!server_reality_configured(None, Some("key")));
        assert!(server_reality_configured(Some("vk.com:443"), Some("key")));
    }

    #[test]
    fn client_reality_configured_requires_both_fields() {
        let pk = [1u8; 32];
        assert!(!client_reality_configured(Some("vk.com:443"), None));
        assert!(!client_reality_configured(None, Some(&pk)));
        assert!(client_reality_configured(Some("vk.com:443"), Some(&pk)));
    }
}
