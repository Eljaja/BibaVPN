//! Control plane API client (import token redeem).

use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ImportPayload {
    pub invite_uri: String,
    pub invite_passphrase: String,
    pub instance_id: i64,
    pub display_name: String,
    pub server_name: String,
    pub server_public_host: String,
    pub host_port: i64,
    pub expires_at: String,
    pub config_version: String,
}

const HTTP_TIMEOUT_SECS: u64 = 20;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Keep error bodies out of logs/front-end in full; they are remote-controlled.
const MAX_ERROR_TEXT: usize = 512;

fn http_agent() -> ureq::Agent {
    use std::time::Duration;
    let timeout = Duration::from_secs(HTTP_TIMEOUT_SECS);
    ureq::AgentBuilder::new()
        .timeout_read(timeout)
        .timeout_connect(timeout)
        // The base origin is allowlisted; do not let a 3xx hop move the
        // import request to another host.
        .redirects(0)
        .build()
}

fn read_body_capped(resp: ureq::Response, url: &str) -> Result<String, String> {
    use std::io::Read;
    if let Some(len) = resp
        .header("Content-Length")
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        if len > MAX_RESPONSE_BYTES as u64 {
            return Err(format!(
                "control plane body too large ({len} > {MAX_RESPONSE_BYTES} bytes)"
            ));
        }
    }
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("control plane body: {e}"))?;
    if buf.len() > MAX_RESPONSE_BYTES {
        return Err("control plane body too large".into());
    }
    String::from_utf8(buf).map_err(|e| format!("control plane body ({url}): {e}"))
}

fn truncate_for_error(text: &str) -> String {
    let mut end = text.len().min(MAX_ERROR_TEXT);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    if end < text.len() {
        format!("{}…", &text[..end])
    } else {
        text.to_string()
    }
}

fn redact_secret(text: &str, secret: &str) -> String {
    if secret.len() < 4 {
        return text.to_string();
    }
    text.replace(secret, "<redacted>")
}

/// Extract `https://host` or `https://host:port` from a service URL (path/query ignored).
/// Used for `BIBA_BYPASS_DOMAINS_URL` and saved profile `control_plane_base_url` values.
pub fn origin_from_service_url(url_str: &str) -> Result<String, String> {
    let trimmed = url_str.trim();
    if trimmed.is_empty() {
        return Err("control plane: URL пуст".into());
    }
    let parsed = Url::parse(trimmed).map_err(|_| "control plane: неверный URL".to_string())?;
    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Err("control plane: требуется HTTPS".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("control plane: userinfo в URL запрещён".into());
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "control plane: хост не задан".to_string())?;
    let port = parsed.port().unwrap_or(443);
    Ok(canonical_origin(host, port))
}

fn canonical_origin(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    }
}

/// Strict validation for deeplink `base_url` before any HTTP request.
pub fn validate_control_plane_base_url(
    base_url: &str,
    allowed_origins: &[String],
) -> Result<String, String> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err("control plane base_url пуст".into());
    }
    if allowed_origins.is_empty() {
        return Err("control plane: импорт недоступен (не задан BIBA_BYPASS_DOMAINS_URL)".into());
    }
    let parsed = Url::parse(trimmed).map_err(|_| "control plane: неверный URL".to_string())?;
    if !parsed.scheme().eq_ignore_ascii_case("https") {
        return Err("control plane: требуется HTTPS".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("control plane: userinfo в URL запрещён".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("control plane: query/fragment в URL запрещён".into());
    }
    let path = parsed.path();
    if !path.is_empty() && path != "/" {
        return Err("control plane: путь в URL запрещён".into());
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "control plane: хост не задан".to_string())?;
    let port = parsed.port().unwrap_or(443);
    let origin = canonical_origin(host, port);
    let allowed = allowed_origins
        .iter()
        .any(|o| o.eq_ignore_ascii_case(&origin));
    if !allowed {
        return Err("control plane: хост не в списке разрешённых".into());
    }
    Ok(origin)
}

/// Build the union allowlist: compile-time/runtime bypass URL origin + saved profile origins.
pub fn build_allowed_origins(profile_origins: &[String]) -> Vec<String> {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    if let Some(url) = crate::bypass_domains::bypass_domains_url() {
        if let Ok(origin) = origin_from_service_url(&url) {
            set.insert(origin);
        }
    }
    for o in profile_origins {
        let t = o.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(origin) = origin_from_service_url(t) {
            set.insert(origin);
        }
    }
    set.into_iter().collect()
}

pub fn redeem_import(
    base_url: &str,
    token: &str,
    allowed_origins: &[String],
) -> Result<(String, ImportPayload), String> {
    let base = validate_control_plane_base_url(base_url, allowed_origins)?;
    let payload = redeem_import_at_origin(&base, token)?;
    Ok((base, payload))
}

fn redeem_import_at_origin(base: &str, token: &str) -> Result<ImportPayload, String> {
    let tok = token.trim();
    if tok.is_empty() {
        return Err("import token пуст".into());
    }
    let url = format!("{base}/api/v1/client/import");
    let body = serde_json::json!({ "token": tok });
    let resp = http_agent()
        .post(&url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_json(body)
        .map_err(|e| format!("control plane: {e}"))?;
    let status = resp.status();
    let text = read_body_capped(resp, &url)?;
    if status != 200 {
        return Err(format!(
            "control plane HTTP {status}: {}",
            truncate_for_error(&redact_secret(&text, tok))
        ));
    }
    serde_json::from_str(&text).map_err(|e| format!("control plane JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(host: &str) -> Vec<String> {
        vec![format!("https://{host}")]
    }

    #[test]
    fn import_payload_deserializes() {
        let raw = r#"{
            "invite_uri": "biba://x",
            "invite_passphrase": "pw",
            "instance_id": 7,
            "display_name": "alice",
            "server_name": "node1",
            "server_public_host": "203.0.113.1",
            "host_port": 20001,
            "expires_at": "2026-12-01T00:00:00Z",
            "config_version": "20260529120000"
        }"#;
        let p: ImportPayload = serde_json::from_str(raw).unwrap();
        assert_eq!(p.instance_id, 7);
        assert_eq!(p.config_version, "20260529120000");
    }

    #[test]
    fn accept_https_origin_when_allowlisted() {
        let allowed = allow("cp.example.com");
        assert_eq!(
            validate_control_plane_base_url("https://cp.example.com", &allowed).unwrap(),
            "https://cp.example.com"
        );
        assert_eq!(
            validate_control_plane_base_url("https://cp.example.com/", &allowed).unwrap(),
            "https://cp.example.com"
        );
    }

    #[test]
    fn accept_case_insensitive_scheme_and_host() {
        let allowed = allow("cp.example.com");
        assert_eq!(
            validate_control_plane_base_url("HTTPS://CP.EXAMPLE.COM", &allowed).unwrap(),
            "https://cp.example.com"
        );
    }

    #[test]
    fn accept_profile_origin_when_env_unset() {
        let allowed = vec!["https://cp.example.com".to_string()];
        assert_eq!(
            validate_control_plane_base_url("https://cp.example.com", &allowed).unwrap(),
            "https://cp.example.com"
        );
    }

    #[test]
    fn reject_http_scheme() {
        let allowed = allow("cp.example.com");
        let err = validate_control_plane_base_url("http://cp.example.com", &allowed).unwrap_err();
        assert!(err.contains("HTTPS"), "{err}");
    }

    #[test]
    fn reject_non_allowlisted_host() {
        let allowed = allow("cp.example.com");
        let err = validate_control_plane_base_url("https://evil.example", &allowed).unwrap_err();
        assert!(err.contains("разрешённых"), "{err}");
    }

    #[test]
    fn reject_userinfo() {
        let allowed = allow("cp.example.com");
        for url in [
            "https://evil@cp.example.com",
            "https://evil:pw@cp.example.com",
        ] {
            let err = validate_control_plane_base_url(url, &allowed).unwrap_err();
            assert!(err.contains("userinfo"), "{url}: {err}");
        }
    }

    #[test]
    fn reject_scheme_relative() {
        let allowed = allow("cp.example.com");
        assert!(validate_control_plane_base_url("//cp.example.com", &allowed).is_err());
    }

    #[test]
    fn reject_suffix_host_attack() {
        let allowed = allow("cp.example.com");
        let err = validate_control_plane_base_url("https://cp.example.com.evil.com", &allowed)
            .unwrap_err();
        assert!(err.contains("разрешённых"), "{err}");
    }

    #[test]
    fn reject_path_and_query() {
        let allowed = allow("cp.example.com");
        for url in ["https://cp.example.com/extra", "https://cp.example.com?x=1"] {
            let err = validate_control_plane_base_url(url, &allowed).unwrap_err();
            assert!(
                err.contains("путь") || err.contains("query"),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn reject_empty_base_url() {
        let allowed = allow("cp.example.com");
        assert!(validate_control_plane_base_url("", &allowed).is_err());
        assert!(validate_control_plane_base_url("   ", &allowed).is_err());
    }

    #[test]
    fn reject_empty_allowlist() {
        let err = validate_control_plane_base_url("https://cp.example.com", &[]).unwrap_err();
        assert!(err.contains("недоступен"), "{err}");
    }

    #[test]
    fn redeem_import_rejects_http_before_network() {
        let allowed = allow("cp.example.com");
        let err = redeem_import("http://cp.example.com", "tok", &allowed).unwrap_err();
        assert!(err.contains("HTTPS"), "{err}");
    }

    #[test]
    fn origin_from_service_url_strips_path() {
        assert_eq!(
            origin_from_service_url("https://cp.example.com/api/v1/foo").unwrap(),
            "https://cp.example.com"
        );
    }

    #[test]
    fn truncate_for_error_respects_utf8_boundaries() {
        let s = "я".repeat(MAX_ERROR_TEXT);
        let out = truncate_for_error(&s);
        assert!(out.len() <= MAX_ERROR_TEXT + '…'.len_utf8());
        assert!(out.ends_with('…'));
        assert_eq!(truncate_for_error("short"), "short");
    }

    #[test]
    fn redact_secret_hides_tokens_from_error_bodies() {
        assert_eq!(
            redact_secret("bad token abcdef123", "abcdef123"),
            "bad token <redacted>"
        );
        assert_eq!(redact_secret("x", ""), "x");
    }

    #[test]
    fn origin_from_service_url_non_default_port() {
        assert_eq!(
            origin_from_service_url("https://cp.example.com:4443/x").unwrap(),
            "https://cp.example.com:4443"
        );
        let allowed = vec!["https://cp.example.com:4443".to_string()];
        let err = validate_control_plane_base_url(
            "https://cp.example.com:4443",
            &allow("cp.example.com"),
        )
        .unwrap_err();
        assert!(err.contains("разрешённых"), "{err}");
        assert_eq!(
            validate_control_plane_base_url("https://cp.example.com:4443", &allowed).unwrap(),
            "https://cp.example.com:4443"
        );
    }
}
