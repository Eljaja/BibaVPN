//! Control plane API client (import token redeem).

use serde::Deserialize;

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

fn http_agent() -> ureq::Agent {
    use std::time::Duration;
    let timeout = Duration::from_secs(HTTP_TIMEOUT_SECS);
    ureq::AgentBuilder::new()
        .timeout_read(timeout)
        .timeout_connect(timeout)
        .build()
}

pub fn redeem_import(base_url: &str, token: &str) -> Result<ImportPayload, String> {
    let base = base_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err("control plane base_url пуст".into());
    }
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
    let text = resp
        .into_string()
        .map_err(|e| format!("control plane body: {e}"))?;
    if status != 200 {
        return Err(format!("control plane HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("control plane JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
