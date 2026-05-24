//! Bypass (split-tunnel) domain lists from the control-plane API.
//!
//! URL is **not** hardcoded: set `BIBA_BYPASS_DOMAINS_URL` at build time (CI secret / local `.env`)
//! or at runtime. Responses are cached on disk under `%LOCALAPPDATA%/BibaVPN/`.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const USER_AGENT: &str = "bibavpn-desktop/1.0";
const DEFAULT_TTL_SEC: u64 = 86_400;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BypassPresetInfo {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub android_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BypassCacheFile {
    fetched_at_unix: u64,
    ttl_sec: u64,
    url: String,
    presets: Vec<BypassPresetInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiPayload {
    #[serde(default)]
    ttl_sec: u64,
    #[serde(default)]
    presets: Vec<ApiPreset>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiPreset {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    android_packages: Vec<String>,
}

struct CacheState {
    loaded: bool,
    url: String,
    fetched_at: Option<SystemTime>,
    ttl: Duration,
    presets: Vec<BypassPresetInfo>,
    by_id: HashMap<String, BypassPresetInfo>,
}

impl Default for CacheState {
    fn default() -> Self {
        Self {
            loaded: false,
            url: String::new(),
            fetched_at: None,
            ttl: Duration::from_secs(DEFAULT_TTL_SEC),
            presets: Vec::new(),
            by_id: HashMap::new(),
        }
    }
}

static CACHE: OnceLock<Mutex<CacheState>> = OnceLock::new();

fn cache_lock() -> &'static Mutex<CacheState> {
    CACHE.get_or_init(|| Mutex::new(CacheState::default()))
}

/// Compile-time URL from `build.rs` (`cargo:rustc-env`) or runtime `BIBA_BYPASS_DOMAINS_URL`.
pub fn bypass_domains_url() -> Option<String> {
    if let Ok(v) = std::env::var("BIBA_BYPASS_DOMAINS_URL") {
        let t = v.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    option_env!("BIBA_BYPASS_DOMAINS_URL").and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

fn cache_file_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("BibaVPN").join("bypass_domains_cache.json"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn apply_presets(state: &mut CacheState, presets: Vec<BypassPresetInfo>, ttl_sec: u64, url: &str) {
    state.by_id.clear();
    for p in &presets {
        state.by_id.insert(p.id.clone(), p.clone());
    }
    state.presets = presets;
    state.url = url.to_string();
    state.fetched_at = Some(SystemTime::now());
    state.ttl = Duration::from_secs(ttl_sec.max(3600));
    state.loaded = true;
}

fn load_disk_cache(url: &str) -> Option<BypassCacheFile> {
    let path = cache_file_path()?;
    let text = fs::read_to_string(&path).ok()?;
    let file: BypassCacheFile = serde_json::from_str(&text).ok()?;
    if file.url != url {
        return None;
    }
    let age = now_unix().saturating_sub(file.fetched_at_unix);
    if age > file.ttl_sec.saturating_add(600) {
        return None;
    }
    Some(file)
}

fn save_disk_cache(url: &str, ttl_sec: u64, presets: &[BypassPresetInfo]) {
    let Some(path) = cache_file_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let file = BypassCacheFile {
        fetched_at_unix: now_unix(),
        ttl_sec,
        url: url.to_string(),
        presets: presets.to_vec(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&file) {
        let _ = fs::write(path, json);
    }
}

fn parse_api_payload(body: &str) -> Result<(Vec<BypassPresetInfo>, u64), String> {
    let data: ApiPayload =
        serde_json::from_str(body).map_err(|e| format!("JSON bypass-domains: {e}"))?;
    let ttl = if data.ttl_sec >= 3600 {
        data.ttl_sec
    } else {
        DEFAULT_TTL_SEC
    };
    let presets: Vec<BypassPresetInfo> = data
        .presets
        .into_iter()
        .map(|p| BypassPresetInfo {
            id: p.id,
            label: p
                .label
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "Preset".into()),
            source: p.source,
            domains: p.domains,
            android_packages: p.android_packages,
        })
        .collect();
    if presets.is_empty() {
        return Err("bypass-domains API returned no presets".into());
    }
    Ok((presets, ttl))
}

fn fetch_remote(url: &str) -> Result<(Vec<BypassPresetInfo>, u64), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(20))
        .timeout_connect(Duration::from_secs(12))
        .user_agent(USER_AGENT)
        .build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("HTTP {} from {url}", resp.status()));
    }
    let body = resp
        .into_string()
        .map_err(|e| format!("read body {url}: {e}"))?;
    parse_api_payload(&body)
}

fn cache_is_fresh(state: &CacheState) -> bool {
    let Some(at) = state.fetched_at else {
        return false;
    };
    at.elapsed().unwrap_or(Duration::MAX) < state.ttl
}

/// Load presets from memory, disk, or network (in that order when stale).
pub fn ensure_loaded(force_refresh: bool) -> Result<Vec<BypassPresetInfo>, String> {
    let url = bypass_domains_url().ok_or_else(|| {
        "BIBA_BYPASS_DOMAINS_URL не задан (CI secret или local .env)".to_string()
    })?;

    {
        let state = cache_lock().lock().map_err(|e| e.to_string())?;
        if state.loaded && !force_refresh && cache_is_fresh(&state) && state.url == url {
            return Ok(state.presets.clone());
        }
    }

    if !force_refresh {
        if let Some(file) = load_disk_cache(&url) {
            let mut state = cache_lock().lock().map_err(|e| e.to_string())?;
            apply_presets(&mut state, file.presets.clone(), file.ttl_sec, &url);
            info!(target: "bibavpn_desktop", count = state.presets.len(), "bypass-domains: disk cache");
            return Ok(state.presets.clone());
        }
    }

    match fetch_remote(&url) {
        Ok((presets, ttl)) => {
            save_disk_cache(&url, ttl, &presets);
            let mut state = cache_lock().lock().map_err(|e| e.to_string())?;
            apply_presets(&mut state, presets.clone(), ttl, &url);
            info!(
                target: "bibavpn_desktop",
                count = presets.len(),
                url = %url,
                "bypass-domains: fetched from API"
            );
            Ok(presets)
        }
        Err(e) => {
            warn!(target: "bibavpn_desktop", "bypass-domains fetch failed: {e}");
            let state = cache_lock().lock().map_err(|e2| e2.to_string())?;
            if state.loaded && !state.presets.is_empty() {
                return Ok(state.presets.clone());
            }
            if let Some(file) = load_disk_cache(&url) {
                drop(state);
                let mut state = cache_lock().lock().map_err(|e2| e2.to_string())?;
                apply_presets(&mut state, file.presets.clone(), file.ttl_sec, &url);
                return Ok(state.presets.clone());
            }
            Err(e)
        }
    }
}

pub fn list_presets() -> Result<Vec<BypassPresetInfo>, String> {
    ensure_loaded(false)
}

pub fn cached_presets_or_empty() -> Vec<BypassPresetInfo> {
    cache_lock()
        .lock()
        .ok()
        .filter(|s| s.loaded)
        .map(|s| s.presets.clone())
        .unwrap_or_default()
}

pub fn domains_for_preset_ids(ids: &[String]) -> Vec<String> {
    let _ = ensure_loaded(false);
    let state = match cache_lock().lock() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for id in ids {
        let key = id.trim();
        if key.is_empty() {
            continue;
        }
        if let Some(p) = state.by_id.get(key) {
            for d in &p.domains {
                if !out.iter().any(|x| x.eq_ignore_ascii_case(d)) {
                    out.push(d.clone());
                }
            }
        }
    }
    out
}

pub fn android_packages_for_preset_ids(ids: &[String]) -> Vec<String> {
    let _ = ensure_loaded(false);
    let state = match cache_lock().lock() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for id in ids {
        let key = id.trim();
        if key.is_empty() {
            continue;
        }
        if let Some(p) = state.by_id.get(key) {
            for pkg in &p.android_packages {
                let k = pkg.trim();
                if !k.is_empty() && !out.iter().any(|x| x == k) {
                    out.push(k.to_string());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_payload() {
        let json = r#"{
            "version": 1,
            "ttl_sec": 86400,
            "presets": [
                {"id": "banks", "label": "Banks", "domains": ["sberbank.ru"], "android_packages": []},
                {"id": "tinkoff", "label": "T-Bank", "domains": ["tinkoff.ru"], "android_packages": ["com.idamob.tinkoff.android"]}
            ]
        }"#;
        let (presets, ttl) = parse_api_payload(json).unwrap();
        assert_eq!(ttl, 86400);
        assert_eq!(presets.len(), 2);
        assert_eq!(presets[1].android_packages[0], "com.idamob.tinkoff.android");
    }
}
