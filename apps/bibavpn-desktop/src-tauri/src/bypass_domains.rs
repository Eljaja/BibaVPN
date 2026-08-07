//! Bypass (split-tunnel) domain lists from the control-plane API.
//!
//! URL is **not** hardcoded: set `BIBA_BYPASS_DOMAINS_URL` at build time (CI secret / local `.env`)
//! or at runtime. CI also fetches the JSON before `cargo build` and embeds it via `build.rs`
//! (`include_str!` from `OUT_DIR`) so split-tunnel works offline / before the first refresh.
//! Responses are cached on disk under the platform data dir (`…/BibaVPN/`).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const USER_AGENT: &str = "bibavpn-desktop/1.0";
const DEFAULT_TTL_SEC: u64 = 86_400;
/// Max wait for connect + response body when fetching bypass lists (fail fast; use disk cache).
pub const HTTP_TIMEOUT_SECS: u64 = 2;
/// When the bulk JSON stalls (~17 KiB on the origin), fetch each preset via `?preset=`.
const FALLBACK_PRESET_IDS: &[&str] = &[
    "gosuslugi",
    "gov",
    "max",
    "vk",
    "media",
    "entertainment",
    "banks",
    "tinkoff",
    "sber",
    "yandex_bank",
    "banki",
    "bog",
    "vtb",
    "alfa",
    "ecommerce",
    "retail",
    "ozon",
    "yandex_market",
    "steam",
    "games",
    "yandex_taxi",
    "yandex_vezet",
    "deliveryclub",
    "yandex_eda",
    "yandex_lavka",
    "samokat",
    "travel",
    "yandex",
    "medicine",
    "ru_all",
];

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
struct SinglePresetPayload {
    preset: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    android_packages: Vec<String>,
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

/// JSON baked in at compile time (CI `ci-fetch-bypass-domains.sh` → `build.rs` → OUT_DIR).
const EMBEDDED_BYPASS_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bypass_domains_embedded.json"));

fn load_embedded_presets() -> Option<(Vec<BypassPresetInfo>, u64)> {
    match parse_api_payload(EMBEDDED_BYPASS_JSON) {
        Ok((presets, ttl)) if !presets.is_empty() => Some((presets, ttl)),
        _ => None,
    }
}

/// True when a URL is configured and/or a non-empty list was embedded at build time.
pub fn bypass_source_configured() -> bool {
    if bypass_domains_url().is_some() {
        return true;
    }
    option_env!("BIBA_BYPASS_DOMAINS_EMBEDDED").is_some() || load_embedded_presets().is_some()
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

fn preset_label(id: &str, label: Option<String>) -> String {
    label
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| id.replace('_', " "))
}

fn parse_single_preset(body: &str) -> Result<BypassPresetInfo, String> {
    let data: SinglePresetPayload =
        serde_json::from_str(body).map_err(|e| format!("JSON bypass-domains preset: {e}"))?;
    if data.domains.is_empty() {
        return Err(format!("preset {} returned no domains", data.preset));
    }
    Ok(BypassPresetInfo {
        id: data.preset.clone(),
        label: preset_label(&data.preset, data.label),
        source: data.source,
        domains: data.domains,
        android_packages: data.android_packages,
    })
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
            id: p.id.clone(),
            label: preset_label(&p.id, p.label),
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

fn parse_api_response(body: &str) -> Result<(Vec<BypassPresetInfo>, u64), String> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') && trimmed.contains("\"presets\"") {
        parse_api_payload(body)
    } else {
        parse_single_preset(body).map(|p| (vec![p], DEFAULT_TTL_SEC))
    }
}

fn http_agent() -> ureq::Agent {
    let timeout = Duration::from_secs(HTTP_TIMEOUT_SECS);
    ureq::AgentBuilder::new()
        .timeout_read(timeout)
        .timeout_connect(timeout)
        .user_agent(USER_AGENT)
        .build()
}

fn url_has_preset_filter(url: &str) -> bool {
    url.split('?')
        .nth(1)
        .is_some_and(|q| q.split('&').any(|part| part.starts_with("preset=")))
}

fn preset_fetch_url(base_url: &str, preset_id: &str) -> String {
    if let Some((path, query)) = base_url.split_once('?') {
        format!("{path}?{query}&preset={preset_id}")
    } else {
        format!("{base_url}?preset={preset_id}")
    }
}

fn fetch_http_body(agent: &ureq::Agent, url: &str) -> Result<String, String> {
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("HTTP GET {url}: {e}"))?;
    let status = resp.status();
    if status == 429 {
        return Err(format!("HTTP 429 (rate limit) from {url}"));
    }
    if status != 200 {
        return Err(format!("HTTP {status} from {url}"));
    }
    resp.into_string()
        .map_err(|e| format!("read body {url}: {e}"))
}

fn fetch_remote_bulk(url: &str) -> Result<(Vec<BypassPresetInfo>, u64), String> {
    let agent = http_agent();
    let body = fetch_http_body(&agent, url)?;
    parse_api_response(&body)
}

fn fetch_remote_presets(base_url: &str) -> Result<(Vec<BypassPresetInfo>, u64), String> {
    let agent = http_agent();
    let mut presets = Vec::new();
    let mut errors = Vec::new();
    for (i, id) in FALLBACK_PRESET_IDS.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(120));
        }
        let url = preset_fetch_url(base_url, id);
        match fetch_http_body(&agent, &url) {
            Ok(body) => match parse_single_preset(&body) {
                Ok(p) => presets.push(p),
                Err(e) => errors.push(format!("{id}: {e}")),
            },
            Err(e) => errors.push(format!("{id}: {e}")),
        }
    }
    if presets.is_empty() {
        return Err(format!(
            "per-preset fetch returned nothing ({})",
            errors.join("; ")
        ));
    }
    if !errors.is_empty() {
        warn!(
            target: "bibavpn_desktop",
            ok = presets.len(),
            failed = errors.len(),
            "bypass-domains: partial per-preset fetch"
        );
    }
    Ok((presets, DEFAULT_TTL_SEC))
}

/// Single bulk request (or one preset URL). Used on the UI/connect hot path — max [`HTTP_TIMEOUT_SECS`].
fn fetch_remote(url: &str) -> Result<(Vec<BypassPresetInfo>, u64), String> {
    if url_has_preset_filter(url) {
        let agent = http_agent();
        let body = fetch_http_body(&agent, url)?;
        return parse_api_response(&body);
    }
    fetch_remote_bulk(url)
}

fn refresh_from_network_with_fallback(url: &str) -> Result<(Vec<BypassPresetInfo>, u64), String> {
    match fetch_remote(url) {
        Ok(result) => Ok(result),
        Err(bulk_err) => {
            warn!(
                target: "bibavpn_desktop",
                error = %bulk_err,
                "bypass-domains bulk fetch failed, trying per-preset (background)"
            );
            fetch_remote_presets(url)
                .map_err(|fallback_err| format!("{bulk_err}; per-preset fallback: {fallback_err}"))
        }
    }
}

fn cache_is_fresh(state: &CacheState) -> bool {
    let Some(at) = state.fetched_at else {
        return false;
    };
    at.elapsed().unwrap_or(Duration::MAX) < state.ttl
}

/// Background-only refresh (bulk, then per-preset fallback). Does not block the UI or connect path.
pub fn background_refresh_full() {
    let Some(url) = bypass_domains_url() else {
        return;
    };
    match refresh_from_network_with_fallback(&url) {
        Ok((presets, ttl)) => {
            save_disk_cache(&url, ttl, &presets);
            if let Ok(mut state) = cache_lock().lock() {
                apply_presets(&mut state, presets.clone(), ttl, &url);
                info!(
                    target: "bibavpn_desktop",
                    count = presets.len(),
                    "bypass-domains: background refresh ok"
                );
            }
        }
        Err(e) => {
            warn!(target: "bibavpn_desktop", "bypass-domains background refresh: {e}");
        }
    }
}

fn apply_embedded_into_cache() -> Result<Vec<BypassPresetInfo>, String> {
    let Some((presets, ttl)) = load_embedded_presets() else {
        return Ok(Vec::new());
    };
    let url = bypass_domains_url().unwrap_or_else(|| "embedded://bypass_domains".to_string());
    let mut state = cache_lock().lock().map_err(|e| e.to_string())?;
    apply_presets(&mut state, presets.clone(), ttl, &url);
    info!(
        target: "bibavpn_desktop",
        count = presets.len(),
        "bypass-domains: using compile-time embedded list"
    );
    Ok(presets)
}

/// Load presets from memory, disk, network, or compile-time embed (in that order when stale).
pub fn ensure_loaded(force_refresh: bool) -> Result<Vec<BypassPresetInfo>, String> {
    let url_opt = bypass_domains_url();
    if url_opt.is_none() && load_embedded_presets().is_none() {
        return Err(
            "BIBA_BYPASS_DOMAINS_URL не задан и embedded-список пуст (CI secret / local .env)"
                .to_string(),
        );
    }
    let url = url_opt
        .clone()
        .unwrap_or_else(|| "embedded://bypass_domains".to_string());

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
        // Prefer baked-in list over a cold network hop on first launch.
        if let Ok(presets) = apply_embedded_into_cache() {
            if !presets.is_empty() {
                return Ok(presets);
            }
        }
    }

    let Some(remote_url) = url_opt else {
        return apply_embedded_into_cache();
    };

    match fetch_remote(&remote_url) {
        Ok((presets, ttl)) => {
            save_disk_cache(&remote_url, ttl, &presets);
            let mut state = cache_lock().lock().map_err(|e| e.to_string())?;
            apply_presets(&mut state, presets.clone(), ttl, &remote_url);
            info!(
                target: "bibavpn_desktop",
                count = presets.len(),
                url = %remote_url,
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
            if let Some(file) = load_disk_cache(&remote_url) {
                drop(state);
                let mut state = cache_lock().lock().map_err(|e2| e2.to_string())?;
                apply_presets(&mut state, file.presets.clone(), file.ttl_sec, &remote_url);
                return Ok(state.presets.clone());
            }
            drop(state);
            apply_embedded_into_cache()
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

fn domains_for_preset_ids_from_cache(ids: &[String]) -> Vec<String> {
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

/// Return preset domains without touching the network.
///
/// The desktop connect path calls this while applying system proxy settings; a slow
/// control-plane URL must not make the UI look frozen during connect.
pub fn cached_domains_for_preset_ids(ids: &[String]) -> Vec<String> {
    domains_for_preset_ids_from_cache(ids)
}

pub fn domains_for_preset_ids(ids: &[String]) -> Vec<String> {
    cached_domains_for_preset_ids(ids)
}

fn android_packages_for_preset_ids_from_cache(ids: &[String]) -> Vec<String> {
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

pub fn cached_android_packages_for_preset_ids(ids: &[String]) -> Vec<String> {
    android_packages_for_preset_ids_from_cache(ids)
}

pub fn android_packages_for_preset_ids(ids: &[String]) -> Vec<String> {
    cached_android_packages_for_preset_ids(ids)
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

    #[test]
    fn parse_single_preset_payload() {
        let json = r#"{"preset":"banks","domains":["sberbank.ru","*.sberbank.ru"],"count":2}"#;
        let p = parse_single_preset(json).unwrap();
        assert_eq!(p.id, "banks");
        assert_eq!(p.label, "banks");
        assert_eq!(p.domains.len(), 2);
    }

    #[test]
    fn preset_fetch_url_appends_query() {
        assert_eq!(
            preset_fetch_url("https://example.com/api", "banks"),
            "https://example.com/api?preset=banks"
        );
        assert_eq!(
            preset_fetch_url("https://example.com/api?format=json", "gov"),
            "https://example.com/api?format=json&preset=gov"
        );
    }
}
