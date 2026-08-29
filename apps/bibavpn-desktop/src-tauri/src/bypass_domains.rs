//! Bypass (split-tunnel) domain lists from the control-plane API.
//!
//! URL is **not** hardcoded: set `BIBA_BYPASS_DOMAINS_URL` at build time (CI secret / local `.env`)
//! or at runtime. CI also fetches the JSON before `cargo build` and embeds it via `build.rs`
//! (`include_str!` from `OUT_DIR`) so split-tunnel works offline / before the first refresh.
//! Responses are cached on disk under the platform data dir (`…/BibaVPN/`).
//!
//! All network, disk-cache, and non-empty embed paths require HTTPS for the configured URL and a
//! detached Ed25519 signature verified with `BIBA_BYPASS_DOMAINS_PUBKEY` before JSON is parsed.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const USER_AGENT: &str = "bibavpn-desktop/1.0";
const DEFAULT_TTL_SEC: u64 = 86_400;
/// Max wait for connect + response body when fetching bypass lists (fail fast; use disk cache).
pub const HTTP_TIMEOUT_SECS: u64 = 2;
const EMBEDDED_SOURCE: &str = "embedded";

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
    raw_body: String,
    /// Detached Ed25519 signature (raw 64 bytes or base64 in JSON as byte array).
    signature: Vec<u8>,
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

/// True when `url` is `https://` with a non-empty host. The internal `embedded://` sentinel is not remote.
fn is_https_url_with_host(url: &str) -> bool {
    let url = url.trim();
    if !url.starts_with("https://") {
        return false;
    }
    let rest = &url[8..];
    if rest.is_empty() {
        return false;
    }
    let host = rest
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or("")
        .trim();
    !host.is_empty()
}

fn log_refused_non_https_url(url: &str) {
    warn!(
        target: "bibavpn_desktop",
        url = %url,
        "bypass-domains: BIBA_BYPASS_DOMAINS_URL must be https:// with a non-empty host; refusing"
    );
}

/// Compile-time URL from `build.rs` (`cargo:rustc-env`) or runtime `BIBA_BYPASS_DOMAINS_URL`.
pub fn bypass_domains_url() -> Option<String> {
    let from_env = std::env::var("BIBA_BYPASS_DOMAINS_URL")
        .ok()
        .or_else(|| option_env!("BIBA_BYPASS_DOMAINS_URL").map(str::to_string));
    let Some(raw) = from_env else {
        return None;
    };
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    if is_https_url_with_host(&trimmed) {
        Some(trimmed)
    } else {
        log_refused_non_https_url(&trimmed);
        None
    }
}

fn parse_pubkey_hex(hex_str: &str) -> Option<[u8; 32]> {
    let hex_str = hex_str.trim();
    if hex_str.len() != 64 || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &hex_str[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Pinned Ed25519 public key from runtime env or `build.rs` (`cargo:rustc-env`).
pub fn bypass_domains_pubkey() -> Option<[u8; 32]> {
    if let Ok(v) = std::env::var("BIBA_BYPASS_DOMAINS_PUBKEY") {
        if let Some(pk) = parse_pubkey_hex(&v) {
            return Some(pk);
        }
    }
    option_env!("BIBA_BYPASS_DOMAINS_PUBKEY").and_then(|s| parse_pubkey_hex(s))
}

/// JSON baked in at compile time (CI `ci-fetch-bypass-domains.sh` → `build.rs` → OUT_DIR).
const EMBEDDED_BYPASS_JSON: &str =
    include_str!(concat!(env!("OUT_DIR"), "/bypass_domains_embedded.json"));
const EMBEDDED_BYPASS_SIG: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/bypass_domains_embedded.json.sig"));

fn embedded_has_nonempty_presets(body: &str) -> bool {
    serde_json::from_str::<ApiPayload>(body)
        .ok()
        .is_some_and(|data| !data.presets.is_empty())
}

fn decode_signature_bytes(sig: &[u8]) -> Option<[u8; 64]> {
    if sig.len() == 64 {
        return sig.try_into().ok();
    }
    let trimmed = sig.trim_ascii();
    if trimmed.len() == 64 {
        return trimmed.try_into().ok();
    }
    let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
        .ok()?;
    if decoded.len() == 64 {
        decoded.try_into().ok()
    } else {
        None
    }
}

fn verify_bypass_signature(
    body: &[u8],
    signature: &[u8],
    pubkey: &[u8; 32],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Some(sig_bytes) = decode_signature_bytes(signature) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(body, &sig).is_ok()
}

fn signature_companion_url(url: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let sig_base = format!("{base}.sig");
    match query {
        Some(q) => format!("{sig_base}?{q}"),
        None => sig_base,
    }
}

fn count_domains(presets: &[BypassPresetInfo]) -> usize {
    presets.iter().map(|p| p.domains.len()).sum()
}

fn apply_presets(
    state: &mut CacheState,
    presets: Vec<BypassPresetInfo>,
    ttl_sec: u64,
    url: &str,
    source: &str,
) {
    state.by_id.clear();
    for p in &presets {
        state.by_id.insert(p.id.clone(), p.clone());
    }
    state.presets = presets;
    state.url = url.to_string();
    state.fetched_at = Some(SystemTime::now());
    state.ttl = Duration::from_secs(ttl_sec.max(3600));
    state.loaded = true;
    info!(
        target: "bibavpn_desktop",
        source = %source,
        presets = state.presets.len(),
        domains = count_domains(&state.presets),
        "bypass-domains: applied"
    );
}

fn load_embedded_presets(pubkey: Option<&[u8; 32]>) -> Option<(Vec<BypassPresetInfo>, u64)> {
    if !embedded_has_nonempty_presets(EMBEDDED_BYPASS_JSON) {
        return None;
    }
    let Some(pk) = pubkey else {
        warn!(
            target: "bibavpn_desktop",
            "bypass-domains: embedded list requires BIBA_BYPASS_DOMAINS_PUBKEY; refusing"
        );
        return None;
    };
    if EMBEDDED_BYPASS_SIG.is_empty() {
        warn!(
            target: "bibavpn_desktop",
            "bypass-domains: embedded list missing signature; refusing"
        );
        return None;
    }
    let body = EMBEDDED_BYPASS_JSON.as_bytes();
    if !verify_bypass_signature(body, EMBEDDED_BYPASS_SIG, pk) {
        warn!(
            target: "bibavpn_desktop",
            "bypass-domains: embedded list signature verification failed; refusing"
        );
        return None;
    }
    parse_api_payload(EMBEDDED_BYPASS_JSON)
        .ok()
        .filter(|(presets, _)| !presets.is_empty())
}

/// True when a URL is configured and/or a non-empty list was embedded at build time.
pub fn bypass_source_configured() -> bool {
    if bypass_domains_url().is_some() {
        return true;
    }
    option_env!("BIBA_BYPASS_DOMAINS_EMBEDDED").is_some()
        || load_embedded_presets(bypass_domains_pubkey().as_ref()).is_some()
}

fn cache_file_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("BibaVPN").join("bypass_domains_cache.json"))
}

fn delete_disk_cache() {
    if let Some(path) = cache_file_path() {
        let _ = fs::remove_file(path);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn verify_and_parse_cache_file(
    file: &BypassCacheFile,
    expected_url: &str,
    pubkey: &[u8; 32],
) -> Option<(Vec<BypassPresetInfo>, u64)> {
    if file.url != expected_url {
        return None;
    }
    if file.raw_body.is_empty() || file.signature.is_empty() {
        return None;
    }
    let body = file.raw_body.as_bytes();
    if !verify_bypass_signature(body, &file.signature, pubkey) {
        return None;
    }
    let age = now_unix().saturating_sub(file.fetched_at_unix);
    if age > file.ttl_sec.saturating_add(600) {
        return None;
    }
    parse_api_payload(&file.raw_body).ok()
}

fn load_disk_cache(url: &str, pubkey: &[u8; 32]) -> Option<(Vec<BypassPresetInfo>, u64)> {
    let path = cache_file_path()?;
    let text = fs::read_to_string(&path).ok()?;
    let file: BypassCacheFile = match serde_json::from_str(&text) {
        Ok(f) => f,
        Err(_) => {
            warn!(
                target: "bibavpn_desktop",
                "bypass-domains: disk cache format invalid; deleting"
            );
            delete_disk_cache();
            return None;
        }
    };
    match verify_and_parse_cache_file(&file, url, pubkey) {
        Some(result) => Some(result),
        None => {
            warn!(
                target: "bibavpn_desktop",
                "bypass-domains: disk cache signature or TTL check failed; deleting"
            );
            delete_disk_cache();
            None
        }
    }
}

fn save_disk_cache(url: &str, ttl_sec: u64, raw_body: &str, signature: &[u8]) {
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
        raw_body: raw_body.to_string(),
        signature: signature.to_vec(),
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

fn fetch_http_bytes(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, String> {
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
    let mut body = Vec::new();
    resp.into_reader()
        .read_to_end(&mut body)
        .map_err(|e| format!("read body {url}: {e}"))?;
    Ok(body)
}

fn fetch_verified_remote(
    url: &str,
    pubkey: &[u8; 32],
) -> Result<(Vec<BypassPresetInfo>, u64, String, Vec<u8>), String> {
    if !is_https_url_with_host(url) {
        log_refused_non_https_url(url);
        return Err(format!("refusing non-https bypass-domains URL: {url}"));
    }
    let agent = http_agent();
    let body = fetch_http_bytes(&agent, url)?;
    let sig_url = signature_companion_url(url);
    let signature = fetch_http_bytes(&agent, &sig_url)?;
    if !verify_bypass_signature(&body, &signature, pubkey) {
        return Err("bypass-domains signature verification failed".into());
    }
    let body_str = std::str::from_utf8(&body).map_err(|e| format!("UTF-8 body: {e}"))?;
    let (presets, ttl) = parse_api_response(body_str)?;
    Ok((presets, ttl, body_str.to_string(), signature))
}

/// Single bulk request (or one preset URL). Used on the UI/connect hot path — max [`HTTP_TIMEOUT_SECS`].
fn fetch_remote(url: &str, pubkey: &[u8; 32]) -> Result<(Vec<BypassPresetInfo>, u64, String, Vec<u8>), String> {
    if url_has_preset_filter(url) {
        let agent = http_agent();
        let body = fetch_http_bytes(&agent, url)?;
        let sig_url = signature_companion_url(url);
        let signature = fetch_http_bytes(&agent, &sig_url)?;
        if !verify_bypass_signature(&body, &signature, pubkey) {
            return Err("bypass-domains signature verification failed".into());
        }
        let body_str = std::str::from_utf8(&body).map_err(|e| format!("UTF-8 body: {e}"))?;
        let (presets, ttl) = parse_api_response(body_str)?;
        return Ok((presets, ttl, body_str.to_string(), signature));
    }
    fetch_verified_remote(url, pubkey)
}

fn cache_is_fresh(state: &CacheState) -> bool {
    let Some(at) = state.fetched_at else {
        return false;
    };
    at.elapsed().unwrap_or(Duration::MAX) < state.ttl
}

fn known_good_or_embedded(
    remote_url: Option<&str>,
    pubkey: Option<&[u8; 32]>,
) -> Result<Vec<BypassPresetInfo>, String> {
    let state = cache_lock().lock().map_err(|e| e.to_string())?;
    if state.loaded && !state.presets.is_empty() {
        return Ok(state.presets.clone());
    }
    drop(state);
    if remote_url.is_some() && pubkey.is_none() {
        return Ok(Vec::new());
    }
    apply_embedded_into_cache(pubkey)
}

/// Background-only refresh (signed bulk fetch). Does not block the UI or connect path.
pub fn background_refresh_full() {
    let Some(url) = bypass_domains_url() else {
        return;
    };
    let Some(pubkey) = bypass_domains_pubkey() else {
        warn!(
            target: "bibavpn_desktop",
            "bypass-domains: BIBA_BYPASS_DOMAINS_PUBKEY not set; refusing background refresh"
        );
        return;
    };
    match fetch_remote(&url, &pubkey) {
        Ok((presets, ttl, raw_body, signature)) => {
            save_disk_cache(&url, ttl, &raw_body, &signature);
            if let Ok(mut state) = cache_lock().lock() {
                apply_presets(&mut state, presets.clone(), ttl, &url, &url);
            }
        }
        Err(e) => {
            warn!(target: "bibavpn_desktop", "bypass-domains background refresh: {e}");
        }
    }
}

fn apply_embedded_into_cache(
    pubkey: Option<&[u8; 32]>,
) -> Result<Vec<BypassPresetInfo>, String> {
    let Some((presets, ttl)) = load_embedded_presets(pubkey) else {
        return Ok(Vec::new());
    };
    let url = bypass_domains_url().unwrap_or_else(|| "embedded://bypass_domains".to_string());
    let mut state = cache_lock().lock().map_err(|e| e.to_string())?;
    apply_presets(&mut state, presets.clone(), ttl, &url, EMBEDDED_SOURCE);
    Ok(presets)
}

/// Load presets from memory, disk, network, or compile-time embed (in that order when stale).
pub fn ensure_loaded(force_refresh: bool) -> Result<Vec<BypassPresetInfo>, String> {
    let url_opt = bypass_domains_url();
    let pubkey = bypass_domains_pubkey();
    if url_opt.is_none() && load_embedded_presets(pubkey.as_ref()).is_none() {
        return Err(
            "BIBA_BYPASS_DOMAINS_URL не задан и embedded-список пуст (CI secret / local .env)"
                .to_string(),
        );
    }
    let url = url_opt
        .clone()
        .unwrap_or_else(|| "embedded://bypass_domains".to_string());
    let signed_sources_ok = url_opt.is_none() || pubkey.is_some();

    {
        let state = cache_lock().lock().map_err(|e| e.to_string())?;
        if state.loaded && !force_refresh && cache_is_fresh(&state) && state.url == url {
            return Ok(state.presets.clone());
        }
    }

    if !force_refresh {
        if signed_sources_ok {
            if let (Some(pk), Some(remote)) = (pubkey.as_ref(), url_opt.as_deref()) {
                if let Some((presets, ttl)) = load_disk_cache(remote, pk) {
                    let mut state = cache_lock().lock().map_err(|e| e.to_string())?;
                    apply_presets(&mut state, presets.clone(), ttl, remote, "disk");
                    return Ok(presets);
                }
            }
        } else {
            warn!(
                target: "bibavpn_desktop",
                "bypass-domains: BIBA_BYPASS_DOMAINS_PUBKEY not set; refusing disk cache"
            );
        }
        if let Ok(presets) = apply_embedded_into_cache(pubkey.as_ref()) {
            if !presets.is_empty() {
                return Ok(presets);
            }
        }
    }

    let Some(remote_url) = url_opt else {
        return apply_embedded_into_cache(pubkey.as_ref());
    };

    let Some(pk) = pubkey else {
        warn!(
            target: "bibavpn_desktop",
            "bypass-domains: BIBA_BYPASS_DOMAINS_PUBKEY not set; refusing network fetch"
        );
        return known_good_or_embedded(Some(&remote_url), pubkey.as_ref());
    };

    match fetch_remote(&remote_url, &pk) {
        Ok((presets, ttl, raw_body, signature)) => {
            save_disk_cache(&remote_url, ttl, &raw_body, &signature);
            let mut state = cache_lock().lock().map_err(|e| e.to_string())?;
            apply_presets(&mut state, presets.clone(), ttl, &remote_url, &remote_url);
            Ok(presets)
        }
        Err(e) => {
            warn!(target: "bibavpn_desktop", "bypass-domains fetch failed: {e}");
            known_good_or_embedded(Some(&remote_url), Some(&pk))
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
pub fn replace_cache_for_test(presets: Vec<BypassPresetInfo>) {
    let mut state = cache_lock().lock().expect("bypass cache");
    apply_presets(&mut state, presets, DEFAULT_TTL_SEC, "test://bypass");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn test_keypair() -> (SigningKey, [u8; 32]) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key.to_bytes())
    }

    fn sign_body(signing_key: &SigningKey, body: &[u8]) -> Vec<u8> {
        signing_key.sign(body).to_bytes().to_vec()
    }

    const SAMPLE_JSON: &str = r#"{
            "version": 1,
            "ttl_sec": 86400,
            "presets": [
                {"id": "banks", "label": "Banks", "domains": ["sberbank.ru"], "android_packages": []},
                {"id": "tinkoff", "label": "T-Bank", "domains": ["tinkoff.ru"], "android_packages": ["com.idamob.tinkoff.android"]}
            ]
        }"#;

    #[test]
    fn parse_sample_payload() {
        let (presets, ttl) = parse_api_payload(SAMPLE_JSON).unwrap();
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

    #[test]
    fn https_url_validation() {
        assert!(is_https_url_with_host("https://example.com/api"));
        assert!(is_https_url_with_host("https://example.com/api?x=1"));
        assert!(!is_https_url_with_host("http://example.com/api"));
        assert!(!is_https_url_with_host("file:///etc/passwd"));
        assert!(!is_https_url_with_host("https://"));
        assert!(!is_https_url_with_host("data:text/plain,hello"));
    }

    #[test]
    fn signature_companion_url_appends_before_query() {
        assert_eq!(
            signature_companion_url("https://host/api?x=1"),
            "https://host/api.sig?x=1"
        );
        assert_eq!(
            signature_companion_url("https://host/api"),
            "https://host/api.sig"
        );
    }

    #[test]
    fn valid_signature_verifies_and_parses() {
        let (sk, pk) = test_keypair();
        let body = SAMPLE_JSON.as_bytes();
        let sig = sign_body(&sk, body);
        assert!(verify_bypass_signature(body, &sig, &pk));
        let (presets, ttl) = parse_api_payload(SAMPLE_JSON).unwrap();
        assert_eq!(ttl, 86400);
        assert_eq!(presets.len(), 2);
    }

    #[test]
    fn tampered_body_fails_verify() {
        let (sk, pk) = test_keypair();
        let mut body = SAMPLE_JSON.as_bytes().to_vec();
        let sig = sign_body(&sk, &body);
        body[10] ^= 0xff;
        assert!(!verify_bypass_signature(&body, &sig, &pk));
    }

    #[test]
    fn wrong_pubkey_fails_verify() {
        let (sk, _pk) = test_keypair();
        let (_other_sk, other_pk) = test_keypair();
        let body = SAMPLE_JSON.as_bytes();
        let sig = sign_body(&sk, body);
        assert!(!verify_bypass_signature(body, &sig, &other_pk));
    }

    #[test]
    fn missing_signature_fails_verify() {
        let (_sk, pk) = test_keypair();
        let body = SAMPLE_JSON.as_bytes();
        assert!(!verify_bypass_signature(body, &[], &pk));
    }

    #[test]
    fn disk_cache_valid_raw_body_and_signature_loads() {
        let (sk, pk) = test_keypair();
        let body = SAMPLE_JSON;
        let sig = sign_body(&sk, body.as_bytes());
        let file = BypassCacheFile {
            fetched_at_unix: now_unix(),
            ttl_sec: DEFAULT_TTL_SEC,
            url: "https://example.com/api".to_string(),
            raw_body: body.to_string(),
            signature: sig,
        };
        let (presets, ttl) =
            verify_and_parse_cache_file(&file, "https://example.com/api", &pk).unwrap();
        assert_eq!(ttl, 86400);
        assert_eq!(presets.len(), 2);
    }

    #[test]
    fn disk_cache_tampered_body_rejected() {
        let (sk, pk) = test_keypair();
        let sig = sign_body(&sk, SAMPLE_JSON.as_bytes());
        let mut tampered = SAMPLE_JSON.to_string();
        tampered.push(' ');
        let file = BypassCacheFile {
            fetched_at_unix: now_unix(),
            ttl_sec: DEFAULT_TTL_SEC,
            url: "https://example.com/api".to_string(),
            raw_body: tampered,
            signature: sig,
        };
        assert!(verify_and_parse_cache_file(&file, "https://example.com/api", &pk).is_none());
    }

    #[test]
    fn disk_cache_missing_signature_rejected() {
        let (_sk, pk) = test_keypair();
        let file = BypassCacheFile {
            fetched_at_unix: now_unix(),
            ttl_sec: DEFAULT_TTL_SEC,
            url: "https://example.com/api".to_string(),
            raw_body: SAMPLE_JSON.to_string(),
            signature: Vec::new(),
        };
        assert!(verify_and_parse_cache_file(&file, "https://example.com/api", &pk).is_none());
    }
}
