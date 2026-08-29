//! Подхватывает `BIBA_BYPASS_DOMAINS_URL` из окружения или `.env` (локально, не коммитится)
//! и вшивает JSON split-tunnel списка (`embedded/bypass_domains.json` или CI fetch).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn env_file_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(manifest) = env::var("CARGO_MANIFEST_DIR") {
        let manifest = PathBuf::from(manifest);
        out.push(manifest.join(".env"));
        if let Some(parent) = manifest.parent() {
            out.push(parent.join(".env"));
            if let Some(grand) = parent.parent() {
                out.push(grand.join(".env"));
            }
        }
    }
    out
}

fn load_dotenv() {
    for path in env_file_candidates() {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() || env::var(key).is_ok() {
                continue;
            }
            let mut val = val.trim().to_string();
            if (val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\''))
            {
                val = val[1..val.len() - 1].to_string();
            }
            // SAFETY: build.rs runs single-threaded before compilation.
            unsafe {
                env::set_var(key, val);
            }
        }
        break;
    }
}

fn empty_bypass_json() -> &'static str {
    r#"{"version":1,"ttl_sec":86400,"presets":[]}"#
}

fn resolve_bypass_json_source(manifest: &Path) -> PathBuf {
    if let Ok(p) = env::var("BIBA_BYPASS_DOMAINS_JSON_FILE") {
        let path = PathBuf::from(p.trim());
        if path.is_file() {
            return path;
        }
    }
    let embedded = manifest.join("embedded").join("bypass_domains.json");
    if embedded.is_file() {
        return embedded;
    }
    // Placeholder next to build.rs so local builds without CI fetch still compile.
    let placeholder = manifest.join("embedded").join("bypass_domains.empty.json");
    if placeholder.is_file() {
        return placeholder;
    }
    embedded
}

fn embed_bypass_domains_json() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out_dir.join("bypass_domains_embedded.json");

    let src = resolve_bypass_json_source(&manifest);
    let body = if src.is_file() {
        fs::read_to_string(&src).unwrap_or_else(|_| empty_bypass_json().to_string())
    } else {
        empty_bypass_json().to_string()
    };
    fs::write(&dest, body.as_bytes()).expect("write bypass_domains_embedded.json");

    // Non-empty presets → runtime can treat embed as a configured source.
    let has_presets = body
        .find("\"presets\"")
        .and_then(|i| body[i..].find('['))
        .map(|bracket_rel| {
            // bracket_rel is offset within the `"presets"` slice; recompute absolute.
            let abs = body.find("\"presets\"").unwrap() + bracket_rel;
            body[abs + 1..].trim_start().starts_with('{')
        })
        .unwrap_or(false);
    if has_presets {
        println!("cargo:rustc-env=BIBA_BYPASS_DOMAINS_EMBEDDED=1");
    }

    println!("cargo:rerun-if-changed={}", src.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("embedded").join("bypass_domains.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest
            .join("embedded")
            .join("bypass_domains.empty.json")
            .display()
    );
    println!("cargo:rerun-if-env-changed=BIBA_BYPASS_DOMAINS_JSON_FILE");
}

fn main() {
    load_dotenv();
    if let Ok(url) = env::var("BIBA_BYPASS_DOMAINS_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            println!("cargo:rustc-env=BIBA_BYPASS_DOMAINS_URL={trimmed}");
        }
    }
    println!("cargo:rerun-if-env-changed=BIBA_BYPASS_DOMAINS_URL");
    for path in env_file_candidates() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    embed_bypass_domains_json();
    tauri_build::build();
}
