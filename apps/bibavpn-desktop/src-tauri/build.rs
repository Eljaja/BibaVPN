//! Подхватывает `BIBA_BYPASS_DOMAINS_URL` из окружения или `.env` (локально, не коммитится).

use std::path::PathBuf;

fn env_file_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
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
        let Ok(text) = std::fs::read_to_string(&path) else {
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
            if key.is_empty() || std::env::var(key).is_ok() {
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
                std::env::set_var(key, val);
            }
        }
        break;
    }
}

fn main() {
    load_dotenv();
    if let Ok(url) = std::env::var("BIBA_BYPASS_DOMAINS_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            println!("cargo:rustc-env=BIBA_BYPASS_DOMAINS_URL={trimmed}");
        }
    }
    println!("cargo:rerun-if-env-changed=BIBA_BYPASS_DOMAINS_URL");
    for path in env_file_candidates() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    tauri_build::build();
}
