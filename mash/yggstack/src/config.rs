/// Thin wrapper around the Yggdrasil-ng `Config`.
///
/// We expose only what yggstack needs: load, save, generate, and key
/// extraction.  The TUN adapter is always disabled (`if_name = "none"`).
use std::fs;
use std::io::{self, Read};
use std::net::Ipv6Addr;
use std::path::Path;

use yggdrasil::config::Config as YggConfig;

pub use yggdrasil::config::Config;

pub const NAME_MAPPING_SUFFIX: &str = ".pk.ygg";

/// Derive the Yggdrasil IPv6 address from a 32-byte public key.
pub fn addr_for_key(public_key: &[u8; 32]) -> Ipv6Addr {
    let a = yggdrasil::address::addr_for_key(public_key);
    Ipv6Addr::from(a.0)
}

/// Derive the Yggdrasil /64 subnet prefix from a 32-byte public key.
pub fn subnet_for_key(public_key: &[u8; 32]) -> (Ipv6Addr, u8) {
    let s = yggdrasil::address::subnet_for_key(public_key);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&s.0);
    (Ipv6Addr::from(bytes), 64)
}

/// Load a config from a file path.
pub fn load_file(path: &Path) -> Result<Config, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let mut cfg: Config = toml::from_str(&text)
        .map_err(|e| format!("TOML parse error: {}", e))?;
    cfg.if_name = "none".to_string();
    // admin_listen is kept from config (e.g. "tcp://127.0.0.1:9001")
    Ok(cfg)
}

/// Load a config from stdin.
pub fn load_stdin() -> Result<Config, String> {
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .map_err(|e| format!("stdin read error: {}", e))?;
    let mut cfg: Config = toml::from_str(&text)
        .map_err(|e| format!("TOML parse error: {}", e))?;
    cfg.if_name = "none".to_string();
    // admin_listen is kept from config
    Ok(cfg)
}

/// Generate a brand-new config (random keypair, TUN disabled).
pub fn generate() -> Config {
    let mut cfg = Config::generate();
    cfg.if_name = "none".to_string();
    cfg.admin_listen = "none".to_string();
    cfg
}

/// Return the TOML text for a freshly generated config.
pub fn generate_text() -> String {
    let text = YggConfig::generate_config_text();
    // Override if_name and admin_listen in the generated text by appending
    // a small override section (simpler than reparsing the full template).
    // The template already has these fields, so toml::from_str + re-serialize.
    let mut cfg: Config = toml::from_str(&text).unwrap_or_else(|_| Config::default());
    cfg.if_name = "none".to_string();
    cfg.admin_listen = "none".to_string();
    toml::to_string_pretty(&cfg).unwrap_or(text)
}
