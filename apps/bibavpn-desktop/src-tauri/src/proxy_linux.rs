//! Системный прокси Linux через GNOME GSettings (`org.gnome.system.proxy`).
//! Работает на GNOME / Pop!_OS / COSMIC и приложениях, читающих libproxy/GProxyResolver.
//! Split-tunnel: домены в `ignore-hosts` (прямой выход, как WinInet ProxyOverride / macOS bypass).
//!
//! Schema notes: only `org.gnome.system.proxy.http` has an `enabled` key (unused by GNOME —
//! a protocol is active when its `host` is non-empty). https/ftp/socks expose only host+port.

use std::io;
use std::process::{Command, Stdio};

const SCHEMA: &str = "org.gnome.system.proxy";
const SCHEMA_HTTP: &str = "org.gnome.system.proxy.http";
const SCHEMA_HTTPS: &str = "org.gnome.system.proxy.https";
const SCHEMA_SOCKS: &str = "org.gnome.system.proxy.socks";
const SCHEMA_FTP: &str = "org.gnome.system.proxy.ftp";

#[derive(Debug, Clone)]
struct HttpSlotBackup {
    enabled: bool,
    host: String,
    port: i32,
}

#[derive(Debug, Clone)]
struct HostPortBackup {
    host: String,
    port: i32,
}

#[derive(Debug, Clone)]
pub struct ProxyBackup {
    mode: String,
    use_same_proxy: bool,
    ignore_hosts: String,
    http: HttpSlotBackup,
    https: HostPortBackup,
    socks: HostPortBackup,
    ftp: HostPortBackup,
}

fn gsettings_available() -> bool {
    Command::new("gsettings")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn gsettings_get(schema: &str, key: &str) -> Result<String, String> {
    let out = Command::new("gsettings")
        .args(["get", schema, key])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("gsettings get {schema} {key}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let msg = err.trim();
        return Err(format!(
            "gsettings get {schema} {key}: {}",
            if msg.is_empty() { "failed" } else { msg }
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn gsettings_set(schema: &str, key: &str, value: &str) -> Result<(), String> {
    let out = Command::new("gsettings")
        .args(["set", schema, key, value])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("gsettings set {schema} {key}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let msg = err.trim();
        return Err(format!(
            "gsettings set {schema} {key}: {}",
            if msg.is_empty() { "failed" } else { msg }
        ));
    }
    Ok(())
}

fn parse_gvariant_string(raw: &str) -> String {
    let t = raw.trim();
    if t == "''" || t == "\"\"" {
        return String::new();
    }
    if (t.starts_with('\'') && t.ends_with('\'')) || (t.starts_with('"') && t.ends_with('"')) {
        return t[1..t.len() - 1].replace("\\'", "'").replace("\\\"", "\"");
    }
    t.to_string()
}

fn parse_gvariant_bool(raw: &str) -> bool {
    matches!(raw.trim(), "true" | "True" | "1")
}

fn parse_gvariant_i32(raw: &str) -> i32 {
    raw.trim().parse().unwrap_or(0)
}

fn format_gvariant_string(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn read_http_slot() -> Result<HttpSlotBackup, String> {
    Ok(HttpSlotBackup {
        enabled: parse_gvariant_bool(&gsettings_get(SCHEMA_HTTP, "enabled")?),
        host: parse_gvariant_string(&gsettings_get(SCHEMA_HTTP, "host")?),
        port: parse_gvariant_i32(&gsettings_get(SCHEMA_HTTP, "port")?),
    })
}

fn read_host_port(schema: &str) -> Result<HostPortBackup, String> {
    Ok(HostPortBackup {
        host: parse_gvariant_string(&gsettings_get(schema, "host")?),
        port: parse_gvariant_i32(&gsettings_get(schema, "port")?),
    })
}

fn write_http_slot(slot: &HttpSlotBackup) -> Result<(), String> {
    gsettings_set(SCHEMA_HTTP, "host", &format_gvariant_string(&slot.host))?;
    gsettings_set(SCHEMA_HTTP, "port", &slot.port.to_string())?;
    gsettings_set(
        SCHEMA_HTTP,
        "enabled",
        if slot.enabled { "true" } else { "false" },
    )?;
    Ok(())
}

fn write_host_port(schema: &str, slot: &HostPortBackup) -> Result<(), String> {
    gsettings_set(schema, "host", &format_gvariant_string(&slot.host))?;
    gsettings_set(schema, "port", &slot.port.to_string())?;
    Ok(())
}

/// Convert Win-style `*.example.com` to GNOME ignore-hosts `.example.com`.
fn normalize_ignore_host(host: &str) -> String {
    let t = host.trim();
    if let Some(rest) = t.strip_prefix("*.") {
        format!(".{rest}")
    } else {
        t.to_string()
    }
}

fn parse_ignore_hosts_list(raw: &str) -> Vec<String> {
    let t = raw.trim();
    let inner = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(t);
    let mut out = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let s = parse_gvariant_string(p);
        if !s.is_empty() {
            out.push(s);
        }
    }
    out
}

fn format_ignore_hosts_list(hosts: &[String]) -> String {
    let mut parts = Vec::with_capacity(hosts.len());
    for h in hosts {
        parts.push(format_gvariant_string(h));
    }
    format!("[{}]", parts.join(", "))
}

fn merge_ignore_hosts(existing_raw: &str, split_tunnel_hosts: &[String]) -> String {
    let mut hosts = parse_ignore_hosts_list(existing_raw);
    for h in split_tunnel_hosts {
        let n = normalize_ignore_host(h);
        if !n.is_empty() && !hosts.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
            hosts.push(n);
        }
    }
    for req in [
        "localhost",
        "127.0.0.0/8",
        "::1",
        "tauri.localhost",
        "steamloopback.host",
        ".steamloopback.host",
        "client-update.steamstatic.com",
        "client-update.akamai.steamstatic.com",
        "client-update.fastly.steamstatic.com",
    ] {
        if !hosts.iter().any(|x| x.eq_ignore_ascii_case(req)) {
            hosts.push(req.to_string());
        }
    }
    format_ignore_hosts_list(&hosts)
}

fn schema_exists() -> bool {
    gsettings_get(SCHEMA, "mode").is_ok()
}

pub fn read_backup() -> io::Result<ProxyBackup> {
    if !gsettings_available() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "gsettings не найден (нужен GLib/GNOME proxy stack)",
        ));
    }
    if !schema_exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "схема org.gnome.system.proxy недоступна",
        ));
    }
    let mode = parse_gvariant_string(
        &gsettings_get(SCHEMA, "mode").map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
    );
    let use_same_proxy = parse_gvariant_bool(
        &gsettings_get(SCHEMA, "use-same-proxy")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
    );
    let ignore_hosts = gsettings_get(SCHEMA, "ignore-hosts")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let http = read_http_slot().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let https = read_host_port(SCHEMA_HTTPS).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let socks = read_host_port(SCHEMA_SOCKS).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let ftp = read_host_port(SCHEMA_FTP).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(ProxyBackup {
        mode,
        use_same_proxy,
        ignore_hosts,
        http,
        https,
        socks,
        ftp,
    })
}

fn split_host_port(hp: &str) -> Result<(String, i32), String> {
    let (h, p) = hp
        .rsplit_once(':')
        .ok_or_else(|| format!("неверный host:port: {hp}"))?;
    let port: u16 = p.parse().map_err(|_| format!("неверный порт: {p}"))?;
    Ok((h.to_string(), i32::from(port)))
}

pub fn apply_proxy(
    http_host_port: &str,
    _socks_host_port: &str,
    _prior_proxy_override: Option<&str>,
    split_tunnel_hosts: &[String],
) -> Result<(), String> {
    if !gsettings_available() {
        return Err(
            "Системный прокси: не найден gsettings. Нужен GNOME/Pop/COSMIC (org.gnome.system.proxy)."
                .into(),
        );
    }
    if !schema_exists() {
        return Err(
            "Системный прокси: схема org.gnome.system.proxy недоступна на этой системе.".into(),
        );
    }

    let (host, port) = split_host_port(http_host_port)?;
    let existing_ignore = gsettings_get(SCHEMA, "ignore-hosts")
        .unwrap_or_else(|_| "['localhost', '127.0.0.0/8', '::1']".to_string());
    let merged_ignore = merge_ignore_hosts(&existing_ignore, split_tunnel_hosts);

    // Manual HTTP/HTTPS only — clear SOCKS host so it is not advertised (same as Win/macOS).
    gsettings_set(SCHEMA, "mode", "'manual'")?;
    gsettings_set(SCHEMA, "use-same-proxy", "true")?;
    gsettings_set(SCHEMA, "ignore-hosts", &merged_ignore)?;

    gsettings_set(SCHEMA_HTTP, "host", &format_gvariant_string(&host))?;
    gsettings_set(SCHEMA_HTTP, "port", &port.to_string())?;
    gsettings_set(SCHEMA_HTTP, "enabled", "true")?;

    gsettings_set(SCHEMA_HTTPS, "host", &format_gvariant_string(&host))?;
    gsettings_set(SCHEMA_HTTPS, "port", &port.to_string())?;

    gsettings_set(SCHEMA_SOCKS, "host", "''")?;
    gsettings_set(SCHEMA_SOCKS, "port", "0")?;
    gsettings_set(SCHEMA_FTP, "host", "''")?;
    gsettings_set(SCHEMA_FTP, "port", "0")?;

    Ok(())
}

pub fn restore(backup: &ProxyBackup) -> Result<(), String> {
    write_http_slot(&backup.http)?;
    write_host_port(SCHEMA_HTTPS, &backup.https)?;
    write_host_port(SCHEMA_SOCKS, &backup.socks)?;
    write_host_port(SCHEMA_FTP, &backup.ftp)?;
    gsettings_set(
        SCHEMA,
        "use-same-proxy",
        if backup.use_same_proxy {
            "true"
        } else {
            "false"
        },
    )?;
    gsettings_set(SCHEMA, "ignore-hosts", &backup.ignore_hosts)?;
    gsettings_set(SCHEMA, "mode", &format_gvariant_string(&backup.mode))?;
    Ok(())
}

/// Если снимок потерян, а manual-прокси указывает на loopback Biba — выключить.
pub fn disable_if_residual_biba_proxy() -> Result<(), String> {
    if !gsettings_available() || !schema_exists() {
        return Ok(());
    }
    let mode = parse_gvariant_string(&gsettings_get(SCHEMA, "mode")?);
    if mode != "manual" {
        return Ok(());
    }
    let http = read_http_slot()?;
    let https = read_host_port(SCHEMA_HTTPS)?;
    let is_loopback = |host: &str| {
        matches!(
            host.trim().to_ascii_lowercase().as_str(),
            "127.0.0.1" | "localhost"
        )
    };
    if is_loopback(&http.host) || is_loopback(&https.host) {
        gsettings_set(SCHEMA, "mode", "'none'")?;
        gsettings_set(SCHEMA_HTTP, "host", "''")?;
        gsettings_set(SCHEMA_HTTP, "port", "0")?;
        gsettings_set(SCHEMA_HTTP, "enabled", "false")?;
        gsettings_set(SCHEMA_HTTPS, "host", "''")?;
        gsettings_set(SCHEMA_HTTPS, "port", "0")?;
        gsettings_set(SCHEMA_SOCKS, "host", "''")?;
        gsettings_set(SCHEMA_SOCKS, "port", "0")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_star_domains() {
        assert_eq!(normalize_ignore_host("*.example.com"), ".example.com");
        assert_eq!(normalize_ignore_host("example.com"), "example.com");
    }

    #[test]
    fn merge_adds_loopback_and_split() {
        let merged = merge_ignore_hosts("['localhost']", &["*.bank.ru".into()]);
        assert!(merged.contains("localhost"));
        assert!(merged.contains(".bank.ru"));
        assert!(merged.contains("127.0.0.0/8"));
    }
}
