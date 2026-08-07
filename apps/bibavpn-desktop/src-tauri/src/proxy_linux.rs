//! Системный прокси Linux:
//! 1) GNOME GSettings (`org.gnome.system.proxy`) — браузеры / часть GNOME-стека
//! 2) Session env (`ALL_PROXY` / `http_proxy` …) через systemd --user + dbus —
//!    для приложений, читающих env (на COSMIC libproxy+gsettings часто даёт `direct://`)
//! 3) Telegram Desktop (официальный бинарник): «Use system proxy» на Linux не работает
//!    (force-disabled upstream) — открываем `tg://socks?server=…&port=…` (явный SOCKS5)
//!
//! Split-tunnel: домены в `ignore-hosts` (+ `NO_PROXY`).

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const SCHEMA: &str = "org.gnome.system.proxy";
const SCHEMA_HTTP: &str = "org.gnome.system.proxy.http";
const SCHEMA_HTTPS: &str = "org.gnome.system.proxy.https";
const SCHEMA_SOCKS: &str = "org.gnome.system.proxy.socks";
const SCHEMA_FTP: &str = "org.gnome.system.proxy.ftp";

const PROXY_ENV_KEYS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

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

#[derive(Debug, Clone, Default)]
struct EnvBackup {
    /// Previous systemd --user environment values (None = key was unset).
    values: HashMap<String, Option<String>>,
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
    env: EnvBackup,
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

fn read_systemd_user_environment() -> HashMap<String, String> {
    let out = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let Ok(out) = out else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    let mut map = HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        map.insert(k.to_string(), v.to_string());
    }
    map
}

fn snapshot_proxy_env() -> EnvBackup {
    let current = read_systemd_user_environment();
    let mut values = HashMap::new();
    for key in PROXY_ENV_KEYS {
        values.insert((*key).to_string(), current.get(*key).cloned());
    }
    EnvBackup { values }
}

fn no_proxy_list(split_tunnel_hosts: &[String]) -> String {
    let mut hosts = vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
        "tauri.localhost".into(),
    ];
    for h in split_tunnel_hosts {
        let n = normalize_ignore_host(h);
        // NO_PROXY uses host/domain forms; strip leading dot for broader match.
        let n = n.trim_start_matches('.').to_string();
        if !n.is_empty() && !hosts.iter().any(|x: &String| x.eq_ignore_ascii_case(&n)) {
            hosts.push(n);
        }
    }
    hosts.join(",")
}

fn proxy_env_assignments(
    http_host: &str,
    http_port: i32,
    socks_host: &str,
    socks_port: i32,
    split_tunnel_hosts: &[String],
) -> Vec<(String, String)> {
    let http = format!("http://{http_host}:{http_port}");
    // Qt / Telegram read all_proxy; socks5h = DNS via proxy.
    let socks = format!("socks5h://{socks_host}:{socks_port}");
    let no_proxy = no_proxy_list(split_tunnel_hosts);
    vec![
        ("ALL_PROXY".into(), socks.clone()),
        ("all_proxy".into(), socks),
        ("HTTP_PROXY".into(), http.clone()),
        ("http_proxy".into(), http.clone()),
        ("HTTPS_PROXY".into(), http.clone()),
        ("https_proxy".into(), http),
        ("NO_PROXY".into(), no_proxy.clone()),
        ("no_proxy".into(), no_proxy),
    ]
}

fn set_systemd_user_environment(vars: &[(String, String)]) -> Result<(), String> {
    if vars.is_empty() {
        return Ok(());
    }
    let mut cmd = Command::new("systemctl");
    cmd.args(["--user", "set-environment"]);
    for (k, v) in vars {
        cmd.arg(format!("{k}={v}"));
    }
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("systemctl --user set-environment: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "systemctl --user set-environment: {}",
            err.trim()
        ));
    }
    Ok(())
}

fn unset_systemd_user_environment(keys: &[&str]) -> Result<(), String> {
    if keys.is_empty() {
        return Ok(());
    }
    let mut cmd = Command::new("systemctl");
    cmd.args(["--user", "unset-environment"]);
    cmd.args(keys);
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("systemctl --user unset-environment: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "systemctl --user unset-environment: {}",
            err.trim()
        ));
    }
    Ok(())
}

fn dbus_update_activation_environment(vars: &[(String, String)]) -> Result<(), String> {
    if vars.is_empty() {
        return Ok(());
    }
    let mut cmd = Command::new("dbus-update-activation-environment");
    cmd.arg("--systemd");
    for (k, v) in vars {
        cmd.env(k, v);
        cmd.arg(k);
    }
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("dbus-update-activation-environment: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        // Non-fatal on minimal sessions — systemd env still helps some launchers.
        return Err(format!(
            "dbus-update-activation-environment: {}",
            err.trim()
        ));
    }
    Ok(())
}

fn apply_session_env(
    http_host: &str,
    http_port: i32,
    socks_host: &str,
    socks_port: i32,
    split_tunnel_hosts: &[String],
) {
    let vars =
        proxy_env_assignments(http_host, http_port, socks_host, socks_port, split_tunnel_hosts);
    let _ = set_systemd_user_environment(&vars);
    let _ = dbus_update_activation_environment(&vars);
}

fn restore_session_env(backup: &EnvBackup) {
    let mut to_set = Vec::new();
    let mut to_unset = Vec::new();
    for key in PROXY_ENV_KEYS {
        match backup.values.get(*key) {
            Some(Some(v)) => to_set.push(((*key).to_string(), v.clone())),
            _ => to_unset.push(*key),
        }
    }
    if !to_unset.is_empty() {
        let _ = unset_systemd_user_environment(&to_unset);
    }
    if !to_set.is_empty() {
        let _ = set_systemd_user_environment(&to_set);
        let _ = dbus_update_activation_environment(&to_set);
    } else {
        // Clear activation env keys we unset (best-effort: set empty).
        let cleared: Vec<(String, String)> = to_unset
            .iter()
            .map(|k| ((*k).to_string(), String::new()))
            .collect();
        let _ = dbus_update_activation_environment(&cleared);
    }
}

/// Official Telegram Desktop ignores «Use system proxy» on non-sandboxed Linux.
/// Explicit SOCKS5 via deep link is the supported path (user confirms in Telegram UI).
fn open_telegram_socks(host: &str, port: i32) {
    let url = format!("tg://socks?server={host}&port={port}");
    // Prefer xdg-open / gio so the desktop MimeType handler forwards %U to the running instance.
    for (bin, args) in [
        ("xdg-open", vec![url.as_str()]),
        ("gio", vec!["open", url.as_str()]),
    ] {
        let ok = Command::new(bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            notify_telegram_socks(host, port);
            return;
        }
    }
    // Fallback: launch binary with URL (may start a second process that hands off via local socket).
    if let Some(exe) = find_telegram_exe() {
        let mut cmd = Command::new(exe);
        cmd.arg(&url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
        }
        let _ = cmd.spawn();
    }
    notify_telegram_socks(host, port);
}

fn find_telegram_exe() -> Option<PathBuf> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return None;
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        if name.to_str().and_then(|s| s.parse::<i32>().ok()).is_none() {
            continue;
        }
        let Ok(comm) = fs::read_to_string(ent.path().join("comm")) else {
            continue;
        };
        let comm = comm.trim();
        if comm != "Telegram" && comm != "telegram-desktop" {
            continue;
        }
        if let Ok(exe) = fs::read_link(ent.path().join("exe")) {
            if exe.exists() {
                return Some(exe);
            }
        }
    }
    if let Ok(home) = env::var("HOME") {
        let p = PathBuf::from(home).join("opt/Telegram/Telegram");
        if p.is_file() {
            return Some(p);
        }
    }
    for candidate in ["/usr/bin/telegram-desktop", "/usr/bin/Telegram"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    which_bin("telegram-desktop").or_else(|| which_bin("Telegram"))
}

fn which_bin(name: &str) -> Option<PathBuf> {
    let out = Command::new("which")
        .arg(name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

fn notify_telegram_socks(host: &str, port: i32) {
    let body = format!(
        "В Telegram подтвердите SOCKS5 {host}:{port}\n\
         (или Settings → Advanced → Connection type → SOCKS5).\n\
         «Use system proxy» на Linux в официальном Telegram не работает."
    );
    let _ = Command::new("notify-send")
        .args([
            "--app-name=BibaVPN",
            "--urgency=normal",
            "Telegram: нужен явный SOCKS5",
            &body,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
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
        env: snapshot_proxy_env(),
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
    socks_host_port: &str,
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

    let (http_host, http_port) = split_host_port(http_host_port)?;
    let (socks_host, socks_port) = split_host_port(socks_host_port)?;
    let existing_ignore = gsettings_get(SCHEMA, "ignore-hosts")
        .unwrap_or_else(|_| "['localhost', '127.0.0.0/8', '::1']".to_string());
    let merged_ignore = merge_ignore_hosts(&existing_ignore, split_tunnel_hosts);

    gsettings_set(SCHEMA, "mode", "'manual'")?;
    gsettings_set(SCHEMA, "use-same-proxy", "false")?;
    gsettings_set(SCHEMA, "ignore-hosts", &merged_ignore)?;

    gsettings_set(SCHEMA_HTTP, "host", &format_gvariant_string(&http_host))?;
    gsettings_set(SCHEMA_HTTP, "port", &http_port.to_string())?;
    gsettings_set(SCHEMA_HTTP, "enabled", "true")?;

    gsettings_set(SCHEMA_HTTPS, "host", &format_gvariant_string(&http_host))?;
    gsettings_set(SCHEMA_HTTPS, "port", &http_port.to_string())?;

    gsettings_set(SCHEMA_SOCKS, "host", &format_gvariant_string(&socks_host))?;
    gsettings_set(SCHEMA_SOCKS, "port", &socks_port.to_string())?;

    gsettings_set(SCHEMA_FTP, "host", "''")?;
    gsettings_set(SCHEMA_FTP, "port", "0")?;

    // COSMIC: gsettings alone is often not enough (libproxy returns direct://).
    // Env snapshot for restore is taken in read_backup() before apply.
    apply_session_env(
        &http_host,
        http_port,
        &socks_host,
        socks_port,
        split_tunnel_hosts,
    );
    // Telegram: do not rely on system proxy / env — open explicit SOCKS5 deep link.
    open_telegram_socks(&socks_host, socks_port);

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
    restore_session_env(&backup.env);
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
    let socks = read_host_port(SCHEMA_SOCKS)?;
    if is_loopback(&http.host) || is_loopback(&https.host) || is_loopback(&socks.host) {
        gsettings_set(SCHEMA, "mode", "'none'")?;
        gsettings_set(SCHEMA_HTTP, "host", "''")?;
        gsettings_set(SCHEMA_HTTP, "port", "0")?;
        gsettings_set(SCHEMA_HTTP, "enabled", "false")?;
        gsettings_set(SCHEMA_HTTPS, "host", "''")?;
        gsettings_set(SCHEMA_HTTPS, "port", "0")?;
        gsettings_set(SCHEMA_SOCKS, "host", "''")?;
        gsettings_set(SCHEMA_SOCKS, "port", "0")?;
        let _ = unset_systemd_user_environment(PROXY_ENV_KEYS);
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

    #[test]
    fn proxy_env_contains_socks_and_http() {
        let v = proxy_env_assignments("127.0.0.1", 8080, "127.0.0.1", 1080, &[]);
        let map: HashMap<_, _> = v.into_iter().collect();
        assert_eq!(map.get("all_proxy").unwrap(), "socks5h://127.0.0.1:1080");
        assert_eq!(map.get("https_proxy").unwrap(), "http://127.0.0.1:8080");
        assert!(map.get("no_proxy").unwrap().contains("localhost"));
    }
}
