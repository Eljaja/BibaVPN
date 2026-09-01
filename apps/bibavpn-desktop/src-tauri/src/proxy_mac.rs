//! Системный прокси macOS через `networksetup` (как в «Системные настройки → Сеть → Прокси»).

use std::io;
use std::process::{Command, Stdio};

const NETSETUP: &str = "/usr/sbin/networksetup";
/// Столько сетевых сервисов максимум трогаем (остальные — мосты, VPN, Thunderbolt и т.д.).
const MAX_PROXY_SERVICES: usize = 8;

/// `networksetup` can wedge indefinitely (right after wake, while the network
/// service is in flux). It is called dozens of times per connect/disconnect, so a
/// single stuck invocation would block the caller forever — bound it.
const NETSETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn run_netsetup(args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(NETSETUP)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("networksetup: {e}"))?;
    let deadline = std::time::Instant::now() + NETSETUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{} {:?}: не ответил за {} с (зависание системной утилиты)",
                        NETSETUP,
                        args,
                        NETSETUP_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(format!("networksetup: {e}")),
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("networksetup: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let msg = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(format!("{} {:?}: {}", NETSETUP, args, msg));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn list_services() -> Result<Vec<String>, String> {
    let out = run_netsetup(&["-listallnetworkservices"])?;
    let mut v = Vec::new();
    for line in out.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = line
            .strip_prefix('*')
            .map(|s| s.trim_start())
            .unwrap_or(line);
        if !name.is_empty() {
            v.push(name.to_string());
        }
    }
    Ok(v)
}

fn filter_proxy_services(services: Vec<String>) -> Vec<String> {
    fn denied(lower: &str) -> bool {
        if lower.contains("vpn") {
            return true;
        }
        const DENY: &[&str] = &[
            "bridge",
            "thunderbolt",
            "virtual",
            "iphone usb",
            "iphone",
            "usb serial",
            "modem",
            "bluetooth pan",
            "wireless hotspot",
            "rndis",
            "cdc ncm",
            "huawei",
            "android",
            "clash",
            "wireguard",
            "utun",
        ];
        DENY.iter().any(|pat| lower.contains(pat))
    }

    let mut scored: Vec<(u8, String)> = services
        .into_iter()
        .filter(|s| !denied(&s.to_lowercase()))
        .map(|s| {
            let l = s.to_lowercase();
            let pri = if l.contains("wi-fi") || l.contains("wifi") {
                0u8
            } else if l.contains("ethernet") {
                1u8
            } else {
                2u8
            };
            (pri, s)
        })
        .collect();

    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    scored
        .into_iter()
        .take(MAX_PROXY_SERVICES)
        .map(|(_, s)| s)
        .collect()
}

fn services_for_proxy() -> Result<Vec<String>, String> {
    let all = list_services()?;
    if all.is_empty() {
        return Err("networksetup: нет сетевых сервисов".into());
    }
    let mut picked = filter_proxy_services(all.clone());
    if picked.is_empty() {
        picked = all.into_iter().take(MAX_PROXY_SERVICES).collect();
    }
    if picked.is_empty() {
        return Err("networksetup: нет подходящих сетевых сервисов".into());
    }
    Ok(picked)
}

#[derive(Debug, Clone)]
struct ProxySlot {
    enabled: bool,
    server: String,
    port: u16,
}

#[derive(Debug, Clone)]
struct ServiceProxyBackup {
    service: String,
    web: ProxySlot,
    secure: ProxySlot,
    socks: ProxySlot,
    /// Список обхода прокси до подключения BibaVPN (`networksetup -getproxybypassdomains`).
    bypass_domains: Vec<String>,
}

/// Снимок настроек прокси только по тем сервисам, которые мы реально меняем.
#[derive(Debug, Clone)]
pub struct ProxyBackup {
    services: Vec<ServiceProxyBackup>,
}

fn parse_proxy_state(get_cmd: &str, service: &str) -> ProxySlot {
    let out = match run_netsetup(&[get_cmd, service]) {
        Ok(o) => o,
        Err(_) => {
            return ProxySlot {
                enabled: false,
                server: String::new(),
                port: 0,
            };
        }
    };
    let mut enabled = false;
    let mut server = String::new();
    let mut port = 0u16;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Enabled:") {
            enabled = rest.trim().eq_ignore_ascii_case("Yes");
        } else if let Some(rest) = line.strip_prefix("Server:") {
            server = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Port:") {
            if let Ok(p) = rest.trim().parse::<u16>() {
                port = p;
            }
        }
    }
    ProxySlot {
        enabled,
        server,
        port,
    }
}

fn get_proxy_bypass_domains(service: &str) -> Vec<String> {
    let out = match run_netsetup(&["-getproxybypassdomains", service]) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let lower = out.to_lowercase();
    if lower.contains("there aren't any bypass")
        || lower.contains("there are not any bypass")
        || lower.contains("no bypass domain")
    {
        return Vec::new();
    }
    let mut v = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let tl = t.to_lowercase();
        if tl.starts_with("bypassed domain") || tl == "enabled: yes" || tl == "enabled: no" {
            continue;
        }
        v.push(t.to_string());
    }
    v
}

fn merge_bypass_for_apply(saved: &[String], split_tunnel: &[String]) -> Vec<String> {
    let mut v: Vec<String> = saved.to_vec();
    for s in split_tunnel {
        let t = s.trim();
        if !t.is_empty() && !v.iter().any(|x| x.eq_ignore_ascii_case(t)) {
            v.push(t.to_string());
        }
    }
    for req in [
        "127.0.0.1",
        "localhost",
        "*.local",
        "tauri.localhost",
        "steamloopback.host",
        "*.steamloopback.host",
        "client-update.steamstatic.com",
        "client-update.akamai.steamstatic.com",
        "client-update.fastly.steamstatic.com",
    ] {
        if !v.iter().any(|x| x.eq_ignore_ascii_case(req)) {
            v.push(req.to_string());
        }
    }
    if v.is_empty() {
        v.extend(
            ["127.0.0.1", "localhost", "*.local"]
                .iter()
                .map(|s| (*s).to_string()),
        );
    }
    v
}

fn set_proxy_bypass_domains(service: &str, domains: &[String]) -> Result<(), String> {
    let mut argv: Vec<&str> = vec!["-setproxybypassdomains", service];
    let owned: Vec<String> = domains.to_vec();
    for d in &owned {
        argv.push(d.as_str());
    }
    run_netsetup(&argv)?;
    Ok(())
}

pub fn read_backup() -> io::Result<ProxyBackup> {
    let services = services_for_proxy().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut backups = Vec::with_capacity(services.len());
    for service in services {
        let bypass_domains = get_proxy_bypass_domains(&service);
        backups.push(ServiceProxyBackup {
            web: parse_proxy_state("-getwebproxy", &service),
            secure: parse_proxy_state("-getsecurewebproxy", &service),
            socks: parse_proxy_state("-getsocksfirewallproxy", &service),
            bypass_domains,
            service,
        });
    }
    Ok(ProxyBackup { services: backups })
}

fn split_host_port(hp: &str) -> Result<(String, String), String> {
    let (h, p) = hp
        .rsplit_once(':')
        .ok_or_else(|| format!("неверный host:port: {hp}"))?;
    let _: u16 = p.parse().map_err(|_| format!("неверный порт: {p}"))?;
    Ok((h.to_string(), p.to_string()))
}

pub fn apply_proxy(
    http_host_port: &str,
    _socks_host_port: &str,
    _prior_proxy_override: Option<&str>,
    split_tunnel_hosts: &[String],
    backup: &ProxyBackup,
) -> Result<(), String> {
    let (http_host, http_port) = split_host_port(http_host_port)?;
    let mut ok_any = false;
    let mut last_err = String::new();
    for sbackup in &backup.services {
        match apply_to_service(
            &sbackup.service,
            &http_host,
            &http_port,
            split_tunnel_hosts,
            &sbackup.bypass_domains,
        ) {
            Ok(()) => ok_any = true,
            Err(e) => last_err = e,
        }
    }
    if ok_any {
        Ok(())
    } else if last_err.is_empty() {
        Err("не удалось применить прокси ни к одному сервису".into())
    } else {
        Err(last_err)
    }
}

fn apply_to_service(
    service: &str,
    http_host: &str,
    http_port: &str,
    split_tunnel_hosts: &[String],
    saved_bypass: &[String],
) -> Result<(), String> {
    run_netsetup(&["-setwebproxy", service, http_host, http_port])?;
    run_netsetup(&["-setwebproxystate", service, "on"])?;
    run_netsetup(&["-setsecurewebproxy", service, http_host, http_port])?;
    run_netsetup(&["-setsecurewebproxystate", service, "on"])?;
    // Do not advertise SOCKS at the OS level: some clients fall back to SOCKS4-style behavior,
    // while the local BibaVPN listener only speaks SOCKS5.
    run_netsetup(&["-setsocksfirewallproxystate", service, "off"])?;
    let merged = merge_bypass_for_apply(saved_bypass, split_tunnel_hosts);
    set_proxy_bypass_domains(service, &merged)?;
    Ok(())
}

pub fn restore(backup: &ProxyBackup) -> Result<(), String> {
    let mut errs = Vec::new();
    for s in &backup.services {
        if let Err(e) = restore_service(s) {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// Отключить loopback-прокси BibaVPN на управляемых сервисах, если снимок настроек потерян.
pub fn disable_biba_proxies_on_services() -> Result<(), String> {
    let services = services_for_proxy()?;
    let mut errs = Vec::new();
    for service in services {
        let web = parse_proxy_state("-getwebproxy", &service);
        let secure = parse_proxy_state("-getsecurewebproxy", &service);
        let loopback = |slot: &ProxySlot| {
            slot.enabled
                && matches!(
                    slot.server.trim().to_ascii_lowercase().as_str(),
                    "127.0.0.1" | "localhost"
                )
        };
        if loopback(&web) {
            if let Err(e) = run_netsetup(&["-setwebproxystate", &service, "off"]) {
                errs.push(e);
            }
        }
        if loopback(&secure) {
            if let Err(e) = run_netsetup(&["-setsecurewebproxystate", &service, "off"]) {
                errs.push(e);
            }
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

fn restore_service(s: &ServiceProxyBackup) -> Result<(), String> {
    let service = s.service.as_str();
    restore_slot("-setwebproxy", "-setwebproxystate", service, &s.web)?;
    restore_slot(
        "-setsecurewebproxy",
        "-setsecurewebproxystate",
        service,
        &s.secure,
    )?;
    restore_slot(
        "-setsocksfirewallproxy",
        "-setsocksfirewallproxystate",
        service,
        &s.socks,
    )?;
    if !s.bypass_domains.is_empty() {
        set_proxy_bypass_domains(service, &s.bypass_domains)?;
    } else {
        let _ = run_netsetup(&["-setproxybypassdomains", service, "127.0.0.1", "localhost", "*.local"]);
    }
    Ok(())
}

fn restore_slot(
    set_cmd: &str,
    state_cmd: &str,
    service: &str,
    slot: &ProxySlot,
) -> Result<(), String> {
    if slot.enabled && !slot.server.is_empty() {
        let port_str = slot.port.to_string();
        run_netsetup(&[set_cmd, service, &slot.server, &port_str])?;
        run_netsetup(&[state_cmd, service, "on"])?;
    } else {
        run_netsetup(&[state_cmd, service, "off"])?;
    }
    Ok(())
}
