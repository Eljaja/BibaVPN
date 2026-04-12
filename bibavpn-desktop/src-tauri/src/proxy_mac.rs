//! Системный прокси macOS через `networksetup` (как в «Системные настройки → Сеть → Прокси»).

use std::io;
use std::process::{Command, Stdio};

const NETSETUP: &str = "/usr/sbin/networksetup";
/// Столько сетевых сервисов максимум трогаем (остальные — мосты, VPN, Thunderbolt и т.д.).
const MAX_PROXY_SERVICES: usize = 8;

/// Поднять мягкий лимит дескрипторов (частая причина `Too many open files` при долгой работе + spawn).
pub fn init_process_limits() {
    use libc::{getrlimit, rlim_t, rlimit, setrlimit, RLIMIT_NOFILE, RLIM_INFINITY};

    const WANT: rlim_t = 50_000;
    unsafe {
        let mut lim: rlimit = std::mem::zeroed();
        if getrlimit(RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let hard = if lim.rlim_max == RLIM_INFINITY {
            WANT
        } else {
            lim.rlim_max
        };
        let target = WANT.min(hard).max(lim.rlim_cur);
        if target > lim.rlim_cur {
            lim.rlim_cur = target;
            let _ = setrlimit(RLIMIT_NOFILE, &lim);
        }
    }
}

fn run_netsetup(args: &[&str]) -> Result<String, String> {
    let out = Command::new(NETSETUP)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
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

pub fn read_backup() -> io::Result<ProxyBackup> {
    let services = services_for_proxy().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut backups = Vec::with_capacity(services.len());
    for service in services {
        backups.push(ServiceProxyBackup {
            web: parse_proxy_state("-getwebproxy", &service),
            secure: parse_proxy_state("-getsecurewebproxy", &service),
            socks: parse_proxy_state("-getsocksfirewallproxy", &service),
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
) -> Result<(), String> {
    let (http_host, http_port) = split_host_port(http_host_port)?;
    let services = services_for_proxy()?;
    let mut ok_any = false;
    let mut last_err = String::new();
    for service in &services {
        match apply_to_service(service, &http_host, &http_port) {
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
) -> Result<(), String> {
    run_netsetup(&["-setwebproxy", service, http_host, http_port])?;
    run_netsetup(&["-setwebproxystate", service, "on"])?;
    run_netsetup(&["-setsecurewebproxy", service, http_host, http_port])?;
    run_netsetup(&["-setsecurewebproxystate", service, "on"])?;
    // Do not advertise SOCKS at the OS level: some clients fall back to SOCKS4-style behavior,
    // while the local BibaVPN listener only speaks SOCKS5.
    run_netsetup(&["-setsocksfirewallproxystate", service, "off"])?;
    Ok(())
}

pub fn restore(backup: &ProxyBackup) -> Result<(), String> {
    let mut last = Ok(());
    for s in &backup.services {
        if let Err(e) = restore_service(s) {
            last = Err(e);
        }
    }
    last
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
