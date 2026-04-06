//! Системный прокси macOS через `networksetup` (как в «Системные настройки → Сеть → Прокси»).

use std::io;
use std::process::Command;

const NETSETUP: &str = "/usr/sbin/networksetup";

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

/// Снимок настроек прокси по всем сервисам из `networksetup -listallnetworkservices`.
#[derive(Debug, Clone)]
pub struct ProxyBackup {
    services: Vec<ServiceProxyBackup>,
}

fn run_netsetup(args: &[&str]) -> Result<String, String> {
    let out = Command::new(NETSETUP)
        .args(args)
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
        return Err(format!(
            "{} {:?}: {}",
            NETSETUP,
            args,
            msg
        ));
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
    let services = list_services().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    if services.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "networksetup: нет сетевых сервисов",
        ));
    }
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
    let _: u16 = p
        .parse()
        .map_err(|_| format!("неверный порт: {p}"))?;
    Ok((h.to_string(), p.to_string()))
}

pub fn apply_proxy(http_host_port: &str, socks_host_port: &str) -> Result<(), String> {
    let (http_host, http_port) = split_host_port(http_host_port)?;
    let (socks_host, socks_port) = split_host_port(socks_host_port)?;
    let services = list_services()?;
    if services.is_empty() {
        return Err("networksetup: нет сетевых сервисов".into());
    }
    let mut ok_any = false;
    let mut last_err = String::new();
    for service in &services {
        match apply_to_service(
            service,
            &http_host,
            &http_port,
            &socks_host,
            &socks_port,
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
    socks_host: &str,
    socks_port: &str,
) -> Result<(), String> {
    run_netsetup(&["-setwebproxy", service, http_host, http_port])?;
    run_netsetup(&["-setwebproxystate", service, "on"])?;
    run_netsetup(&[
        "-setsecurewebproxy",
        service,
        http_host,
        http_port,
    ])?;
    run_netsetup(&["-setsecurewebproxystate", service, "on"])?;
    run_netsetup(&[
        "-setsocksfirewallproxy",
        service,
        socks_host,
        socks_port,
    ])?;
    run_netsetup(&["-setsocksfirewallproxystate", service, "on"])?;
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
