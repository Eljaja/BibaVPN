//! Android: системный прокси не трогаем (трафик через VpnService).

#[derive(Debug, Clone)]
pub struct ProxyBackup;

pub fn read_backup() -> std::io::Result<ProxyBackup> {
    Ok(ProxyBackup)
}

pub fn apply_proxy(
    _http_host_port: &str,
    _socks_host_port: &str,
    _prior_proxy_override: Option<&str>,
    _split_tunnel_hosts: &[String],
) -> Result<(), String> {
    Ok(())
}

pub fn restore(_backup: &ProxyBackup) -> Result<(), String> {
    Ok(())
}
