//! Заглушка для платформ без автоматического переключения системного прокси.

#[derive(Debug, Clone)]
pub struct ProxyBackup;

pub fn read_backup() -> std::io::Result<ProxyBackup> {
    Ok(ProxyBackup)
}

pub fn apply_proxy(_http_host_port: &str, _socks_host_port: &str) -> Result<(), String> {
    Err("Системный прокси для этого приложения поддерживается только в сборках Windows и macOS.".into())
}

pub fn restore(_backup: &ProxyBackup) -> Result<(), String> {
    Ok(())
}
