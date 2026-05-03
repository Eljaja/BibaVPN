//! Файловые логи в `%LOCALAPPDATA%\\BibaVPN\\logs\\` + дублирование в stderr (если есть консоль).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Подавляем шум UI-стека; bibavpn / bibavpn_desktop / bibavpn_client остаются на info.
        EnvFilter::new("info,tauri=warn,wry=warn,tao=warn")
    })
}

fn try_init_stderr_only(filter: EnvFilter) {
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .with_target(true)
        .try_init();
}

/// Каталог с ротированными `bibavpn-desktop.log.*` (после успешного [`init`]).
pub fn logs_directory() -> Option<&'static Path> {
    LOG_DIR.get().map(|p| p.as_path())
}

/// Открыть путь в проводнике / Finder / файловом менеджере.
pub fn open_in_file_manager(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer.exe").arg(path).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

/// Включает `tracing`: ежедневная ротация `bibavpn-desktop.log.YYYY-MM-DD` в `…\BibaVPN\logs\`.
/// Повторный вызов безопасен (игнорируется, если subscriber уже стоит).
pub fn init() -> Option<PathBuf> {
    let filter = env_filter();

    let Some(base) = dirs::data_local_dir() else {
        try_init_stderr_only(filter);
        return None;
    };
    let log_dir = base.join("BibaVPN").join("logs");
    if std::fs::create_dir_all(&log_dir).is_err() {
        try_init_stderr_only(filter);
        return None;
    }
    let _ = LOG_DIR.set(log_dir.clone());

    let file_appender = tracing_appender::rolling::RollingFileAppender::new(
        tracing_appender::rolling::Rotation::DAILY,
        &log_dir,
        "bibavpn-desktop",
    );
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    std::mem::forget(guard);

    let file_layer = fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .with_target(true);

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .with_target(true);

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stderr_layer);

    if subscriber.try_init().is_err() {
        return Some(log_dir);
    }

    tracing::info!(
        target: "bibavpn_desktop",
        dir = %log_dir.display(),
        "логи: ежедневные файлы bibavpn-desktop.log.* (RUST_LOG переопределяет уровни; шум tauri/wry по умолчанию warn)"
    );
    Some(log_dir)
}
