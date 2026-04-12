//! Файловые логи в `%LOCALAPPDATA%\\BibaVPN\\logs\\` + дублирование в stderr (если есть консоль).

use std::path::PathBuf;

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

fn try_init_stderr_only(filter: EnvFilter) {
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .with_target(true)
        .try_init();
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
        "логи: ежедневные файлы bibavpn-desktop.log.* в этой папке (переменная RUST_LOG задаёт уровень)"
    );
    Some(log_dir)
}
