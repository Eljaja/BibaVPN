//! Shared tracing subscriber setup for server and client binaries.

use std::str::FromStr;

use anyhow::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Registry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    #[default]
    Plain,
    Json,
}

impl FromStr for LogFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "plain" | "text" => Ok(LogFormat::Plain),
            "json" => Ok(LogFormat::Json),
            other => anyhow::bail!("unknown log format {other:?}: use plain or json"),
        }
    }
}

/// When `filter` is set it wins over `level` and replaces `RUST_LOG`-style discovery for the default directive.
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: String,
    pub format: LogFormat,
    pub filter: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Plain,
            filter: None,
        }
    }
}

pub fn init(config: LogConfig) -> anyhow::Result<()> {
    let filter = |cfg: &LogConfig| -> EnvFilter {
        let f = cfg.filter.clone().filter(|s| !s.trim().is_empty());
        if let Some(f) = f {
            EnvFilter::new(f)
        } else {
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(cfg.level.trim()))
        }
    };

    match config.format {
        LogFormat::Plain => {
            let subscriber = Registry::default()
                .with(filter(&config))
                .with(fmt::layer().with_target(true));
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        LogFormat::Json => {
            let subscriber = Registry::default()
                .with(filter(&config))
                .with(fmt::layer().json().with_target(true));
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
    }
    Ok(())
}

/// Parse `--log-level` case-insensitively into a default `EnvFilter` directive.
pub fn level_directive(level: &str) -> anyhow::Result<String> {
    let l = level.trim().to_ascii_lowercase();
    match l.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => Ok::<_, anyhow::Error>(l),
        "" => Ok("info".to_string()),
        other => anyhow::bail!("unknown log level {other:?}"),
    }
    .context("log-level")
}
