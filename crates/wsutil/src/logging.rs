//! `wslog`-equivalent surface — wraps `tracing-subscriber` with upstream's
//! `--log-level`, `--log-domain`, `--log-file`, `--log-debug`, `--log-noisy`,
//! `--log-fatal` flag semantics.

use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Noisy,
    Debug,
    Info,
    Message,
    Warning,
    Critical,
    Error,
}

impl LogLevel {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "noisy" | "trace" => LogLevel::Noisy,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "message" | "msg" => LogLevel::Message,
            "warning" | "warn" => LogLevel::Warning,
            "critical" | "crit" => LogLevel::Critical,
            "error" | "err" => LogLevel::Error,
            _ => return None,
        })
    }

    pub fn as_tracing_filter(&self) -> &'static str {
        match self {
            LogLevel::Noisy => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Message => "info",
            LogLevel::Warning => "warn",
            LogLevel::Critical => "warn",
            LogLevel::Error => "error",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct LogConfig {
    pub level: Option<LogLevel>,
    pub domains: Vec<String>,
    pub debug_domains: Vec<String>,
    pub noisy_domains: Vec<String>,
    pub fatal_level: Option<LogLevel>,
    pub file: Option<PathBuf>,
}

static INIT: OnceLock<()> = OnceLock::new();

/// Initialize the global subscriber. May only be called once per process.
pub fn init(cfg: &LogConfig) {
    INIT.get_or_init(|| {
        let level = cfg
            .level
            .map(|l| l.as_tracing_filter())
            .unwrap_or("info");
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_writer(std::io::stderr)
            .try_init();
    });
}
