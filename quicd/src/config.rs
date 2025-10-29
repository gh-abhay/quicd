use clap::{CommandFactory, FromArgMatches, Parser};
use config::Config as ConfigLoader;
use serde::{Deserialize, Serialize};

use crate::netio::NetIoConfig;
use crate::telemetry::TelemetryConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeConfig {
    /// Number of worker threads for the Tokio runtime
    pub worker_threads: usize,
    /// Maximum number of blocking threads
    pub max_blocking_threads: usize,
    /// Thread name prefix
    pub thread_name: String,
    /// Thread stack size in bytes
    pub thread_stack_size: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            max_blocking_threads: 512,
            thread_name: "quicd-worker".to_string(),
            thread_stack_size: 2 * 1024 * 1024, // 2MB
        }
    }
}

#[derive(Parser, Debug, Clone, Deserialize, Serialize)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind to
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Path to config file
    #[arg(long, default_value = "config.toml")]
    #[serde(skip)]
    pub config_file: String,

    /// Runtime configuration
    #[clap(skip)]
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Network I/O configuration
    #[clap(skip)]
    #[serde(default)]
    pub netio: NetIoConfig,

    /// Telemetry configuration
    #[clap(skip)]
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

pub fn load_config() -> anyhow::Result<Config> {
    let matches = Config::command().get_matches();
    let cli = Config::from_arg_matches(&matches)?;

    let default_config = Config {
        host: "127.0.0.1".to_string(),
        port: 8080,
        log_level: "info".to_string(),
        config_file: cli.config_file.clone(),
        runtime: RuntimeConfig::default(),
        netio: NetIoConfig::default(),
        telemetry: TelemetryConfig::default(),
    };

    // Load config from file and env
    let config_result = ConfigLoader::builder()
        .add_source(config::File::with_name(&cli.config_file).required(false))
        .add_source(config::Environment::with_prefix("QUICD"))
        .build()?
        .try_deserialize::<Config>();

    let mut settings = config_result.unwrap_or(default_config);

    // Set config_file from CLI
    settings.config_file = cli.config_file.clone();

    // Override with CLI provided values
    use clap::parser::ValueSource;
    if matches.value_source("host") == Some(ValueSource::CommandLine) {
        settings.host = cli.host;
    }
    if matches.value_source("port") == Some(ValueSource::CommandLine) {
        settings.port = cli.port;
    }
    if matches.value_source("log_level") == Some(ValueSource::CommandLine) {
        settings.log_level = cli.log_level;
    }

    Ok(settings)
}