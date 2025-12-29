//! Configuration loading and parsing.
//!
//! This module handles loading configuration from files, environment variables,
//! and command-line arguments, with proper precedence handling.

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser};
use config::Config as ConfigLoader;
use std::path::Path;

use super::ServerConfig;

/// Command-line interface for the server.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Path to configuration file (TOML format)
    #[arg(long, short = 'c', default_value = "quicd.toml")]
    pub config: String,

    /// Host address to bind to (overrides config file)
    #[arg(long)]
    pub host: Option<String>,

    /// Port to bind to (overrides config file)
    #[arg(long)]
    pub port: Option<u16>,

    /// Log level (overrides config file)
    #[arg(long)]
    pub log_level: Option<String>,

    /// Validate configuration and exit
    #[arg(long)]
    pub validate: bool,

    /// Print default configuration and exit
    #[arg(long)]
    pub print_default_config: bool,
}

/// Load and parse server configuration.
///
/// This function implements the configuration precedence:
/// 1. Default values (lowest priority)
/// 2. Configuration file
/// 3. Environment variables (QUICD_ prefix)
/// 4. Command-line arguments (highest priority)
///
/// # Errors
///
/// Returns an error if:
/// - Configuration file cannot be parsed
/// - Validation fails
/// - Required values are missing
pub fn load_config() -> Result<ServerConfig> {
    let matches = CliArgs::command().get_matches();
    let cli =
        CliArgs::from_arg_matches(&matches).context("Failed to parse command-line arguments")?;

    // Handle special flags
    if cli.print_default_config {
        print_default_config()?;
        std::process::exit(0);
    }

    // Load base configuration
    let mut config = load_config_file(&cli.config)?;

    // Apply environment variable overrides
    apply_env_overrides(&mut config)?;

    // Apply CLI overrides
    apply_cli_overrides(&mut config, &cli);

    // Validate
    config.validate().map_err(|errors| {
        anyhow::anyhow!("Configuration validation failed:\n{}", errors.join("\n"))
    })?;

    if cli.validate {
        println!("✓ Configuration is valid");
        std::process::exit(0);
    }

    Ok(config)
}

/// Load configuration from a TOML file.
fn load_config_file(path: &str) -> Result<ServerConfig> {
    let path_obj = Path::new(path);

    // If file doesn't exist, use default config
    if !path_obj.exists() {
        tracing::warn!(
            config_path = %path,
            "Configuration file not found, using defaults"
        );
        return Ok(ServerConfig::default());
    }

    let config_str = std::fs::read_to_string(path_obj)
        .with_context(|| format!("Failed to read config file: {}", path))?;

    toml::from_str(&config_str).with_context(|| format!("Failed to parse TOML config: {}", path))
}

/// Apply environment variable overrides.
///
/// Environment variables are prefixed with `QUICD_` and use `__` as a separator.
///
/// Examples:
/// - `QUICD_GLOBAL__NETWORK__HOST=0.0.0.0`
/// - `QUICD_GLOBAL__LOGGING__LEVEL=debug`
fn apply_env_overrides(config: &mut ServerConfig) -> Result<()> {
    // Use config crate to handle env vars
    let env_config = ConfigLoader::builder()
        .add_source(config::Environment::with_prefix("QUICD").separator("__"))
        .build()
        .context("Failed to load environment variables")?;

    // Manually apply known overrides to avoid full deserialization
    if let Ok(host) = env_config.get_string("global.network.host") {
        config.global.network.host = host;
    }
    if let Ok(port) = env_config.get_int("global.network.port") {
        config.global.network.port = port as u16;
    }
    if let Ok(level) = env_config.get_string("global.logging.level") {
        if let Ok(parsed_level) = level.parse() {
            config.global.logging.level = parsed_level;
        }
    }

    Ok(())
}

/// Apply command-line argument overrides.
fn apply_cli_overrides(config: &mut ServerConfig, cli: &CliArgs) {
    if let Some(ref host) = cli.host {
        config.global.network.host = host.clone();
    }

    if let Some(port) = cli.port {
        config.global.network.port = port;
    }

    if let Some(ref level_str) = cli.log_level {
        if let Ok(level) = level_str.parse() {
            config.global.logging.level = level;
        } else {
            tracing::warn!(level = %level_str, "Invalid log level specified, ignoring");
        }
    }
}

/// Print the default configuration in TOML format.
fn print_default_config() -> Result<()> {
    let default_config = ServerConfig::default();
    let toml_str =
        toml::to_string_pretty(&default_config).context("Failed to serialize default config")?;
    println!("{}", toml_str);
    Ok(())
}
