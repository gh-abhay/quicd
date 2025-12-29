//! Global server configuration.
//!
//! This module defines configuration settings that apply server-wide,
//! including network binding, TLS/crypto settings, runtime configuration,
//! and logging.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Global server configuration.
///
/// Contains all settings that apply to the entire server instance,
/// independent of any specific application protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    /// Network binding configuration
    pub network: NetworkConfig,

    /// TLS/cryptographic configuration
    pub tls: TlsConfig,

    /// Runtime (thread pool, async executor) configuration
    pub runtime: RuntimeConfig,

    /// Logging and observability configuration
    pub logging: LoggingConfig,

    // QUIC transport configuration removed
    // pub quic: quicd_x::QuicTransportConfig,
    /// Network I/O configuration
    pub netio: crate::netio::NetIoConfig,

    /// Channel capacity configuration
    pub channels: crate::channel_config::ChannelConfig,

    /// Telemetry configuration
    pub telemetry: crate::telemetry::TelemetryConfig,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            tls: TlsConfig::default(),
            runtime: RuntimeConfig::default(),
            logging: LoggingConfig::default(),
            // quic: quicd_x::QuicTransportConfig::default(),
            netio: crate::netio::NetIoConfig::default(),
            channels: crate::channel_config::ChannelConfig::default(),
            telemetry: crate::telemetry::TelemetryConfig::default(),
        }
    }
}

impl GlobalConfig {
    /// Validate global configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate network config
        if let Err(e) = self.network.validate() {
            errors.extend(e);
        }

        // Validate TLS config
        if let Err(e) = self.tls.validate() {
            errors.extend(e);
        }

        // Validate runtime config
        if let Err(e) = self.runtime.validate() {
            errors.extend(e);
        }

        // Validate QUIC config
        // if let Err(e) = self.quic.validate() {
        //     errors.push(e);
        // }

        // Validate channel config
        if let Err(e) = self.channels.validate() {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Network binding configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Host address to bind to.
    ///
    /// Examples:
    /// - `"0.0.0.0"` - Bind to all IPv4 interfaces
    /// - `"::"` - Bind to all IPv6 interfaces
    /// - `"127.0.0.1"` - Localhost only (testing)
    ///
    /// **Default:** `"0.0.0.0"`
    pub host: String,

    /// UDP port to bind to.
    ///
    /// Standard ports:
    /// - `443` - HTTPS/QUIC (requires root/capabilities)
    /// - `8443` - Common alternative for QUIC
    ///
    /// **Default:** `443`
    pub port: u16,

    /// Enable SO_REUSEADDR socket option.
    ///
    /// Allows binding to a port that was recently closed.
    /// Useful for development and quick restarts.
    ///
    /// **Default:** `true`
    pub reuse_addr: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 443,
            reuse_addr: true,
        }
    }
}

impl NetworkConfig {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate host can be parsed as an IP address
        if self.host.parse::<std::net::IpAddr>().is_err() {
            errors.push(format!("Invalid host address: {}", self.host));
        }

        // Port 0 is valid (OS assigns random port) but warn
        if self.port == 0 {
            eprintln!("Warning: port=0 will bind to a random port assigned by the OS");
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// TLS and cryptographic configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Path to TLS certificate file (.crt file with PEM encoding).
    ///
    /// REQUIRED: Server certificates must be provided.
    /// Self-signed certificates are not supported.
    pub cert_path: Option<PathBuf>,

    /// Path to TLS private key file (.key file with PEM encoding).
    ///
    /// Must be provided if `cert_path` is specified.
    pub key_path: Option<PathBuf>,

    /// Enable TLS 1.3 early data (0-RTT).
    ///
    /// **Security Warning:** 0-RTT data is not forward secret and can be
    /// replayed. Only enable if your application is idempotent.
    ///
    /// **Default:** `false`
    pub enable_early_data: bool,

    /// Minimum TLS version to accept.
    ///
    /// QUIC requires TLS 1.3, so this is always `TLS1_3`.
    /// This field exists for future extensibility.
    #[serde(skip)]
    pub min_tls_version: TlsVersion,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            enable_early_data: false,
            min_tls_version: TlsVersion::Tls13,
        }
    }
}

impl TlsConfig {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Both cert and key are REQUIRED
        if self.cert_path.is_none() {
            errors.push(
                "cert_path is required - self-signed certificates are not supported".to_string(),
            );
        }

        if self.key_path.is_none() {
            errors.push(
                "key_path is required - self-signed certificates are not supported".to_string(),
            );
        }

        // Validate files exist if provided
        if let Some(cert) = &self.cert_path {
            if !cert.exists() {
                errors.push(format!("Certificate file not found: {}", cert.display()));
            }
        }

        if let Some(key) = &self.key_path {
            if !key.exists() {
                errors.push(format!("Private key file not found: {}", key.display()));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// TLS version enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls13,
}

/// Runtime configuration for the async executor and thread pools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Number of worker threads for the Tokio runtime.
    ///
    /// These threads run async application tasks.
    /// Does not include network I/O worker threads.
    ///
    /// **Default:** Number of CPU cores
    pub worker_threads: usize,

    /// Maximum number of blocking threads in the pool.
    ///
    /// Used for blocking operations that can't be made async.
    ///
    /// **Default:** 512
    pub max_blocking_threads: usize,

    /// Thread name prefix for worker threads.
    ///
    /// Useful for debugging and profiling.
    ///
    /// **Default:** `"quicd-worker"`
    pub thread_name: String,

    /// Stack size for each thread in bytes.
    ///
    /// **Default:** 2 MB
    pub thread_stack_size: usize,

    /// Enable thread-local statistics collection.
    ///
    /// **Default:** `false`
    pub enable_thread_stats: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        // let resources = quicd_x::system_resources::SystemResources::query();

        Self {
            worker_threads: num_cpus::get(), // Default to number of CPUs
            max_blocking_threads: 512,
            thread_name: "quicd-worker".to_string(),
            thread_stack_size: 2 * 1024 * 1024, // 2MB
            enable_thread_stats: false,
        }
    }
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.worker_threads == 0 {
            errors.push("worker_threads must be > 0".to_string());
        }

        if self.worker_threads > 1024 {
            errors.push("worker_threads is unreasonably high (> 1024)".to_string());
        }

        if self.max_blocking_threads == 0 {
            errors.push("max_blocking_threads must be > 0".to_string());
        }

        if self.thread_stack_size < 128 * 1024 {
            errors.push("thread_stack_size too small (< 128 KB)".to_string());
        }

        if self.thread_stack_size > 64 * 1024 * 1024 {
            errors.push("thread_stack_size too large (> 64 MB)".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Logging and observability configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level for the entire application.
    ///
    /// **Default:** `Info`
    pub level: LogLevel,

    /// Enable structured JSON logging.
    ///
    /// When enabled, logs are emitted in JSON format for machine parsing.
    ///
    /// **Default:** `false`
    pub json_format: bool,

    /// Enable ANSI color codes in logs.
    ///
    /// Disable when logging to files or non-TTY outputs.
    ///
    /// **Default:** `true` (auto-detected based on TTY)
    pub enable_colors: bool,

    /// Include source file and line number in logs.
    ///
    /// **Default:** `false` (performance overhead)
    pub include_file_line: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            json_format: false,
            enable_colors: true,
            include_file_line: false,
        }
    }
}

/// Log level enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("Invalid log level: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_global_config_requires_certs() {
        let config = GlobalConfig::default();
        let result = config.validate();
        // Default config should fail validation because certs are required
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("cert_path")));
        assert!(errors.iter().any(|e| e.contains("key_path")));
    }

    #[test]
    fn test_invalid_host() {
        let mut config = NetworkConfig::default();
        config.host = "not-an-ip".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tls_cert_without_key() {
        let mut config = TlsConfig::default();
        config.cert_path = Some(PathBuf::from("/tmp/cert.pem"));
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_worker_threads() {
        let mut config = RuntimeConfig::default();
        config.worker_threads = 0;
        assert!(config.validate().is_err());
    }
}
