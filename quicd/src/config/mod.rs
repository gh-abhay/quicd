//! Server configuration module.
//!
//! This module provides a modular, composable configuration system that
//! separates global server settings from application-specific configuration.
//!
//! # Architecture
//!
//! - **Global Configuration:** Network binding, TLS, runtime settings
//! - **ALPN Routing:** Map ALPN identifiers to application configurations
//! - **Application Configs:** Polymorphic configurations for different protocols
//!
//! # Example
//!
//! ```toml
//! [server]
//! host = "0.0.0.0"
//! port = 443
//! log_level = "info"
//!
//! [[applications]]
//! alpn = "h3"
//! type = "http3"
//! [applications.config]
//! max_concurrent_streams = 100
//! enable_server_push = false
//!
//! [[applications]]
//! alpn = "my-proto"
//! type = "custom"
//! [applications.config]
//! # custom config here
//! ```

pub mod application;
pub mod global;
pub mod loader;
pub mod validation;

pub use application::ApplicationConfig;
pub use global::{GlobalConfig, RuntimeConfig};
pub use loader::load_config;
pub use validation::ConfigValidator;

use serde::{Deserialize, Serialize};

/// Master server configuration composing all subsystems.
///
/// This is the top-level configuration structure that aggregates:
/// - Global server settings (network, TLS, runtime)
/// - Application configurations mapped by ALPN
/// - Subsystem configurations (QUIC, network I/O, telemetry)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Global server configuration
    pub global: GlobalConfig,

    /// Application configurations indexed by ALPN
    ///
    /// Each application can have its own configuration schema.
    /// The server will route connections to applications based on
    /// the negotiated ALPN during the QUIC handshake.
    #[serde(rename = "applications")]
    pub apps: Vec<ApplicationConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            global: GlobalConfig::default(),
            apps: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// Validate the entire configuration.
    ///
    /// This performs comprehensive validation including:
    /// - Global settings validation
    /// - Application configuration validation
    /// - Cross-configuration consistency checks
    /// - Resource limit sanity checks
    /// - System resource pre-flight checks
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Validate global config
        if let Err(e) = self.global.validate() {
            errors.extend(e);
        }

        // Validate each application config
        for (idx, app) in self.apps.iter().enumerate() {
            if let Err(e) = app.validate() {
                for err in e {
                    errors.push(format!("Application[{}] (ALPN: {}): {}", idx, app.alpn, err));
                }
            }
        }

        // Check for duplicate ALPNs
        let mut seen_alpns = std::collections::HashSet::new();
        for app in &self.apps {
            if !seen_alpns.insert(&app.alpn) {
                errors.push(format!("Duplicate ALPN identifier: {}", app.alpn));
            }
        }

        // Ensure at least one application is configured
        if self.apps.is_empty() {
            errors.push("No applications configured. At least one application must be defined.".to_string());
        }

        // System resource pre-flight checks
        let resources = quicd_x::system_resources::SystemResources::query();
        match resources.validate_system_limits() {
            Ok(()) => {
                // System looks good
            }
            Err(warns) => {
                warnings.extend(warns);
            }
        }

        // Convert warnings to errors if they're critical
        for warning in warnings {
            if warning.contains("File descriptor limit") {
                errors.push(format!("CRITICAL: {}", warning));
            } else {
                eprintln!("WARNING: {}", warning);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Find an application configuration by ALPN identifier.
    pub fn find_app_by_alpn(&self, alpn: &str) -> Option<&ApplicationConfig> {
        self.apps.iter().find(|app| app.alpn == alpn)
    }

    /// Get the list of all supported ALPNs.
    pub fn supported_alpns(&self) -> Vec<&str> {
        self.apps.iter().map(|app| app.alpn.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::application::{ApplicationType, ApplicationTypeConfig, Http3Config};

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        // Default config will fail validation (no apps)
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_duplicate_alpn_detection() {
        let mut config = ServerConfig::default();
        config.apps = vec![
            ApplicationConfig {
                alpn: "h3".to_string(),
                app_type: ApplicationType::Http3,
                config: ApplicationTypeConfig::Http3(Http3Config::default()),
            },
            ApplicationConfig {
                alpn: "h3".to_string(),
                app_type: ApplicationType::Http3,
                config: ApplicationTypeConfig::Http3(Http3Config::default()),
            },
        ];
        
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Duplicate ALPN")));
    }
}
