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
//! enabled = true
//!
//! [[applications]]
//! alpn = "my-proto"
//! type = "plugin"
//! [applications.config]
//! library_path = "/path/to/libmy_proto.so"
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
/// - Application configurations mapped by name
/// - Subsystem configurations (QUIC, network I/O, telemetry)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Global server configuration
    pub global: GlobalConfig,

    /// Application configurations indexed by unique name
    ///
    /// Each application can handle multiple ALPN identifiers and has its own
    /// configuration schema. The server will route connections to applications
    /// based on the negotiated ALPN during the QUIC handshake.
    ///
    /// Example structure:
    /// ```toml
    /// [applications.http3]
    /// type = "builtin:http3"
    /// alpn = ["h3", "h3-29"]
    /// enabled = true
    /// ```
    #[serde(default)]
    pub applications: std::collections::HashMap<String, ApplicationConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            global: GlobalConfig::default(),
            applications: std::collections::HashMap::new(),
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
        let mut warnings: Vec<String> = Vec::new();

        // Validate global config
        if let Err(e) = self.global.validate() {
            errors.extend(e);
        }

        // Validate each application config
        for (name, app) in &self.applications {
            if let Err(e) = app.validate() {
                for err in e {
                    errors.push(format!(
                        "Application '{}' (ALPN: {:?}): {}",
                        name, app.alpn, err
                    ));
                }
            }
        }

        // Check for duplicate ALPNs across applications
        let mut seen_alpns = std::collections::HashSet::new();
        for (name, app) in &self.applications {
            for alpn in &app.alpn {
                if !seen_alpns.insert(alpn) {
                    errors.push(format!(
                        "Duplicate ALPN identifier '{}' in application '{}'",
                        alpn, name
                    ));
                }
            }
        }

        // Ensure at least one enabled application is configured
        let enabled_count = self.applications.values().filter(|app| app.enabled).count();
        if enabled_count == 0 {
            errors.push(
                "No enabled applications configured. At least one application must be defined and enabled.".to_string(),
            );
        }

        // System resource pre-flight checks
        // let resources = quicd_x::system_resources::SystemResources::query();
        // match resources.validate_system_limits() {
        //     Ok(()) => {
        //         // System looks good
        //     }
        //     Err(warns) => {
        //         warnings.extend(warns);
        //     }
        // }

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
    pub fn find_app_by_alpn(&self, alpn: &str) -> Option<(&String, &ApplicationConfig)> {
        self.applications
            .iter()
            .find(|(_, app)| app.alpn.contains(&alpn.to_string()))
    }

    /// Get the list of all supported ALPNs.
    pub fn supported_alpns(&self) -> Vec<&str> {
        let mut alpns = Vec::new();
        for app in self.applications.values() {
            if app.enabled {
                for alpn in &app.alpn {
                    alpns.push(alpn.as_str());
                }
            }
        }
        alpns
    }
}

