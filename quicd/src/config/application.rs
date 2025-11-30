//! Application configuration and ALPN routing.
//!
//! This module defines the polymorphic configuration system for different
//! application protocols (HTTP/3, custom protocols, etc.).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Application-specific configuration.
///
/// Each application is identified by its ALPN string and has a type-specific
/// configuration schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfig {
    /// ALPN identifier for this application.
    ///
    /// This string is used during QUIC handshake to negotiate which
    /// application protocol to use.
    ///
    /// Examples: `"h3"`, `"h3-29"`, `"doq"`, `"my-custom-proto"`
    pub alpn: String,

    /// Application type (determines config schema).
    #[serde(rename = "type")]
    pub app_type: ApplicationType,

    /// Type-specific configuration.
    ///
    /// The structure of this field depends on `app_type`:
    /// - `Http3` → HTTP/3 configuration
    /// - `Custom` → Generic key-value configuration
    #[serde(flatten)]
    pub config: ApplicationTypeConfig,
}

impl ApplicationConfig {
    /// Validate application configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate ALPN string
        if self.alpn.is_empty() {
            errors.push("ALPN identifier cannot be empty".to_string());
        }

        if self.alpn.len() > 255 {
            errors.push("ALPN identifier too long (max 255 bytes)".to_string());
        }

        // Validate type-specific config
        if let Err(e) = self.config.validate(&self.app_type) {
            errors.extend(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Application type enumeration.
///
/// Determines which configuration schema is used for an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    /// HTTP/3 protocol (RFC 9114)
    Http3,

    /// Custom application protocol
    ///
    /// Uses generic key-value configuration and requires a custom
    /// `QuicAppFactory` implementation.
    Custom,
}

/// Type-specific application configuration.
///
/// This enum holds the actual configuration data for each application type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApplicationTypeConfig {
    /// HTTP/3 configuration
    Http3(Http3Config),

    /// Custom application configuration
    Custom(CustomConfig),
}

impl Default for ApplicationTypeConfig {
    fn default() -> Self {
        Self::Http3(Http3Config::default())
    }
}

impl ApplicationTypeConfig {
    /// Validate configuration against the expected type.
    pub fn validate(&self, expected_type: &ApplicationType) -> Result<(), Vec<String>> {
        match (self, expected_type) {
            (ApplicationTypeConfig::Http3(cfg), ApplicationType::Http3) => {
                cfg.validate().map_err(|e| vec![e])
            }
            (ApplicationTypeConfig::Custom(_), ApplicationType::Custom) => {
                // Custom configs are opaque to the server
                Ok(())
            }
            (ApplicationTypeConfig::Http3(_), ApplicationType::Custom) => {
                Err(vec!["Type mismatch: expected Custom config but got Http3".to_string()])
            }
            (ApplicationTypeConfig::Custom(_), ApplicationType::Http3) => {
                Err(vec!["Type mismatch: expected Http3 config but got Custom".to_string()])
            }
        }
    }

    /// Try to extract HTTP/3 configuration.
    pub fn as_http3(&self) -> Option<&Http3Config> {
        match self {
            ApplicationTypeConfig::Http3(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Try to extract custom configuration.
    pub fn as_custom(&self) -> Option<&CustomConfig> {
        match self {
            ApplicationTypeConfig::Custom(cfg) => Some(cfg),
            _ => None,
        }
    }
}

/// HTTP/3 application configuration.
///
/// This wraps the `quicd-h3` configuration and adds server-specific settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Http3Config {
    /// Core HTTP/3 protocol configuration
    #[serde(flatten)]
    pub h3: quicd_h3::H3Config,

    /// Enable HTTP/3 server
    ///
    /// If false, HTTP/3 requests will be rejected even if ALPN is negotiated.
    ///
    /// **Default:** `true`
    pub enabled: bool,

    /// Custom request handler configuration
    ///
    /// Additional settings specific to the request handler implementation.
    pub handler: Option<HashMap<String, serde_json::Value>>,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            h3: quicd_h3::H3Config::default(),
            enabled: true,
            handler: None,
        }
    }
}

impl Http3Config {
    pub fn validate(&self) -> Result<(), String> {
        self.h3.validate()
    }
}

/// Custom application configuration.
///
/// Opaque key-value configuration for custom application protocols.
/// The server does not validate this; it's passed directly to the
/// application's `QuicAppFactory`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomConfig {
    /// Arbitrary configuration parameters
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_http3_app() {
        let app = ApplicationConfig {
            alpn: "h3".to_string(),
            app_type: ApplicationType::Http3,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert!(app.validate().is_ok());
    }

    #[test]
    fn test_empty_alpn_invalid() {
        let app = ApplicationConfig {
            alpn: String::new(),
            app_type: ApplicationType::Http3,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert!(app.validate().is_err());
    }

    #[test]
    fn test_type_mismatch() {
        let config = ApplicationTypeConfig::Http3(Http3Config::default());
        assert!(config.validate(&ApplicationType::Custom).is_err());
    }
}
