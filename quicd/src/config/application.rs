//! Application configuration and ALPN routing.
//!
//! This module defines the polymorphic configuration system for different
//! application protocols (HTTP/3, custom protocols, etc.).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Application-specific configuration.
///
/// Each application is identified by a unique name and can handle multiple
/// ALPN identifiers. This allows one application to serve multiple protocol
/// versions or variants without duplication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfig {
    /// ALPN identifiers for this application.
    ///
    /// Array of strings used during QUIC handshake to negotiate which
    /// application protocol to use. One application can handle multiple ALPNs.
    ///
    /// Examples: `["h3", "h3-29"]`, `["echo"]`, `["my-proto-v1", "my-proto-v2"]`
    pub alpn: Vec<String>,

    /// Application type (determines config schema).
    ///
    /// Can be:
    /// - `"builtin:http3"` - HTTP/3 protocol (RFC 9114)
    /// - `"builtin:moq"` - Media over QUIC (if implemented)
    /// - `"plugin"` - Dynamically loaded plugin
    #[serde(rename = "type")]
    pub app_type: String,

    /// Enable this application.
    ///
    /// If false, the application won't be loaded even if configured.
    ///
    /// **Default:** `true`
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Type-specific configuration.
    ///
    /// The structure of this field depends on `app_type`:
    /// - `builtin:http3` → HTTP/3 configuration with subsections
    /// - `builtin:moq` → MOQ configuration
    /// - `plugin` → Plugin configuration with library_path
    #[serde(default)]
    pub config: ApplicationTypeConfig,
}

fn default_enabled() -> bool {
    true
}

impl ApplicationConfig {
    /// Validate application configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate ALPN strings
        if self.alpn.is_empty() {
            errors.push("At least one ALPN identifier must be specified".to_string());
        }

        for alpn in &self.alpn {
            if alpn.is_empty() {
                errors.push("ALPN identifier cannot be empty".to_string());
            }

            if alpn.len() > 255 {
                errors.push(format!("ALPN identifier '{}' too long (max 255 bytes)", alpn));
            }
        }

        // Validate app_type
        if self.app_type.is_empty() {
            errors.push("Application type cannot be empty".to_string());
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

    /// Parse application type into category
    pub fn parse_type(&self) -> Result<ApplicationType, String> {
        if self.app_type.starts_with("builtin:") {
            let builtin_name = &self.app_type[8..];
            match builtin_name {
                "http3" => Ok(ApplicationType::Http3),
                "hq-interop" => Ok(ApplicationType::HqInterop),
                "moq" => Ok(ApplicationType::Moq),
                _ => Err(format!("Unknown builtin application type: {}", builtin_name)),
            }
        } else if self.app_type == "plugin" {
            Ok(ApplicationType::Plugin)
        } else {
            Err(format!("Invalid application type format: {}. Expected 'builtin:<name>' or 'plugin'", self.app_type))
        }
    }
}

/// Application type enumeration.
/// Determines which configuration schema is used for an application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    /// HTTP/3 protocol (RFC 9114)
    Http3,

    /// HTTP/0.9 over QUIC (hq-interop)
    HqInterop,

    /// Media over QUIC
    Moq,

    /// Dynamically loaded plugin
    ///
    /// Loads an application factory from a shared library (.so/.dylib/.dll).
    Plugin,
}

/// Type-specific application configuration.
///
/// This enum holds the actual configuration data for each application type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApplicationTypeConfig {
    /// HQ-Interop configuration (must come before Http3 for proper deserialization)
    HqInterop(HqInteropConfig),

    /// HTTP/3 configuration
    Http3(Http3Config),

    /// MOQ configuration
    Moq(MoqConfig),

    /// Plugin configuration
    Plugin(PluginConfig),

    /// Unknown/empty configuration
    Empty(HashMap<String, serde_json::Value>),
}

impl Default for ApplicationTypeConfig {
    fn default() -> Self {
        Self::Http3(Http3Config::default())
    }
}

impl ApplicationTypeConfig {
    /// Validate configuration against the expected type string.
    pub fn validate(&self, type_str: &str) -> Result<(), Vec<String>> {
        match self {
            ApplicationTypeConfig::Http3(cfg) => {
                if type_str == "builtin:http3" {
                    cfg.validate().map_err(|e| vec![e])
                } else {
                    Err(vec![format!("Type mismatch: expected '{}' but got Http3 config", type_str)])
                }
            }
            ApplicationTypeConfig::HqInterop(cfg) => {
                if type_str == "builtin:hq-interop" {
                    cfg.validate().map_err(|e| vec![e])
                } else {
                    Err(vec![format!("Type mismatch: expected '{}' but got HqInterop config", type_str)])
                }
            }
            ApplicationTypeConfig::Moq(cfg) => {
                if type_str == "builtin:moq" {
                    cfg.validate().map_err(|e| vec![e])
                } else {
                    Err(vec![format!("Type mismatch: expected '{}' but got MOQ config", type_str)])
                }
            }
            ApplicationTypeConfig::Plugin(cfg) => {
                if type_str == "plugin" {
                    cfg.validate().map_err(|e| vec![e])
                } else {
                    Err(vec![format!("Type mismatch: expected 'plugin' but got Plugin config")])
                }
            }
            ApplicationTypeConfig::Empty(_) => Ok(()),
        }
    }

    /// Try to extract HTTP/3 configuration.
    #[allow(dead_code)]
    pub fn as_http3(&self) -> Option<&Http3Config> {
        match self {
            ApplicationTypeConfig::Http3(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Try to extract HqInterop configuration.
    #[allow(dead_code)]
    pub fn as_hq_interop(&self) -> Option<&HqInteropConfig> {
        match self {
            ApplicationTypeConfig::HqInterop(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Try to extract MOQ configuration.
    #[allow(dead_code)]
    pub fn as_moq(&self) -> Option<&MoqConfig> {
        match self {
            ApplicationTypeConfig::Moq(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Try to extract plugin configuration.
    #[allow(dead_code)]
    pub fn as_plugin(&self) -> Option<&PluginConfig> {
        match self {
            ApplicationTypeConfig::Plugin(cfg) => Some(cfg),
            _ => None,
        }
    }
}

/// QPACK Configuration (RFC 9204)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QpackConfig {
    /// Maximum dynamic table capacity in bytes
    ///
    /// **Default:** `4096`
    pub max_table_capacity: usize,

    /// Maximum number of blocked streams waiting for QPACK updates
    ///
    /// **Default:** `100`
    pub blocked_streams: usize,
}

impl Default for QpackConfig {
    fn default() -> Self {
        Self {
            max_table_capacity: 4096,
            blocked_streams: 100,
        }
    }
}

/// Server Push Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PushConfig {
    /// Enable HTTP/3 server push
    ///
    /// **Default:** `false`
    pub enabled: bool,

    /// Maximum concurrent push streams
    ///
    /// **Default:** `100`
    pub max_concurrent: usize,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent: 100,
        }
    }
}

/// HTTP Handler Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HandlerConfig {
    /// Enable file serving
    ///
    /// **Default:** `true`
    pub file_serving_enabled: bool,

    /// File serving root directory
    ///
    /// **Default:** `"./www"`
    pub file_root: String,

    /// Enable directory listing (security consideration)
    ///
    /// **Default:** `false`
    pub directory_listing: bool,

    /// Enable compression (gzip, brotli)
    ///
    /// **Default:** `true`
    pub compression_enabled: bool,

    /// Compression algorithms to use
    ///
    /// **Default:** `["gzip", "br"]`
    pub compression_algorithms: Vec<String>,

    /// Index file names
    ///
    /// **Default:** `["index.html", "index.htm"]`
    pub index_files: Vec<String>,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            file_serving_enabled: true,
            file_root: "./www".to_string(),
            directory_listing: false,
            compression_enabled: true,
            compression_algorithms: vec!["gzip".to_string(), "br".to_string()],
            index_files: vec!["index.html".to_string(), "index.htm".to_string()],
        }
    }
}

/// Connection Limits Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    /// Maximum field section (header) size in bytes
    ///
    /// **Default:** `16384` (16 KB)
    pub max_field_section_size: usize,

    /// Maximum concurrent bidirectional streams per connection
    ///
    /// **Default:** `100`
    pub max_concurrent_streams: usize,

    /// Connection idle timeout in seconds
    ///
    /// **Default:** `30`
    pub idle_timeout_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_field_section_size: 16384,
            max_concurrent_streams: 100,
            idle_timeout_secs: 30,
        }
    }
}

/// HTTP/3 application configuration.
///
/// This contains all HTTP/3 specific settings organized into subsections.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Http3Config {
    /// QPACK Configuration (RFC 9204)
    #[serde(default)]
    pub qpack: QpackConfig,

    /// Server Push Configuration
    #[serde(default)]
    pub push: PushConfig,

    /// HTTP Handler Configuration
    #[serde(default)]
    pub handler: HandlerConfig,

    /// Connection Limits
    #[serde(default)]
    pub limits: LimitsConfig,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            qpack: QpackConfig::default(),
            push: PushConfig::default(),
            handler: HandlerConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

impl Http3Config {
    pub fn validate(&self) -> Result<(), String> {
        // Validate QPACK settings
        if self.qpack.max_table_capacity == 0 {
            return Err("QPACK max_table_capacity must be greater than 0".to_string());
        }

        // Validate push settings
        if self.push.enabled && self.push.max_concurrent == 0 {
            return Err("Push max_concurrent must be greater than 0 when push is enabled".to_string());
        }

        // Validate handler settings
        if self.handler.file_serving_enabled && self.handler.file_root.is_empty() {
            return Err("Handler file_root cannot be empty when file serving is enabled".to_string());
        }

        // Validate limits
        if self.limits.max_field_section_size == 0 {
            return Err("Limits max_field_section_size must be greater than 0".to_string());
        }

        if self.limits.max_concurrent_streams == 0 {
            return Err("Limits max_concurrent_streams must be greater than 0".to_string());
        }

        Ok(())
    }
}

/// HQ-Interop (HTTP/0.9 over QUIC) application configuration.
///
/// This contains settings for the hq-interop protocol used in QUIC interoperability testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HqInteropConfig {
    /// HTTP Handler Configuration
    #[serde(default)]
    pub handler: HqInteropHandlerConfig,
}

impl Default for HqInteropConfig {
    fn default() -> Self {
        Self {
            handler: HqInteropHandlerConfig::default(),
        }
    }
}

impl HqInteropConfig {
    pub fn validate(&self) -> Result<(), String> {
        // Validate handler settings
        if self.handler.file_root.is_empty() {
            return Err("Handler file_root cannot be empty".to_string());
        }

        Ok(())
    }
}

/// Handler configuration for HQ-Interop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HqInteropHandlerConfig {
    /// Root directory for file serving
    pub file_root: String,

    /// Index files to try for directory requests (e.g., "index.html")
    pub index_files: Vec<String>,
}

impl Default for HqInteropHandlerConfig {
    fn default() -> Self {
        Self {
            file_root: "/www".to_string(),
            index_files: vec!["index.html".to_string()],
        }
    }
}

/// MOQ (Media over QUIC) application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MoqConfig {
    /// Maximum number of concurrent streams
    pub max_streams: usize,

    /// Enable track sources
    pub track_sources: bool,

    /// Additional MOQ-specific settings
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for MoqConfig {
    fn default() -> Self {
        Self {
            max_streams: 50,
            track_sources: true,
            extra: HashMap::new(),
        }
    }
}

impl MoqConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_streams == 0 {
            return Err("MOQ max_streams must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// Plugin application configuration.
///
/// # ABI Compatibility
///
/// The plugin must be compiled with:
/// - The same Rust compiler version as the server
/// - The same `quicd-x` dependency version
/// - Compatible system ABI (same target triple)
///
/// Failure to meet these requirements will result in undefined behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginConfig {
    /// Plugin-specific settings
    #[serde(default)]
    pub plugin: PluginSettings,

    /// Additional arbitrary configuration passed to the plugin
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            plugin: PluginSettings::default(),
            extra: HashMap::new(),
        }
    }
}

/// Plugin-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginSettings {
    /// Path to the dynamic library (.so, .dylib, .dll)
    ///
    /// Can be absolute or relative to the server's working directory.
    pub library_path: String,
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            library_path: String::new(),
        }
    }
}

impl PluginConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.plugin.library_path.is_empty() {
            return Err("Plugin library_path cannot be empty".to_string());
        }

        // Check if the file exists
        let path = std::path::Path::new(&self.plugin.library_path);
        if !path.exists() {
            return Err(format!("Plugin library not found: {}", self.plugin.library_path));
        }

        if !path.is_file() {
            return Err(format!("Plugin path is not a file: {}", self.plugin.library_path));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_http3_app() {
        let app = ApplicationConfig {
            alpn: vec!["h3".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert!(app.validate().is_ok());
    }

    #[test]
    fn test_multiple_alpns() {
        let app = ApplicationConfig {
            alpn: vec!["h3".to_string(), "h3-29".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert!(app.validate().is_ok());
    }

    #[test]
    fn test_empty_alpn_invalid() {
        let app = ApplicationConfig {
            alpn: Vec::new(),
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert!(app.validate().is_err());
    }

    #[test]
    fn test_parse_builtin_type() {
        let app = ApplicationConfig {
            alpn: vec!["h3".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert_eq!(app.parse_type().unwrap(), ApplicationType::Http3);
    }

    #[test]
    fn test_parse_plugin_type() {
        let app = ApplicationConfig {
            alpn: vec!["echo".to_string()],
            app_type: "plugin".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Empty(HashMap::new()),
        };
        assert_eq!(app.parse_type().unwrap(), ApplicationType::Plugin);
    }

    #[test]
    fn test_plugin_config_validation() {
        let plugin = PluginConfig::default();
        assert!(plugin.validate().is_err());

        let plugin = PluginConfig {
            plugin: PluginSettings {
                library_path: "/nonexistent/path.so".to_string(),
            },
            extra: HashMap::new(),
        };
        assert!(plugin.validate().is_err());
    }
}
