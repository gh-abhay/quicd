//! HTTP/3 application configuration.
//!
//! This module defines configuration structures for the H3 application,
//! including QPACK settings, connection limits, handler configuration, etc.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// HTTP/3 application configuration.
///
/// This configuration is specific to the HTTP/3 protocol and can be
/// customized per-application in the quicd.toml configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct H3Config {
    /// QPACK configuration.
    #[serde(default)]
    pub qpack: QpackConfig,

    /// Server push configuration.
    #[serde(default)]
    pub push: PushConfig,

    /// HTTP handler configuration.
    #[serde(default)]
    pub handler: HandlerConfig,

    /// Connection limits.
    #[serde(default)]
    pub limits: LimitsConfig,
}


impl H3Config {
    /// Validate the configuration.
    ///
    /// Returns a vector of validation errors. Empty vector means valid configuration.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        errors.extend(self.qpack.validate());
        errors.extend(self.push.validate());
        errors.extend(self.handler.validate());
        errors.extend(self.limits.validate());

        errors
    }
}

/// QPACK configuration per RFC 9204.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QpackConfig {
    /// Maximum dynamic table capacity in bytes.
    ///
    /// Per RFC 9204, this is advertised via SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    /// Default: 4096 bytes (4 KB).
    #[serde(default = "default_qpack_max_table_capacity")]
    pub max_table_capacity: u64,

    /// Maximum number of streams that can be blocked waiting for QPACK dynamic
    /// table updates.
    ///
    /// Per RFC 9204, advertised via SETTINGS_QPACK_BLOCKED_STREAMS.
    /// Default: 100 streams.
    #[serde(default = "default_qpack_blocked_streams")]
    pub blocked_streams: u64,
}

impl Default for QpackConfig {
    fn default() -> Self {
        Self {
            max_table_capacity: default_qpack_max_table_capacity(),
            blocked_streams: default_qpack_blocked_streams(),
        }
    }
}

impl QpackConfig {
    fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.max_table_capacity == 0 {
            errors.push("QPACK max_table_capacity must be > 0".to_string());
        }

        if self.max_table_capacity > 1024 * 1024 * 100 {
            // 100 MB limit seems reasonable
            errors.push(format!(
                "QPACK max_table_capacity too large: {} bytes (max 100 MB)",
                self.max_table_capacity
            ));
        }

        errors
    }
}

fn default_qpack_max_table_capacity() -> u64 {
    4096
}

fn default_qpack_blocked_streams() -> u64 {
    100
}

/// Server push configuration per RFC 9114 Section 4.6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushConfig {
    /// Enable server push.
    ///
    /// If false, the server will not send PUSH_PROMISE frames.
    /// Default: false (disabled for simplicity and performance).
    #[serde(default = "default_push_enabled")]
    pub enabled: bool,

    /// Maximum number of concurrent server push streams.
    ///
    /// Only used if push is enabled.
    /// Default: 100.
    #[serde(default = "default_max_concurrent_pushes")]
    pub max_concurrent: u64,

    /// Maximum push ID.
    ///
    /// Advertised via MAX_PUSH_ID frame to client.
    /// Default: 1000.
    #[serde(default = "default_max_push_id")]
    pub max_push_id: u64,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            enabled: default_push_enabled(),
            max_concurrent: default_max_concurrent_pushes(),
            max_push_id: default_max_push_id(),
        }
    }
}

impl PushConfig {
    fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.enabled && self.max_concurrent == 0 {
            errors.push("Push max_concurrent must be > 0 when push is enabled".to_string());
        }

        errors
    }
}

fn default_push_enabled() -> bool {
    false
}

fn default_max_concurrent_pushes() -> u64 {
    100
}

fn default_max_push_id() -> u64 {
    1000
}

/// HTTP handler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerConfig {
    /// Enable the default file-serving handler.
    ///
    /// Default: true.
    #[serde(default = "default_file_serving_enabled")]
    pub file_serving_enabled: bool,

    /// Root directory for file serving.
    ///
    /// Required if file_serving_enabled is true.
    /// Default: "./www"
    #[serde(default = "default_file_root")]
    pub file_root: PathBuf,

    /// Enable directory listing.
    ///
    /// If true, directories without index.html will show a file listing.
    /// Default: false (for security).
    #[serde(default = "default_directory_listing")]
    pub directory_listing: bool,

    /// Enable response compression.
    ///
    /// Supports gzip and brotli based on Accept-Encoding header.
    /// Default: true.
    #[serde(default = "default_compression_enabled")]
    pub compression_enabled: bool,

    /// Compression algorithms to use.
    ///
    /// Valid values: "gzip", "br" (brotli).
    /// Default: ["gzip", "br"]
    #[serde(default = "default_compression_algorithms")]
    pub compression_algorithms: Vec<String>,

    /// Default index file names.
    ///
    /// When a directory is requested, try these files in order.
    /// Default: ["index.html", "index.htm"]
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            file_serving_enabled: default_file_serving_enabled(),
            file_root: default_file_root(),
            directory_listing: default_directory_listing(),
            compression_enabled: default_compression_enabled(),
            compression_algorithms: default_compression_algorithms(),
            index_files: default_index_files(),
        }
    }
}

impl HandlerConfig {
    fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.file_serving_enabled {
            if !self.file_root.exists() {
                errors.push(format!(
                    "File serving root directory does not exist: {}",
                    self.file_root.display()
                ));
            } else if !self.file_root.is_dir() {
                errors.push(format!(
                    "File serving root is not a directory: {}",
                    self.file_root.display()
                ));
            }
        }

        for algo in &self.compression_algorithms {
            if algo != "gzip" && algo != "br" {
                errors.push(format!("Unknown compression algorithm: {}", algo));
            }
        }

        errors
    }
}

fn default_file_serving_enabled() -> bool {
    true
}

fn default_file_root() -> PathBuf {
    PathBuf::from("./www")
}

fn default_directory_listing() -> bool {
    false
}

fn default_compression_enabled() -> bool {
    true
}

fn default_compression_algorithms() -> Vec<String> {
    vec!["gzip".to_string(), "br".to_string()]
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string(), "index.htm".to_string()]
}

/// Connection-level limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum field section size in bytes.
    ///
    /// Per RFC 9114, advertised via SETTINGS_MAX_FIELD_SECTION_SIZE.
    /// Default: 16384 bytes (16 KB).
    #[serde(default = "default_max_field_section_size")]
    pub max_field_section_size: u64,

    /// Maximum number of concurrent bidirectional streams per connection.
    ///
    /// This is a soft limit for resource management.
    /// Default: 100.
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u64,

    /// Connection idle timeout in seconds.
    ///
    /// If no frames are received within this time, close the connection.
    /// Default: 30 seconds.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_field_section_size: default_max_field_section_size(),
            max_concurrent_streams: default_max_concurrent_streams(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

impl LimitsConfig {
    fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.max_field_section_size == 0 {
            errors.push("max_field_section_size must be > 0".to_string());
        }

        if self.max_concurrent_streams == 0 {
            errors.push("max_concurrent_streams must be > 0".to_string());
        }

        errors
    }
}

fn default_max_field_section_size() -> u64 {
    16384
}

fn default_max_concurrent_streams() -> u64 {
    100
}

fn default_idle_timeout_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = H3Config::default();
        let errors = config.validate();
        // File root may not exist, so check specific validations
        assert!(errors.iter().all(|e| e.contains("File serving root")));
    }

    #[test]
    fn test_qpack_validation() {
        let mut config = QpackConfig::default();
        assert!(config.validate().is_empty());

        config.max_table_capacity = 0;
        assert!(!config.validate().is_empty());
    }

    #[test]
    fn test_push_validation() {
        let mut config = PushConfig::default();
        assert!(config.validate().is_empty());

        config.enabled = true;
        config.max_concurrent = 0;
        assert!(!config.validate().is_empty());
    }

    #[test]
    fn test_limits_validation() {
        let mut config = LimitsConfig::default();
        assert!(config.validate().is_empty());

        config.max_field_section_size = 0;
        assert!(!config.validate().is_empty());
    }
}
