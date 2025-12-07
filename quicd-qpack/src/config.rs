//! QPACK configuration and tunable parameters.
//!
//! This module provides configuration options for QPACK header compression,
//! allowing operators to tune performance, security, and resource limits.

#[cfg(feature = "std")]
use std::time::Duration;

#[cfg(not(feature = "std"))]
use core::time::Duration;

use serde::{Deserialize, Serialize};

fn default_timeout() -> Duration {
    Duration::from_secs(60)
}

/// Configuration for QPACK header compression.
///
/// Default values are chosen for a balance of performance, security, and
/// RFC compliance. Adjust based on your deployment needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QpackConfig {
    /// Maximum dynamic table capacity (default: 4 KB).
    ///
    /// RFC 9204 Section 3.2.3: Sent in SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    /// Higher values improve compression but use more memory per connection.
    pub max_table_capacity: usize,

    /// Maximum number of blocked streams (default: 100).
    ///
    /// RFC 9204 Section 2.1.4: Sent in SETTINGS_QPACK_BLOCKED_STREAMS.
    /// Streams waiting for dynamic table updates count toward this limit.
    pub max_blocked_streams: usize,

    /// Timeout for blocked streams (default: 60 seconds).
    ///
    /// RFC 9204 Section 2.1.4: "Implementations SHOULD impose a timeout"
    /// on blocked streams. Streams blocked longer are reset with
    /// QPACK_DECOMPRESSION_FAILED.
    #[serde(default = "default_timeout")]
    pub blocked_stream_timeout: Duration,
}

impl Default for QpackConfig {
    fn default() -> Self {
        Self {
            max_table_capacity: 4096, // 4 KB
            max_blocked_streams: 100,
            blocked_stream_timeout: Duration::from_secs(60),
        }
    }
}

impl QpackConfig {
    /// Validate configuration values are within reasonable bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_table_capacity == 0 {
            return Err("max_table_capacity must be non-zero".into());
        }
        if self.max_table_capacity > 1 << 30 {
            return Err("max_table_capacity too large (max 1 GB)".into());
        }
        if self.max_blocked_streams == 0 {
            return Err("max_blocked_streams must be non-zero".into());
        }
        if self.blocked_stream_timeout.as_secs() == 0 {
            return Err("blocked_stream_timeout must be non-zero".into());
        }
        Ok(())
    }

    /// Create a configuration optimized for high-throughput scenarios.
    ///
    /// Increases table capacity and blocked streams for better compression
    /// at the cost of higher memory usage.
    pub fn high_throughput() -> Self {
        Self {
            max_table_capacity: 16384, // 16 KB
            max_blocked_streams: 500,
            ..Default::default()
        }
    }

    /// Create a configuration optimized for memory-constrained environments.
    ///
    /// Reduces table capacity and blocked streams to minimize memory footprint.
    pub fn low_memory() -> Self {
        Self {
            max_table_capacity: 512, // 512 bytes
            max_blocked_streams: 10,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = QpackConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_high_throughput_config_is_valid() {
        let config = QpackConfig::high_throughput();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_low_memory_config_is_valid() {
        let config = QpackConfig::low_memory();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_zero_table_capacity_invalid() {
        let mut config = QpackConfig::default();
        config.max_table_capacity = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_excessive_table_capacity_invalid() {
        let mut config = QpackConfig::default();
        config.max_table_capacity = (1 << 30) + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_blocked_streams_invalid() {
        let mut config = QpackConfig::default();
        config.max_blocked_streams = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_timeout_invalid() {
        let mut config = QpackConfig::default();
        config.blocked_stream_timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());
    }
}
