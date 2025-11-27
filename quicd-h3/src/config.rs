//! HTTP/3 configuration and tunable parameters.
//!
//! This module provides configuration options for the HTTP/3 session,
//! allowing operators to tune performance, security, and resource limits.

use std::time::Duration;

/// Configuration for HTTP/3 session behavior.
///
/// Default values are chosen for a balance of performance, security, and
/// RFC compliance. Adjust based on your deployment needs.
#[derive(Debug, Clone)]
pub struct H3Config {
    /// Maximum size of a single HTTP/3 frame payload (default: 16 MB).
    ///
    /// RFC 9114 Section 7.1: Implementations SHOULD set a limit to avoid
    /// excessive memory consumption from malicious peers.
    ///
    /// Lower values reduce memory risk but may fragment large responses.
    pub max_frame_size: u64,
    
    /// Maximum size of a field section (headers) in bytes (default: 64 KB).
    ///
    /// RFC 9114 Section 7.2.4.2: Sent in SETTINGS_MAX_FIELD_SECTION_SIZE.
    /// Set to 0 for unlimited (not recommended for public servers).
    pub max_field_section_size: u64,
    
    /// Maximum QPACK dynamic table capacity (default: 4 KB).
    ///
    /// RFC 9204 Section 3.2.3: Sent in SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    /// Higher values improve compression but use more memory per connection.
    pub qpack_max_table_capacity: u64,
    
    /// Maximum number of QPACK blocked streams (default: 100).
    ///
    /// RFC 9204 Section 2.1.4: Sent in SETTINGS_QPACK_BLOCKED_STREAMS.
    /// Streams waiting for dynamic table updates count toward this limit.
    pub qpack_blocked_streams: u64,
    
    /// Timeout for QPACK blocked streams (default: 60 seconds).
    ///
    /// RFC 9204 Section 2.1.4: "Implementations SHOULD impose a timeout"
    /// on blocked streams. Streams blocked longer are reset with
    /// H3_QPACK_DECOMPRESSION_FAILED.
    pub qpack_blocked_stream_timeout: Duration,
    
    /// Maximum number of concurrent bidirectional streams (default: 100).
    ///
    /// RFC 9114 Section 5: Controls how many request streams can be open
    /// simultaneously. Exceeding this limit causes H3_REQUEST_REJECTED.
    pub max_concurrent_streams: u64,
    
    /// Maximum push ID server can send (default: 100).
    ///
    /// RFC 9114 Section 7.2.7: Server cannot send PUSH_PROMISE with
    /// push_id greater than this value.
    pub max_push_id: u64,
    
    /// Initial buffer capacity for StreamFrameParser (default: 16 KB).
    ///
    /// Performance tuning: Higher values reduce reallocations for large
    /// frames but use more memory per stream.
    pub stream_buffer_initial_capacity: usize,
    
    /// Maximum buffer size per stream (default: 1 MB).
    ///
    /// Security: Prevents memory exhaustion from slow-reading clients.
    /// Frames exceeding this size cause connection error.
    pub stream_buffer_max_size: usize,
    
    /// Enable extended CONNECT protocol (default: true).
    ///
    /// RFC 9114 Section 4.4: Allows :protocol pseudo-header in CONNECT
    /// requests (e.g., for WebSocket-over-HTTP/3).
    pub enable_connect_protocol: bool,
    
    /// Enable server push (default: false).
    ///
    /// RFC 9114 Section 4.6: Allows server to send PUSH_PROMISE frames.
    /// Disable to reduce complexity if push not needed.
    pub enable_server_push: bool,
    
    /// Probability of sending reserved identifiers for greasing (default: 0.1).
    ///
    /// RFC 9114 Section 7.2.8: "Implementations SHOULD send" reserved
    /// frame types and settings occasionally. Value is 0.0-1.0.
    pub grease_probability: f32,
    
    /// Interval for checking QPACK blocked stream timeouts (default: 10 seconds).
    ///
    /// Performance tuning: Lower values improve responsiveness but increase
    /// CPU overhead. Higher values reduce overhead but delay timeout detection.
    pub blocked_stream_check_interval: Duration,
    
    /// Maximum number of QPACK encoder instructions to batch (default: 8).
    ///
    /// Performance tuning: Higher values reduce syscalls but increase latency.
    pub qpack_encoder_instruction_batch_size: usize,
    
    /// Maximum number of QPACK decoder instructions to batch (default: 8).
    ///
    /// Performance tuning: Higher values reduce syscalls but increase latency.
    pub qpack_decoder_instruction_batch_size: usize,
}

impl Default for H3Config {
    fn default() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024, // 16 MB
            max_field_section_size: 64 * 1024, // 64 KB
            qpack_max_table_capacity: 4096, // 4 KB
            qpack_blocked_streams: 100,
            qpack_blocked_stream_timeout: Duration::from_secs(60),
            max_concurrent_streams: 100,
            max_push_id: 100,
            stream_buffer_initial_capacity: 16 * 1024, // 16 KB
            stream_buffer_max_size: 1024 * 1024, // 1 MB
            enable_connect_protocol: true,
            enable_server_push: false,
            grease_probability: 0.1,
            blocked_stream_check_interval: Duration::from_secs(10),
            qpack_encoder_instruction_batch_size: 8,
            qpack_decoder_instruction_batch_size: 8,
        }
    }
}

impl H3Config {
    /// Create a configuration optimized for high-throughput scenarios.
    ///
    /// Increases buffer sizes and concurrent stream limits, suitable for
    /// servers handling many clients with good network conditions.
    pub fn high_throughput() -> Self {
        Self {
            max_frame_size: 64 * 1024 * 1024, // 64 MB
            max_field_section_size: 256 * 1024, // 256 KB
            qpack_max_table_capacity: 16384, // 16 KB
            qpack_blocked_streams: 500,
            max_concurrent_streams: 1000,
            stream_buffer_initial_capacity: 64 * 1024, // 64 KB
            stream_buffer_max_size: 8 * 1024 * 1024, // 8 MB
            qpack_encoder_instruction_batch_size: 32,
            qpack_decoder_instruction_batch_size: 32,
            ..Default::default()
        }
    }
    
    /// Create a configuration optimized for memory-constrained environments.
    ///
    /// Reduces buffer sizes and concurrent stream limits, suitable for
    /// embedded devices or servers handling millions of connections.
    pub fn low_memory() -> Self {
        Self {
            max_frame_size: 1024 * 1024, // 1 MB
            max_field_section_size: 8192, // 8 KB
            qpack_max_table_capacity: 512, // 512 bytes
            qpack_blocked_streams: 10,
            max_concurrent_streams: 10,
            stream_buffer_initial_capacity: 4096, // 4 KB
            stream_buffer_max_size: 65536, // 64 KB
            qpack_encoder_instruction_batch_size: 2,
            qpack_decoder_instruction_batch_size: 2,
            ..Default::default()
        }
    }
    
    /// Create a configuration optimized for CDN/edge scenarios.
    ///
    /// Balances throughput and memory, with server push enabled and
    /// larger QPACK tables for better compression.
    pub fn cdn() -> Self {
        Self {
            max_frame_size: 32 * 1024 * 1024, // 32 MB
            max_field_section_size: 128 * 1024, // 128 KB
            qpack_max_table_capacity: 8192, // 8 KB
            qpack_blocked_streams: 200,
            max_concurrent_streams: 200,
            max_push_id: 1000,
            enable_server_push: true,
            stream_buffer_initial_capacity: 32 * 1024, // 32 KB
            stream_buffer_max_size: 4 * 1024 * 1024, // 4 MB
            qpack_encoder_instruction_batch_size: 16,
            qpack_decoder_instruction_batch_size: 16,
            ..Default::default()
        }
    }
    
    /// Validate configuration values are within reasonable bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_frame_size == 0 {
            return Err("max_frame_size must be non-zero".into());
        }
        if self.max_frame_size > 128 * 1024 * 1024 {
            return Err("max_frame_size too large (max 128 MB)".into());
        }
        if self.qpack_blocked_stream_timeout.as_secs() == 0 {
            return Err("qpack_blocked_stream_timeout must be non-zero".into());
        }
        if self.grease_probability < 0.0 || self.grease_probability > 1.0 {
            return Err("grease_probability must be between 0.0 and 1.0".into());
        }
        if self.stream_buffer_initial_capacity > self.stream_buffer_max_size {
            return Err("stream_buffer_initial_capacity cannot exceed max_size".into());
        }
        if self.qpack_encoder_instruction_batch_size == 0 {
            return Err("qpack_encoder_instruction_batch_size must be non-zero".into());
        }
        if self.qpack_decoder_instruction_batch_size == 0 {
            return Err("qpack_decoder_instruction_batch_size must be non-zero".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config_is_valid() {
        let config = H3Config::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_high_throughput_config_is_valid() {
        let config = H3Config::high_throughput();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_low_memory_config_is_valid() {
        let config = H3Config::low_memory();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_cdn_config_is_valid() {
        let config = H3Config::cdn();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_invalid_max_frame_size() {
        let mut config = H3Config::default();
        config.max_frame_size = 0;
        assert!(config.validate().is_err());
        
        config.max_frame_size = 200 * 1024 * 1024;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_invalid_grease_probability() {
        let mut config = H3Config::default();
        config.grease_probability = -0.1;
        assert!(config.validate().is_err());
        
        config.grease_probability = 1.1;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_invalid_buffer_sizes() {
        let mut config = H3Config::default();
        config.stream_buffer_initial_capacity = 2 * 1024 * 1024;
        config.stream_buffer_max_size = 1 * 1024 * 1024;
        assert!(config.validate().is_err());
    }
}
