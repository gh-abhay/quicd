//! Configuration for the QUIC application interface.
//!
//! This module defines configuration parameters for the base QUIC application
//! layer, controlling behavior of the event-driven interface between workers
//! and application tasks.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the QUIC application interface layer.
///
/// These settings control the behavior of the channel-based communication
/// between QUIC workers and application tasks, as well as resource limits
/// and timeout behaviors.
///
/// # Philosophy
///
/// The interface configuration is designed to be tunable independently of
/// the QUIC transport layer. These parameters affect the async runtime
/// boundary and application lifecycle, not the wire protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuicAppConfig {
    /// Maximum time an application task is allowed to run after receiving
    /// a `ConnectionClosing` event before being forcefully terminated.
    ///
    /// This grace period allows applications to:
    /// - Flush buffered data
    /// - Save state to persistent storage
    /// - Clean up resources gracefully
    ///
    /// **Default:** 30 seconds
    ///
    /// **Tuning:**
    /// - Lower for fast-failing systems (5-10s)
    /// - Higher for applications with complex cleanup (60s+)
    ///
    /// **RFC Reference:** Not specified; implementation-defined
    #[serde(with = "humantime_serde")]
    pub connection_cleanup_timeout: Duration,

    /// Capacity of the worker egress channel (app → worker).
    ///
    /// This channel receives all egress commands from application tasks
    /// to the worker thread. Each connection's app task shares this channel.
    ///
    /// **Default:** 2048 commands
    ///
    /// **Tuning:**
    /// - Higher for applications with burst writes (HTTP/3 responses)
    /// - Lower for memory-constrained environments
    ///
    /// **Backpressure:** When full, `ConnectionHandle` methods return errors
    pub worker_egress_channel_capacity: usize,

    /// Capacity of the connection ingress channel (worker → app).
    ///
    /// This channel delivers events from the worker to a single app task.
    /// Each connection has its own dedicated ingress channel.
    ///
    /// **Default:** 1024 events
    ///
    /// **Tuning:**
    /// - Higher for slow-processing applications
    /// - Lower to enforce backpressure on the worker
    ///
    /// **Backpressure:** When full, worker thread blocks (affects all connections)
    pub connection_ingress_channel_capacity: usize,

    /// Capacity of per-stream ingress channel (worker → app).
    ///
    /// Each stream has a dedicated channel for zero-copy data delivery.
    /// Memory usage: `capacity * avg_chunk_size * concurrent_streams`
    ///
    /// **Default:** 256 chunks
    ///
    /// **Tuning:**
    /// - Higher for large stream buffers (video streaming)
    /// - Lower for memory efficiency with many concurrent streams
    ///
    /// **Example:** 256 * 64KB * 100 streams = 1.6GB memory
    pub stream_ingress_channel_capacity: usize,

    /// Capacity of per-stream egress channel (app → worker).
    ///
    /// Each stream has a channel for write commands from the app.
    ///
    /// **Default:** 256 commands
    ///
    /// **Tuning:**
    /// - Higher for burst writers
    /// - Lower for flow-control enforcement
    pub stream_egress_channel_capacity: usize,

    /// Enable automatic backpressure signaling via `StreamReadable` events.
    ///
    /// When enabled, the worker sends edge-triggered notifications when
    /// stream data becomes available. Reduces polling overhead.
    ///
    /// **Default:** true
    ///
    /// **Disable if:** Your app uses continuous polling patterns
    pub enable_stream_readable_events: bool,

    /// Interval for checking idle connections and triggering cleanup.
    ///
    /// The worker periodically scans for connections that have exceeded
    /// their idle timeout and initiates closure.
    ///
    /// **Default:** 5 seconds
    ///
    /// **Tuning:**
    /// - Lower for aggressive resource reclamation
    /// - Higher to reduce CPU overhead
    #[serde(with = "humantime_serde")]
    pub idle_check_interval: Duration,

    /// Maximum number of in-flight egress commands per connection.
    ///
    /// Limits the number of concurrent operations (open_stream, send_datagram)
    /// that can be pending for a single connection.
    ///
    /// **Default:** 128
    ///
    /// **Purpose:** Prevents a single misbehaving app from filling the egress channel
    pub max_inflight_commands_per_connection: usize,

    /// Enable detailed event tracing for debugging.
    ///
    /// When enabled, all events and commands are logged with trace-level spans.
    /// Useful for debugging but has performance overhead.
    ///
    /// **Default:** false
    pub enable_event_tracing: bool,
}

impl Default for QuicAppConfig {
    fn default() -> Self {
        Self {
            connection_cleanup_timeout: Duration::from_secs(30),
            worker_egress_channel_capacity: 2048,
            connection_ingress_channel_capacity: 1024,
            stream_ingress_channel_capacity: 256,
            stream_egress_channel_capacity: 256,
            enable_stream_readable_events: true,
            idle_check_interval: Duration::from_secs(5),
            max_inflight_commands_per_connection: 128,
            enable_event_tracing: false,
        }
    }
}

impl QuicAppConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any configuration value is invalid or would
    /// cause runtime issues.
    pub fn validate(&self) -> Result<(), String> {
        // Validate cleanup timeout
        if self.connection_cleanup_timeout.as_secs() == 0 {
            return Err("connection_cleanup_timeout must be > 0".to_string());
        }
        if self.connection_cleanup_timeout.as_secs() > 300 {
            return Err("connection_cleanup_timeout is unreasonably high (> 5 minutes)".to_string());
        }

        // Validate channel capacities (must be at least 1)
        if self.worker_egress_channel_capacity == 0 {
            return Err("worker_egress_channel_capacity must be > 0".to_string());
        }
        if self.connection_ingress_channel_capacity == 0 {
            return Err("connection_ingress_channel_capacity must be > 0".to_string());
        }
        if self.stream_ingress_channel_capacity == 0 {
            return Err("stream_ingress_channel_capacity must be > 0".to_string());
        }
        if self.stream_egress_channel_capacity == 0 {
            return Err("stream_egress_channel_capacity must be > 0".to_string());
        }

        // Validate reasonable lower bounds
        if self.worker_egress_channel_capacity < 64 {
            return Err("worker_egress_channel_capacity should be at least 64".to_string());
        }
        if self.connection_ingress_channel_capacity < 32 {
            return Err("connection_ingress_channel_capacity should be at least 32".to_string());
        }

        // Validate idle check interval
        if self.idle_check_interval.as_secs() == 0 {
            return Err("idle_check_interval must be > 0".to_string());
        }

        // Validate max inflight commands
        if self.max_inflight_commands_per_connection == 0 {
            return Err("max_inflight_commands_per_connection must be > 0".to_string());
        }

        // Check for excessive memory usage scenarios
        let estimated_stream_memory_mb = 
            (self.stream_ingress_channel_capacity * 64 * 1024) / (1024 * 1024);
        if estimated_stream_memory_mb > 16 {
            eprintln!(
                "Warning: stream_ingress_channel_capacity ({}) may use ~{}MB per stream",
                self.stream_ingress_channel_capacity,
                estimated_stream_memory_mb
            );
        }

        Ok(())
    }

    /// Create a configuration optimized for high-throughput scenarios.
    ///
    /// Increases buffer sizes and channel capacities for maximum performance
    /// at the cost of higher memory usage.
    pub fn high_throughput() -> Self {
        Self {
            worker_egress_channel_capacity: 8192,
            connection_ingress_channel_capacity: 4096,
            stream_ingress_channel_capacity: 512,
            stream_egress_channel_capacity: 512,
            max_inflight_commands_per_connection: 256,
            ..Default::default()
        }
    }

    /// Create a configuration optimized for memory-constrained environments.
    ///
    /// Reduces buffer sizes and channel capacities to minimize memory footprint.
    pub fn low_memory() -> Self {
        Self {
            worker_egress_channel_capacity: 512,
            connection_ingress_channel_capacity: 256,
            stream_ingress_channel_capacity: 64,
            stream_egress_channel_capacity: 64,
            max_inflight_commands_per_connection: 32,
            ..Default::default()
        }
    }

    /// Create a configuration optimized for low-latency scenarios.
    ///
    /// Smaller buffers enforce backpressure sooner, reducing queuing delays.
    pub fn low_latency() -> Self {
        Self {
            worker_egress_channel_capacity: 1024,
            connection_ingress_channel_capacity: 512,
            stream_ingress_channel_capacity: 128,
            stream_egress_channel_capacity: 128,
            idle_check_interval: Duration::from_secs(1),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = QuicAppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_configs_are_valid() {
        assert!(QuicAppConfig::high_throughput().validate().is_ok());
        assert!(QuicAppConfig::low_memory().validate().is_ok());
        assert!(QuicAppConfig::low_latency().validate().is_ok());
    }

    #[test]
    fn test_zero_timeout_invalid() {
        let mut config = QuicAppConfig::default();
        config.connection_cleanup_timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_capacity_invalid() {
        let mut config = QuicAppConfig::default();
        config.worker_egress_channel_capacity = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_excessive_timeout_invalid() {
        let mut config = QuicAppConfig::default();
        config.connection_cleanup_timeout = Duration::from_secs(301);
        assert!(config.validate().is_err());
    }
}
