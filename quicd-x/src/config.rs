//! Configuration for the QUIC application interface.
//!
//! This module defines configuration parameters for the base QUIC application
//! layer, controlling behavior of the event-driven interface between workers
//! and application tasks.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default maximum idle timeout (30 seconds)
pub const DEFAULT_MAX_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Default initial RTT estimate (100ms)
pub const DEFAULT_INITIAL_RTT_MS: u64 = 100;

/// Default maximum concurrent bidirectional streams per connection
pub const DEFAULT_MAX_STREAMS_BIDI: u64 = 100;

/// Default maximum concurrent unidirectional streams per connection
pub const DEFAULT_MAX_STREAMS_UNI: u64 = 100;

/// Default maximum UDP payload size (1350 bytes for IPv4, safe for most networks)
pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: usize = 1350;

/// Default connection receive window (10 MB)
pub const DEFAULT_RECV_WINDOW: u64 = 10 * 1024 * 1024;

/// Default stream receive window (1 MB)
pub const DEFAULT_STREAM_RECV_WINDOW: u64 = 1024 * 1024;

/// Default maximum connections per worker
pub const DEFAULT_MAX_CONNECTIONS_PER_WORKER: usize = 100_000;

/// Congestion control algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    /// BBR (Bottleneck Bandwidth and RTT)
    /// Best for high-bandwidth, high-latency networks
    Bbr,
    /// BBR v2
    Bbr2,
    /// CUBIC (default in many systems)
    Cubic,
    /// NewReno (classic TCP-style)
    Reno,
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self::Cubic
    }
}

/// QUIC transport protocol configuration.
///
/// This configuration controls the core QUIC transport parameters,
/// including timeouts, flow control windows, congestion control,
/// and connection limits.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct QuicTransportConfig {
    /// Maximum idle timeout in milliseconds
    /// Connection closed if idle for this duration
    #[serde(default = "default_max_idle_timeout")]
    pub max_idle_timeout_ms: u64,

    /// Initial RTT estimate in milliseconds
    #[serde(default = "default_initial_rtt")]
    pub initial_rtt_ms: u64,

    /// Maximum number of concurrent bidirectional streams per connection
    #[serde(default = "default_max_streams_bidi")]
    pub max_streams_bidi: u64,

    /// Maximum number of concurrent unidirectional streams per connection
    #[serde(default = "default_max_streams_uni")]
    pub max_streams_uni: u64,

    /// Maximum UDP payload size
    /// Should be ≤ path MTU to avoid fragmentation
    #[serde(default = "default_max_udp_payload_size")]
    pub max_udp_payload_size: usize,

    /// Connection-level receive window (flow control)
    #[serde(default = "default_recv_window")]
    pub recv_window: u64,

    /// Per-stream receive window (flow control)
    #[serde(default = "default_stream_recv_window")]
    pub stream_recv_window: u64,

    /// Congestion control algorithm
    #[serde(default)]
    pub congestion_control: CongestionControl,

    /// Enable early data (0-RTT)
    /// Allows sending data during handshake (security implications!)
    #[serde(default)]
    pub enable_early_data: bool,

    /// Disable active migration
    /// If true, connections can't change IP/port
    #[serde(default)]
    pub disable_active_migration: bool,

    /// Enable pacing of sent packets
    /// Helps with congestion control
    #[serde(default = "default_true")]
    pub enable_pacing: bool,

    /// Maximum connections per worker thread
    /// Pre-allocates capacity for this many connections
    #[serde(default = "default_max_connections")]
    pub max_connections_per_worker: usize,

    /// Enable QUIC version negotiation
    #[serde(default = "default_true")]
    pub enable_version_negotiation: bool,

    /// QUIC versions to support (v1 is always enabled)
    /// Example: ["draft-29", "v1"]
    #[serde(default)]
    pub additional_versions: Vec<String>,

    /// Enable DATAGRAM extension (RFC 9221)
    /// Allows sending unreliable datagrams over QUIC
    #[serde(default)]
    pub enable_dgram: bool,

    /// Maximum DATAGRAM frame size
    #[serde(default = "default_max_dgram_size")]
    pub max_dgram_size: usize,

    /// Enable connection statistics collection
    #[serde(default = "default_true")]
    pub enable_stats: bool,
}

fn default_max_idle_timeout() -> u64 {
    DEFAULT_MAX_IDLE_TIMEOUT_MS
}

fn default_initial_rtt() -> u64 {
    DEFAULT_INITIAL_RTT_MS
}

fn default_max_streams_bidi() -> u64 {
    DEFAULT_MAX_STREAMS_BIDI
}

fn default_max_streams_uni() -> u64 {
    DEFAULT_MAX_STREAMS_UNI
}

fn default_max_udp_payload_size() -> usize {
    DEFAULT_MAX_UDP_PAYLOAD_SIZE
}

fn default_recv_window() -> u64 {
    DEFAULT_RECV_WINDOW
}

fn default_stream_recv_window() -> u64 {
    DEFAULT_STREAM_RECV_WINDOW
}

fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS_PER_WORKER
}

fn default_true() -> bool {
    true
}

fn default_max_dgram_size() -> usize {
    DEFAULT_MAX_UDP_PAYLOAD_SIZE
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        let resources = crate::system_resources::SystemResources::query();

        Self {
            max_idle_timeout_ms: resources.optimal_idle_timeout_ms(),
            initial_rtt_ms: DEFAULT_INITIAL_RTT_MS,
            max_streams_bidi: DEFAULT_MAX_STREAMS_BIDI,
            max_streams_uni: DEFAULT_MAX_STREAMS_UNI,
            max_udp_payload_size: resources.optimal_max_udp_payload(),
            recv_window: resources.optimal_quic_recv_window(),
            stream_recv_window: resources.optimal_quic_stream_recv_window(),
            congestion_control: CongestionControl::default(),
            enable_early_data: false,
            disable_active_migration: false,
            enable_pacing: true,
            max_connections_per_worker: (resources.max_connections_from_memory()
                / resources.optimal_worker_threads())
            .max(1000),
            enable_version_negotiation: true,
            additional_versions: Vec::new(),
            enable_dgram: false,
            max_dgram_size: resources.optimal_max_udp_payload(),
            enable_stats: true,
        }
    }
}

impl QuicTransportConfig {
    /// Get idle timeout as Duration
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.max_idle_timeout_ms)
    }

    /// Get initial RTT as Duration
    pub fn initial_rtt(&self) -> Duration {
        Duration::from_millis(self.initial_rtt_ms)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_idle_timeout_ms == 0 {
            return Err("max_idle_timeout_ms must be > 0".to_string());
        }

        if self.max_udp_payload_size < 1200 {
            return Err("max_udp_payload_size must be >= 1200 (QUIC minimum)".to_string());
        }

        if self.max_udp_payload_size > 65535 {
            return Err("max_udp_payload_size must be <= 65535".to_string());
        }

        if self.recv_window == 0 {
            return Err("recv_window must be > 0".to_string());
        }

        if self.stream_recv_window == 0 {
            return Err("stream_recv_window must be > 0".to_string());
        }

        if self.max_connections_per_worker == 0 {
            return Err("max_connections_per_worker must be > 0".to_string());
        }

        Ok(())
    }

    /// Get the congestion control algorithm
    pub fn congestion_control_algorithm(&self) -> CongestionControl {
        self.congestion_control
    }
}

/// Configuration for the QUIC application interface layer.

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
            return Err(
                "connection_cleanup_timeout is unreasonably high (> 5 minutes)".to_string(),
            );
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
                self.stream_ingress_channel_capacity, estimated_stream_memory_mb
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
