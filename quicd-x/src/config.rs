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

/// Default ACK delay exponent (RFC 9000 §18.2)
pub const DEFAULT_ACK_DELAY_EXPONENT: u64 = 3;

/// Default max ACK delay in milliseconds (RFC 9000 §18.2)
pub const DEFAULT_MAX_ACK_DELAY: u64 = 25;

/// Default active connection ID limit (RFC 9000 §18.2)
pub const DEFAULT_ACTIVE_CID_LIMIT: u64 = 2;

/// Default initial congestion window in packets
pub const DEFAULT_INITIAL_CWND_PACKETS: usize = 10;

/// Default max amplification factor (RFC 9000 §8.1)
pub const DEFAULT_AMPLIFICATION_FACTOR: usize = 3;

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

    // ====== Extended Transport Parameters (RFC 9000 §18.2) ======
    
    /// ACK delay exponent for computing ACK Delay field
    #[serde(default = "default_ack_delay_exponent")]
    pub ack_delay_exponent: u64,
    
    /// Maximum ACK delay in milliseconds
    #[serde(default = "default_max_ack_delay")]
    pub max_ack_delay: u64,
    
    /// Active connection ID limit
    #[serde(default = "default_active_cid_limit")]
    pub active_connection_id_limit: u64,

    // ====== TLS & Security ======
    
    /// Whether to verify peer TLS certificate
    #[serde(default = "default_true")]
    pub verify_peer: bool,
    
    /// Path to custom CA certificate file for peer verification
    /// Uses PEM format. If not set, system default CA store is used.
    #[serde(default)]
    pub ca_cert_file: Option<String>,
    
    /// Path to custom CA certificate directory for peer verification
    /// Directory should contain PEM-encoded CA certificates with hashed filenames.
    #[serde(default)]
    pub ca_cert_dir: Option<String>,
    
    /// Session ticket for resumption (not serialized)
    #[serde(skip)]
    pub session_ticket: Option<Vec<u8>>,
    
    /// Enable TLS key logging for debugging (SSLKEYLOGFILE)
    #[serde(default)]
    pub log_keys: bool,
    
    /// Stateless reset token (16 bytes, not serialized)
    #[serde(skip)]
    pub stateless_reset_token: Option<[u8; 16]>,

    // ====== Congestion Control Tuning ======
    
    /// Initial congestion window in packets
    #[serde(default = "default_initial_cwnd")]
    pub initial_congestion_window_packets: usize,
    
    /// Enable HyStart++ slow start algorithm
    #[serde(default = "default_true")]
    pub enable_hystart: bool,
    
    /// Max pacing rate in bytes/sec (None = unlimited)
    #[serde(default)]
    pub max_pacing_rate: Option<u64>,
    
    /// Max amplification factor for anti-amplification (RFC 9000 §8.1)
    #[serde(default = "default_amplification_factor")]
    pub max_amplification_factor: usize,

    // ====== Advanced Features ======
    
    /// Enable PMTU discovery (RFC 9000 §14)
    #[serde(default)]
    pub discover_pmtu: bool,
    
    /// Enable GREASE (RFC 9000 §21)
    #[serde(default = "default_true")]
    pub grease: bool,
    
    /// Disable DCID reuse across paths
    #[serde(default)]
    pub disable_dcid_reuse: bool,
    
    /// Maximum DATAGRAM receive queue length
    #[serde(default = "default_dgram_queue_len")]
    pub dgram_recv_max_queue_len: usize,
    
    /// Maximum DATAGRAM send queue length
    #[serde(default = "default_dgram_queue_len")]
    pub dgram_send_max_queue_len: usize,
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

fn default_ack_delay_exponent() -> u64 {
    DEFAULT_ACK_DELAY_EXPONENT
}

fn default_max_ack_delay() -> u64 {
    DEFAULT_MAX_ACK_DELAY
}

fn default_active_cid_limit() -> u64 {
    DEFAULT_ACTIVE_CID_LIMIT
}

fn default_initial_cwnd() -> usize {
    DEFAULT_INITIAL_CWND_PACKETS
}

fn default_amplification_factor() -> usize {
    DEFAULT_AMPLIFICATION_FACTOR
}

fn default_dgram_queue_len() -> usize {
    1000
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
            ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            max_ack_delay: DEFAULT_MAX_ACK_DELAY,
            active_connection_id_limit: DEFAULT_ACTIVE_CID_LIMIT,
            verify_peer: true,
            ca_cert_file: None,
            ca_cert_dir: None,
            session_ticket: None,
            log_keys: false,
            stateless_reset_token: None,
            initial_congestion_window_packets: DEFAULT_INITIAL_CWND_PACKETS,
            enable_hystart: true,
            max_pacing_rate: None,
            max_amplification_factor: DEFAULT_AMPLIFICATION_FACTOR,
            discover_pmtu: false,
            grease: true,
            disable_dcid_reuse: false,
            dgram_recv_max_queue_len: 1000,
            dgram_send_max_queue_len: 1000,
        }
    }
}

impl QuicTransportConfig {
    /// Create a new builder for configuring QUIC transport parameters.
    ///
    /// Starts with sensible defaults and allows applications to customize
    /// specific parameters via the builder pattern.
    ///
    /// # Example
    ///
    /// ```rust
    /// use quicd_x::QuicTransportConfig;
    ///
    /// let config = QuicTransportConfig::builder()
    ///     .max_idle_timeout_ms(60_000)
    ///     .max_streams_bidi(200)
    ///     .enable_early_data(true)
    ///     .congestion_control(quicd_x::CongestionControl::Bbr)
    ///     .build()
    ///     .expect("valid config");
    /// ```
    pub fn builder() -> QuicTransportConfigBuilder {
        QuicTransportConfigBuilder::default()
    }

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

        // Validate transport parameters (RFC 9000 §18.2)
        if self.ack_delay_exponent > 20 {
            return Err("ack_delay_exponent must be <= 20 (RFC 9000 §18.2)".to_string());
        }

        if self.max_ack_delay > 16384 {
            return Err("max_ack_delay must be <= 16384ms (2^14, RFC 9000 §18.2)".to_string());
        }

        if self.active_connection_id_limit < 2 {
            return Err("active_connection_id_limit must be >= 2 (RFC 9000 §18.2)".to_string());
        }

        // Validate congestion control parameters
        if self.initial_congestion_window_packets == 0 {
            return Err("initial_congestion_window_packets must be > 0".to_string());
        }

        if self.max_amplification_factor < 3 {
            return Err(
                "max_amplification_factor must be >= 3 (RFC 9000 §8.1 anti-amplification)"
                    .to_string(),
            );
        }

        // Validate datagram queue lengths
        if self.dgram_recv_max_queue_len == 0 {
            return Err("dgram_recv_max_queue_len must be > 0".to_string());
        }

        if self.dgram_send_max_queue_len == 0 {
            return Err("dgram_send_max_queue_len must be > 0".to_string());
        }

        Ok(())
    }

    /// Get the congestion control algorithm
    pub fn congestion_control_algorithm(&self) -> CongestionControl {
        self.congestion_control
    }
}

/// Builder for constructing QuicTransportConfig with custom parameters.
///
/// Provides a fluent API for configuring QUIC transport parameters.
/// All methods are optional - sensible defaults are used for unset values.
///
/// # Example
///
/// ```rust
/// use quicd_x::{QuicTransportConfig, CongestionControl};
///
/// let config = QuicTransportConfig::builder()
///     .max_idle_timeout_ms(120_000)
///     .max_streams_bidi(500)
///     .recv_window(20 * 1024 * 1024)
///     .congestion_control(CongestionControl::Bbr2)
///     .enable_dgram(true)
///     .grease(true)
///     .build()
///     .expect("valid configuration");
/// ```
#[derive(Debug, Clone, Default)]
pub struct QuicTransportConfigBuilder {
    inner: QuicTransportConfig,
}

impl QuicTransportConfigBuilder {
    /// Set maximum idle timeout in milliseconds (RFC 9000 §10).
    ///
    /// Connection will be closed if no packets are received for this duration.
    /// Minimum: 1ms, typical: 30s-60s, long-lived: 120s+
    pub fn max_idle_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.inner.max_idle_timeout_ms = timeout_ms;
        self
    }

    /// Set initial RTT estimate in milliseconds.
    ///
    /// Used before actual RTT measurements are available.
    /// Default: 100ms, low-latency: 50ms, high-latency: 200ms+
    pub fn initial_rtt_ms(mut self, rtt_ms: u64) -> Self {
        self.inner.initial_rtt_ms = rtt_ms;
        self
    }

    /// Set maximum concurrent bidirectional streams (RFC 9000 §4.6).
    ///
    /// Controls peer's stream opening limit via STREAMS_BLOCKED frame.
    pub fn max_streams_bidi(mut self, count: u64) -> Self {
        self.inner.max_streams_bidi = count;
        self
    }

    /// Set maximum concurrent unidirectional streams (RFC 9000 §4.6).
    pub fn max_streams_uni(mut self, count: u64) -> Self {
        self.inner.max_streams_uni = count;
        self
    }

    /// Set maximum UDP payload size in bytes.
    ///
    /// Must be >= 1200 (QUIC minimum) and <= path MTU to avoid fragmentation.
    /// Default: 1350 (safe for IPv4), jumbo frames: 9000+
    pub fn max_udp_payload_size(mut self, size: usize) -> Self {
        self.inner.max_udp_payload_size = size;
        self
    }

    /// Set connection-level receive window (RFC 9000 §4.1).
    ///
    /// Total bytes peer can send across all streams. Controls MAX_DATA frame.
    /// Larger = better throughput, more memory. Default: 10MB
    pub fn recv_window(mut self, bytes: u64) -> Self {
        self.inner.recv_window = bytes;
        self
    }

    /// Set per-stream receive window (RFC 9000 §4.1).
    ///
    /// Bytes peer can send on each stream. Controls MAX_STREAM_DATA frame.
    /// Default: 1MB
    pub fn stream_recv_window(mut self, bytes: u64) -> Self {
        self.inner.stream_recv_window = bytes;
        self
    }

    /// Set congestion control algorithm.
    ///
    /// Options: Cubic (default), Reno, BBR, BBR2
    pub fn congestion_control(mut self, algorithm: CongestionControl) -> Self {
        self.inner.congestion_control = algorithm;
        self
    }

    /// Enable 0-RTT early data (RFC 9001 §4.6.1).
    ///
    /// ⚠️ Security implications: early data can be replayed by attackers.
    /// Only enable for idempotent operations.
    pub fn enable_early_data(mut self, enabled: bool) -> Self {
        self.inner.enable_early_data = enabled;
        self
    }

    /// Disable connection migration (RFC 9000 §9).
    ///
    /// If true, connection cannot change IP address or port.
    pub fn disable_active_migration(mut self, disabled: bool) -> Self {
        self.inner.disable_active_migration = disabled;
        self
    }

    /// Enable packet pacing.
    ///
    /// Spreads packet transmission to avoid bursts. Recommended: true
    pub fn enable_pacing(mut self, enabled: bool) -> Self {
        self.inner.enable_pacing = enabled;
        self
    }

    /// Enable DATAGRAM extension (RFC 9221).
    ///
    /// Allows sending unreliable, unordered datagrams over QUIC.
    /// Useful for: real-time media, game state, telemetry
    pub fn enable_dgram(mut self, enabled: bool) -> Self {
        self.inner.enable_dgram = enabled;
        self
    }

    /// Set maximum DATAGRAM frame size.
    ///
    /// Must be <= max_udp_payload_size - QUIC overhead.
    pub fn max_dgram_size(mut self, size: usize) -> Self {
        self.inner.max_dgram_size = size;
        self
    }

    /// Set ACK delay exponent (RFC 9000 §18.2).
    ///
    /// Used in ACK Delay field encoding. Valid range: 0-20, default: 3
    pub fn ack_delay_exponent(mut self, exponent: u64) -> Self {
        self.inner.ack_delay_exponent = exponent;
        self
    }

    /// Set maximum ACK delay in milliseconds (RFC 9000 §18.2).
    ///
    /// Maximum time to delay sending ACK. Valid range: 0-16384ms, default: 25ms
    pub fn max_ack_delay(mut self, delay_ms: u64) -> Self {
        self.inner.max_ack_delay = delay_ms;
        self
    }

    /// Set active connection ID limit (RFC 9000 §5.1.1).
    ///
    /// Number of connection IDs peer can use simultaneously. Min: 2, default: 2
    pub fn active_connection_id_limit(mut self, limit: u64) -> Self {
        self.inner.active_connection_id_limit = limit;
        self
    }

    /// Enable peer certificate verification (TLS).
    ///
    /// Default: true (recommended for security)
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.inner.verify_peer = verify;
        self
    }

    /// Set custom CA certificate file path (PEM format).
    ///
    /// Used for peer certificate verification.
    pub fn ca_cert_file(mut self, path: String) -> Self {
        self.inner.ca_cert_file = Some(path);
        self
    }

    /// Set custom CA certificate directory.
    ///
    /// Directory with hashed PEM certificates for peer verification.
    pub fn ca_cert_dir(mut self, path: String) -> Self {
        self.inner.ca_cert_dir = Some(path);
        self
    }

    /// Set initial congestion window in packets.
    ///
    /// Starting point for congestion control. Default: 10 packets
    pub fn initial_congestion_window_packets(mut self, packets: usize) -> Self {
        self.inner.initial_congestion_window_packets = packets;
        self
    }

    /// Enable HyStart++ slow start algorithm.
    ///
    /// Improves slow start performance. Default: true
    pub fn enable_hystart(mut self, enabled: bool) -> Self {
        self.inner.enable_hystart = enabled;
        self
    }

    /// Set maximum pacing rate in bytes per second.
    ///
    /// Limits send rate even when congestion window allows more. None = unlimited
    pub fn max_pacing_rate(mut self, rate_bps: Option<u64>) -> Self {
        self.inner.max_pacing_rate = rate_bps;
        self
    }

    /// Set maximum amplification factor (RFC 9000 §8.1).
    ///
    /// Anti-amplification attack protection. Min: 3, default: 3
    pub fn max_amplification_factor(mut self, factor: usize) -> Self {
        self.inner.max_amplification_factor = factor;
        self
    }

    /// Enable PMTU discovery (RFC 9000 §14).
    ///
    /// Automatically discovers path MTU to optimize packet size.
    pub fn discover_pmtu(mut self, enabled: bool) -> Self {
        self.inner.discover_pmtu = enabled;
        self
    }

    /// Enable GREASE (RFC 9000 §21).
    ///
    /// Sends random reserved values to test protocol extensibility. Default: true
    pub fn grease(mut self, enabled: bool) -> Self {
        self.inner.grease = enabled;
        self
    }

    /// Disable DCID reuse across network paths.
    ///
    /// Each path gets unique destination connection ID.
    pub fn disable_dcid_reuse(mut self, disabled: bool) -> Self {
        self.inner.disable_dcid_reuse = disabled;
        self
    }

    /// Set maximum DATAGRAM receive queue length.
    ///
    /// Number of received datagrams to buffer. Default: 1000
    pub fn dgram_recv_max_queue_len(mut self, len: usize) -> Self {
        self.inner.dgram_recv_max_queue_len = len;
        self
    }

    /// Set maximum DATAGRAM send queue length.
    ///
    /// Number of outgoing datagrams to buffer. Default: 1000
    pub fn dgram_send_max_queue_len(mut self, len: usize) -> Self {
        self.inner.dgram_send_max_queue_len = len;
        self
    }

    /// Enable connection statistics collection.
    ///
    /// When enabled, collects RTT, cwnd, packet loss, etc. Slight overhead.
    /// Default: true
    pub fn enable_stats(mut self, enabled: bool) -> Self {
        self.inner.enable_stats = enabled;
        self
    }

    /// Build the configuration, validating all parameters.
    ///
    /// Returns an error if any parameter is invalid (e.g., out of RFC-defined ranges).
    pub fn build(self) -> Result<QuicTransportConfig, String> {
        self.inner.validate()?;
        Ok(self.inner)
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

    #[test]
    fn test_ack_delay_exponent_defaults() {
        let config = QuicTransportConfig::default();
        assert_eq!(config.ack_delay_exponent, 3);
    }

    #[test]
    fn test_active_connection_id_limit_defaults() {
        let config = QuicTransportConfig::default();
        assert_eq!(config.active_connection_id_limit, 2);
    }

    #[test]
    fn test_stateless_reset_token_optional() {
        let config = QuicTransportConfig::default();
        assert!(config.stateless_reset_token.is_none());
    }

    #[test]
    fn test_ca_cert_paths_optional() {
        let config = QuicTransportConfig::default();
        assert!(config.ca_cert_file.is_none());
        assert!(config.ca_cert_dir.is_none());
    }

    #[test]
    fn test_hystart_enabled_by_default() {
        let config = QuicTransportConfig::default();
        assert!(config.enable_hystart);
    }

    #[test]
    fn test_pacing_enabled_by_default() {
        let config = QuicTransportConfig::default();
        assert!(config.enable_pacing);
    }

    #[test]
    fn test_pmtu_discovery_disabled_by_default() {
        let config = QuicTransportConfig::default();
        assert!(!config.discover_pmtu);
    }

    #[test]
    fn test_grease_enabled_by_default() {
        let config = QuicTransportConfig::default();
        assert!(config.grease);
    }

    #[test]
    fn test_dcid_reuse_enabled_by_default() {
        let config = QuicTransportConfig::default();
        assert!(!config.disable_dcid_reuse);
    }
}
