//! QUIC protocol configuration.
//!
//! Configuration for the QUIC layer including:
//! - Transport parameters
//! - Congestion control algorithm
//! - Connection limits and timeouts
//! - TLS/crypto settings

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

impl From<CongestionControl> for quiche::CongestionControlAlgorithm {
    fn from(cc: CongestionControl) -> Self {
        match cc {
            CongestionControl::Bbr => quiche::CongestionControlAlgorithm::BBR,
            CongestionControl::Bbr2 => quiche::CongestionControlAlgorithm::BBR2,
            CongestionControl::Cubic => quiche::CongestionControlAlgorithm::CUBIC,
            CongestionControl::Reno => quiche::CongestionControlAlgorithm::Reno,
        }
    }
}

/// QUIC protocol configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuicConfig {
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

    /// Path to TLS certificate file (PEM format)
    /// If not provided, uses self-signed certificate
    pub cert_path: Option<String>,

    /// Path to TLS private key file (PEM format)
    /// If not provided, uses self-signed certificate
    pub key_path: Option<String>,

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

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: DEFAULT_MAX_IDLE_TIMEOUT_MS,
            initial_rtt_ms: DEFAULT_INITIAL_RTT_MS,
            max_streams_bidi: DEFAULT_MAX_STREAMS_BIDI,
            max_streams_uni: DEFAULT_MAX_STREAMS_UNI,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            recv_window: DEFAULT_RECV_WINDOW,
            stream_recv_window: DEFAULT_STREAM_RECV_WINDOW,
            congestion_control: CongestionControl::default(),
            enable_early_data: false,
            disable_active_migration: false,
            enable_pacing: true,
            max_connections_per_worker: DEFAULT_MAX_CONNECTIONS_PER_WORKER,
            cert_path: Some(String::from("certs/cert.pem")),
            key_path: Some(String::from("certs/key.pem")),
            enable_version_negotiation: true,
            additional_versions: Vec::new(),
            enable_dgram: false,
            max_dgram_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            enable_stats: true,
        }
    }
}

impl QuicConfig {
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
}
