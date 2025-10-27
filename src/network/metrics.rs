//! # Network Layer Metrics
//!
//! This module provides thread-safe metrics collection for the network layer.
//! It uses event-driven updates to avoid allocations in hot paths while providing
//! comprehensive observability for network operations.
//!
//! ## Features
//!
//! - **Event-Driven Updates**: Non-blocking metrics recording
//! - **Thread-Safe**: Safe for concurrent access from multiple threads
//! - **Zero Allocation**: Pre-allocated events in hot paths
//! - **Comprehensive Coverage**: Packets, bytes, errors, and performance
//!
//! ## Usage
//!
//! ```rust
//! use superd::network::metrics::NetworkMetrics;
//!
//! let metrics = NetworkMetrics::new();
//!
//! // Record packet reception (non-blocking)
//! metrics.record_packet_received(1500);
//!
//! // Record send error
//! metrics.record_send_error();
//!
//! // Get current snapshot for monitoring
//! let snapshot = metrics.snapshot();
//! println!("Packets received: {}", snapshot.packets_received);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Thread-safe network metrics using atomic counters
/// This provides fast, lock-free updates for high-performance networking
#[derive(Debug)]
pub struct NetworkMetrics {
    /// Total packets received
    packets_received: AtomicU64,
    /// Total packets sent
    packets_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Network receive errors
    receive_errors: AtomicU64,
    /// Network send errors
    send_errors: AtomicU64,
    /// Channel send errors (when metrics channel is full)
    channel_send_errors: AtomicU64,
    /// Channel full errors
    channel_full_errors: AtomicU64,
    /// Start time for uptime calculations
    start_time: Instant,
}

impl NetworkMetrics {
    /// Create new network metrics
    pub fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            receive_errors: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            channel_send_errors: AtomicU64::new(0),
            channel_full_errors: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Record a received packet
    #[inline]
    pub fn record_packet_received(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);

        // Send event to global metrics if available
        if let Some(_metrics) = unsafe { crate::telemetry::GLOBAL_METRICS.as_ref() } {
            crate::telemetry::record_event(crate::telemetry::MetricsEvent::PacketReceived { bytes });
        }
    }

    /// Record a sent packet
    #[inline]
    pub fn record_packet_sent(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);

        // Send event to global metrics if available
        if let Some(_metrics) = unsafe { crate::telemetry::GLOBAL_METRICS.as_ref() } {
            crate::telemetry::record_event(crate::telemetry::MetricsEvent::PacketSent { bytes });
        }
    }

    /// Record a network receive error
    #[inline]
    pub fn record_receive_error(&self) {
        self.receive_errors.fetch_add(1, Ordering::Relaxed);

        // Send event to global metrics if available
        if let Some(_metrics) = unsafe { crate::telemetry::GLOBAL_METRICS.as_ref() } {
            crate::telemetry::record_event(crate::telemetry::MetricsEvent::NetworkReceiveError);
        }
    }

    /// Record a network send error
    #[inline]
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);

        // Send event to global metrics if available
        if let Some(_metrics) = unsafe { crate::telemetry::GLOBAL_METRICS.as_ref() } {
            crate::telemetry::record_event(crate::telemetry::MetricsEvent::NetworkSendError);
        }
    }

    /// Record a channel send error
    #[inline]
    pub fn record_channel_send_error(&self) {
        self.channel_send_errors.fetch_add(1, Ordering::Relaxed);

        // Send event to global metrics if available
        if let Some(_metrics) = unsafe { crate::telemetry::GLOBAL_METRICS.as_ref() } {
            crate::telemetry::record_event(crate::telemetry::MetricsEvent::ChannelSendError);
        }
    }

    /// Record a channel full error
    #[inline]
    pub fn record_channel_full(&self) {
        self.channel_full_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics values
    pub fn snapshot(&self) -> MetricsSnapshot {
        let uptime = self.start_time.elapsed();
        let uptime_secs = uptime.as_secs_f64();

        let packets_rx = self.packets_received.load(Ordering::Relaxed);
        let bytes_rx = self.bytes_received.load(Ordering::Relaxed);
        let packets_tx = self.packets_sent.load(Ordering::Relaxed);
        let bytes_tx = self.bytes_sent.load(Ordering::Relaxed);

        MetricsSnapshot {
            packets_received: packets_rx,
            bytes_received: bytes_rx,
            packets_sent: packets_tx,
            bytes_sent: bytes_tx,
            receive_errors: self.receive_errors.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            channel_send_errors: self.channel_send_errors.load(Ordering::Relaxed),
            channel_full_errors: self.channel_full_errors.load(Ordering::Relaxed),
            uptime,
            rx_pps: (packets_rx as f64 / uptime_secs) as u64,
            rx_throughput_mbps: (bytes_rx as f64 * 8.0 / uptime_secs / 1_000_000.0),
            tx_pps: (packets_tx as f64 / uptime_secs) as u64,
            tx_throughput_mbps: (bytes_tx as f64 * 8.0 / uptime_secs / 1_000_000.0),
        }
    }
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricsSnapshot {
    /// Total packets received
    pub packets_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Network receive errors
    pub receive_errors: u64,
    /// Network send errors
    pub send_errors: u64,
    /// Channel send errors
    pub channel_send_errors: u64,
    /// Channel full errors
    pub channel_full_errors: u64,
    /// Server uptime
    pub uptime: std::time::Duration,
    /// Receive packets per second
    pub rx_pps: u64,
    /// Receive throughput in Mbps
    pub rx_throughput_mbps: f64,
    /// Send packets per second
    pub tx_pps: u64,
    /// Send throughput in Mbps
    pub tx_throughput_mbps: f64,
}

impl MetricsSnapshot {
    /// Calculate packets per second over a time interval
    pub fn packets_per_second(&self, duration_secs: f64) -> f64 {
        (self.packets_received + self.packets_sent) as f64 / duration_secs
    }

    /// Calculate bytes per second over a time interval
    pub fn bytes_per_second(&self, duration_secs: f64) -> f64 {
        (self.bytes_received + self.bytes_sent) as f64 / duration_secs
    }

    /// Calculate error rate as percentage
    pub fn error_rate_percent(&self) -> f64 {
        let total_packets = self.packets_received + self.packets_sent;
        if total_packets == 0 {
            0.0
        } else {
            (self.receive_errors + self.send_errors) as f64 / total_packets as f64 * 100.0
        }
    }
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RX: {:.2}Mpps {:.2}Mbps ({} pkts, {} bytes, {} errs) | \
             TX: {:.2}Mpps {:.2}Mbps ({} pkts, {} bytes, {} errs) | \
             Channel: {} send_errs {} full | Uptime: {:.2}s",
            self.rx_pps as f64 / 1_000_000.0,
            self.rx_throughput_mbps,
            self.packets_received,
            self.bytes_received,
            self.receive_errors,
            self.tx_pps as f64 / 1_000_000.0,
            self.tx_throughput_mbps,
            self.packets_sent,
            self.bytes_sent,
            self.send_errors,
            self.channel_send_errors,
            self.channel_full_errors,
            self.uptime.as_secs_f64()
        )
    }
}

/// Shared network metrics for concurrent access
pub type SharedMetrics = Arc<NetworkMetrics>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_metrics() {
        let metrics = NetworkMetrics::new();

        // Record some activity
        metrics.record_packet_received(100);
        metrics.record_packet_received(200);
        metrics.record_packet_sent(150);
        metrics.record_receive_error();
        metrics.record_send_error();

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.packets_received, 2);
        assert_eq!(snapshot.packets_sent, 1);
        assert_eq!(snapshot.bytes_received, 300);
        assert_eq!(snapshot.bytes_sent, 150);
        assert_eq!(snapshot.receive_errors, 1);
        assert_eq!(snapshot.send_errors, 1);
    }

    #[test]
    fn test_metrics_snapshot_calculations() {
        let snapshot = MetricsSnapshot {
            packets_received: 100,
            packets_sent: 50,
            bytes_received: 15000,
            bytes_sent: 7500,
            receive_errors: 2,
            send_errors: 1,
            channel_send_errors: 0,
            channel_full_errors: 0,
            uptime: std::time::Duration::from_secs(2),
            rx_pps: 50,
            rx_throughput_mbps: 60.0,
            tx_pps: 25,
            tx_throughput_mbps: 30.0,
        };

        assert_eq!(snapshot.packets_per_second(2.0), 75.0);
        assert_eq!(snapshot.bytes_per_second(2.0), 11250.0);
        assert_eq!(snapshot.error_rate_percent(), 2.0); // 3 errors out of 150 packets
    }
}
