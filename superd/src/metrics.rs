//! Performance metrics and monitoring
//!
//! This module provides comprehensive metrics collection for monitoring
//! the daemon's performance in production environments.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Thread-safe performance metrics
///
/// Uses atomic operations for lock-free updates from multiple tasks.
/// Inspired by Cloudflare's metrics architecture for minimal overhead.
#[derive(Debug)]
pub struct Metrics {
    /// Total packets received from network
    packets_received: AtomicU64,
    
    /// Total packets sent to network
    packets_sent: AtomicU64,
    
    /// Total bytes received
    bytes_received: AtomicU64,
    
    /// Total bytes sent
    bytes_sent: AtomicU64,
    
    /// Total connections accepted
    connections_accepted: AtomicU64,
    
    /// Total connections closed
    connections_closed: AtomicU64,
    
    /// Total number of errors encountered
    errors: AtomicU64,
    
    /// Start time for calculating uptime and throughput
    start_time: Instant,
}

impl Metrics {
    /// Create a new metrics instance
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_closed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: Instant::now(),
        })
    }
    
    /// Record a received packet
    #[inline]
    pub fn record_packet_received(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }
    
    /// Record a sent packet
    #[inline]
    pub fn record_packet_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }
    
    /// Record a new connection
    #[inline]
    pub fn record_connection_accepted(&self) {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record a closed connection
    #[inline]
    pub fn record_connection_closed(&self) {
        self.connections_closed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record an error
    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get current throughput in Mbps
    pub fn throughput_mbps(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let total_bytes = self.bytes_received.load(Ordering::Relaxed) 
                + self.bytes_sent.load(Ordering::Relaxed);
            (total_bytes as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        }
    }
    
    /// Get current packet rate (packets per second)
    pub fn packet_rate(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let total_packets = self.packets_received.load(Ordering::Relaxed) 
                + self.packets_sent.load(Ordering::Relaxed);
            total_packets as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get number of active connections
    pub fn active_connections(&self) -> u64 {
        self.connections_accepted.load(Ordering::Relaxed) 
            - self.connections_closed.load(Ordering::Relaxed)
    }
    
    /// Log current statistics
    pub fn log_stats(&self) {
        let packets_rx = self.packets_received.load(Ordering::Relaxed);
        let packets_tx = self.packets_sent.load(Ordering::Relaxed);
        let bytes_rx = self.bytes_received.load(Ordering::Relaxed);
        let bytes_tx = self.bytes_sent.load(Ordering::Relaxed);
        let connections = self.active_connections();
        let errors = self.errors.load(Ordering::Relaxed);
        
        log::info!(
            "Performance: {:.2} Mbps | {:.0} pkt/s | Packets: {}/{} (rx/tx) | Bytes: {}/{} | Connections: {} | Errors: {}",
            self.throughput_mbps(),
            self.packet_rate(),
            packets_rx,
            packets_tx,
            bytes_rx,
            bytes_tx,
            connections,
            errors
        );
    }
    
    /// Get a snapshot of all metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_closed: self.connections_closed.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs(),
            throughput_mbps: self.throughput_mbps(),
            packet_rate: self.packet_rate(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_closed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

/// Immutable snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub connections_accepted: u64,
    pub connections_closed: u64,
    pub errors: u64,
    pub uptime_secs: u64,
    pub throughput_mbps: f64,
    pub packet_rate: f64,
}
