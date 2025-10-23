/// Network layer metrics for observability
/// Tracks packets, bytes, errors, and performance metrics

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug)]
pub struct NetworkMetrics {
    // Receive metrics
    pub packets_received: AtomicU64,
    pub bytes_received: AtomicU64,
    pub receive_errors: AtomicU64,
    
    // Send metrics
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub send_errors: AtomicU64,
    
    // Channel metrics
    pub channel_send_errors: AtomicU64,
    pub channel_full_errors: AtomicU64,
    
    // Timing
    start_time: Instant,
}

impl NetworkMetrics {
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

    #[inline]
    pub fn record_packet_received(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_packet_sent(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_receive_error(&self) {
        self.receive_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_channel_send_error(&self) {
        self.channel_send_errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_channel_full(&self) {
        self.channel_full_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
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

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub receive_errors: u64,
    pub send_errors: u64,
    pub channel_send_errors: u64,
    pub channel_full_errors: u64,
    pub uptime: std::time::Duration,
    pub rx_pps: u64,
    pub rx_throughput_mbps: f64,
    pub tx_pps: u64,
    pub tx_throughput_mbps: f64,
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

/// Thread-local metrics aggregated globally
pub type SharedMetrics = Arc<NetworkMetrics>;
