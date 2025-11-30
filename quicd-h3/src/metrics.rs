//! HTTP/3 metrics and telemetry.
//!
//! This module provides metrics collection for HTTP/3 protocol operations,
//! designed for minimal overhead and production observability.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// HTTP/3 session metrics.
///
/// Tracks key performance indicators and operational metrics for monitoring
/// and debugging HTTP/3 sessions. All counters use relaxed atomic ordering
/// for minimal overhead in hot paths.
///
/// # Performance
/// - Atomic operations with Relaxed ordering for sub-nanosecond overhead
/// - No allocations in metric recording paths
/// - Lock-free concurrent updates from multiple streams
#[derive(Debug, Default)]
pub struct H3Metrics {
    // ========== Request/Response Metrics ==========
    /// Total number of HTTP/3 requests received
    pub requests_received: AtomicU64,
    
    /// Total number of HTTP/3 responses sent
    pub responses_sent: AtomicU64,
    
    /// Number of requests currently being processed
    pub requests_in_flight: AtomicUsize,
    
    /// Total number of requests completed successfully
    pub requests_completed: AtomicU64,
    
    /// Total number of requests that resulted in errors
    pub requests_failed: AtomicU64,
    
    // ========== Data Transfer Metrics ==========
    /// Total bytes received in request bodies (DATA frames)
    pub request_bytes_received: AtomicU64,
    
    /// Total bytes sent in response bodies (DATA frames)
    pub response_bytes_sent: AtomicU64,
    
    /// Total bytes in HEADERS frames received (encoded)
    pub header_bytes_received: AtomicU64,
    
    /// Total bytes in HEADERS frames sent (encoded)
    pub header_bytes_sent: AtomicU64,
    
    // ========== QPACK Metrics ==========
    /// Number of header field sections encoded with QPACK
    pub qpack_encodes: AtomicU64,
    
    /// Number of header field sections decoded with QPACK
    pub qpack_decodes: AtomicU64,
    
    /// Total uncompressed header bytes (sum of name.len() + value.len() for all headers)
    pub qpack_uncompressed_bytes: AtomicU64,
    
    /// Total compressed header bytes (QPACK encoded size)
    pub qpack_compressed_bytes: AtomicU64,
    
    /// Number of dynamic table insertions
    pub qpack_dynamic_inserts: AtomicU64,
    
    /// Number of streams blocked on QPACK dynamic table
    pub qpack_streams_blocked: AtomicU64,
    
    /// Number of streams that were blocked and then unblocked
    pub qpack_streams_unblocked: AtomicU64,
    
    /// Number of Section Acknowledgments sent
    pub qpack_section_acks_sent: AtomicU64,
    
    /// Number of Stream Cancellations sent
    pub qpack_stream_cancellations_sent: AtomicU64,
    
    // ========== Frame Metrics ==========
    /// Count of DATA frames received
    pub frames_data_received: AtomicU64,
    
    /// Count of HEADERS frames received
    pub frames_headers_received: AtomicU64,
    
    /// Count of PRIORITY frames received (RFC 9218)
    pub frames_priority_received: AtomicU64,
    
    /// Count of PRIORITY_UPDATE frames received (RFC 9218)
    pub frames_priority_update_received: AtomicU64,
    
    /// Count of SETTINGS frames received
    pub frames_settings_received: AtomicU64,
    
    /// Count of GOAWAY frames received
    pub frames_goaway_received: AtomicU64,
    
    /// Count of CANCEL_PUSH frames received
    pub frames_cancel_push_received: AtomicU64,
    
    /// Count of MAX_PUSH_ID frames received
    pub frames_max_push_id_received: AtomicU64,
    
    /// Count of PUSH_PROMISE frames sent (server push)
    pub frames_push_promise_sent: AtomicU64,
    
    /// Count of DUPLICATE_PUSH frames received
    pub frames_duplicate_push_received: AtomicU64,
    
    /// Count of reserved/unknown frames received (for greasing)
    pub frames_reserved_received: AtomicU64,
    
    /// Count of reserved frames received (RFC 9114 Section 7.2.8 greasing)
    pub reserved_frames_received: AtomicU64,
    
    /// Count of completely unknown frame types received
    pub unknown_frames_received: AtomicU64,
    
    /// Count of trailer HEADERS received (trailers section)
    pub trailer_bytes_received: AtomicU64,
    
    /// Count of HTTP/3 datagrams received
    pub datagrams_received: AtomicU64,
    
    // ========== Stream Metrics ==========
    /// Number of bidirectional request streams opened
    pub streams_request_opened: AtomicU64,
    
    /// Number of request streams closed normally
    pub streams_request_closed: AtomicU64,
    
    /// Number of request streams reset with error
    pub streams_request_reset: AtomicU64,
    
    /// Number of unidirectional control streams opened
    pub streams_control_opened: AtomicU64,
    
    /// Number of QPACK encoder streams opened
    pub streams_qpack_encoder_opened: AtomicU64,
    
    /// Number of QPACK decoder streams opened
    pub streams_qpack_decoder_opened: AtomicU64,
    
    /// Number of server push streams opened
    pub streams_push_opened: AtomicU64,
    
    /// Number of reserved streams received (RFC 9114 Section 6.2.3 greasing)
    pub reserved_streams_received: AtomicU64,
    
    /// Number of unknown stream types received
    pub unknown_streams_received: AtomicU64,
    
    // ========== Error Metrics ==========
    /// Frame parsing errors (malformed frames)
    pub errors_frame_parse: AtomicU64,
    
    /// QPACK decompression errors
    pub errors_qpack_decompression: AtomicU64,
    
    /// HTTP message validation errors (invalid headers, etc.)
    pub errors_message_validation: AtomicU64,
    
    /// Connection-level protocol errors
    pub errors_connection: AtomicU64,
    
    /// Stream-level errors
    pub errors_stream: AtomicU64,
    
    /// Content-Length validation errors
    pub errors_content_length_mismatch: AtomicU64,
    
    // ========== Server Push Metrics ==========
    /// Number of push promises sent
    pub push_promises_sent: AtomicU64,
    
    /// Number of pushes cancelled by client
    pub push_cancelled: AtomicU64,
    
    /// Number of push responses completed
    pub push_completed: AtomicU64,
    
    // ========== Connection Lifecycle ==========
    /// Number of GOAWAY frames sent
    pub goaway_sent: AtomicU64,
    
    /// Timestamp when connection was established (milliseconds since epoch)
    pub connection_start_time_ms: AtomicU64,
    
    /// Number of times the connection has drained and reconnected
    pub connection_drains: AtomicU64,
}

impl H3Metrics {
    /// Create a new metrics instance.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    
    /// Record a request received.
    #[inline]
    pub fn record_request_received(&self) {
        self.requests_received.fetch_add(1, Ordering::Relaxed);
        self.requests_in_flight.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record a response sent.
    #[inline]
    pub fn record_response_sent(&self) {
        self.responses_sent.fetch_add(1, Ordering::Relaxed);
        self.requests_in_flight.fetch_sub(1, Ordering::Relaxed);
    }
    
    /// Record a request completion (success or failure).
    #[inline]
    pub fn record_request_completed(&self, success: bool) {
        if success {
            self.requests_completed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Record QPACK encoding operation.
    #[inline]
    pub fn record_qpack_encode(&self, uncompressed_bytes: usize, compressed_bytes: usize) {
        self.qpack_encodes.fetch_add(1, Ordering::Relaxed);
        self.qpack_uncompressed_bytes.fetch_add(uncompressed_bytes as u64, Ordering::Relaxed);
        self.qpack_compressed_bytes.fetch_add(compressed_bytes as u64, Ordering::Relaxed);
    }
    
    /// Record QPACK decoding operation.
    #[inline]
    pub fn record_qpack_decode(&self, uncompressed_bytes: usize, compressed_bytes: usize) {
        self.qpack_decodes.fetch_add(1, Ordering::Relaxed);
        self.qpack_uncompressed_bytes.fetch_add(uncompressed_bytes as u64, Ordering::Relaxed);
        self.qpack_compressed_bytes.fetch_add(compressed_bytes as u64, Ordering::Relaxed);
    }
    
    /// Calculate QPACK compression ratio (compressed / uncompressed).
    /// Returns None if no data has been compressed yet.
    pub fn qpack_compression_ratio(&self) -> Option<f64> {
        let uncompressed = self.qpack_uncompressed_bytes.load(Ordering::Relaxed);
        if uncompressed == 0 {
            return None;
        }
        let compressed = self.qpack_compressed_bytes.load(Ordering::Relaxed);
        Some(compressed as f64 / uncompressed as f64)
    }
    
    /// Get current number of requests in flight.
    #[inline]
    pub fn requests_in_flight(&self) -> usize {
        self.requests_in_flight.load(Ordering::Relaxed)
    }
    
    /// Snapshot metrics for logging or export.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_received: self.requests_received.load(Ordering::Relaxed),
            responses_sent: self.responses_sent.load(Ordering::Relaxed),
            requests_in_flight: self.requests_in_flight.load(Ordering::Relaxed),
            requests_completed: self.requests_completed.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            request_bytes_received: self.request_bytes_received.load(Ordering::Relaxed),
            response_bytes_sent: self.response_bytes_sent.load(Ordering::Relaxed),
            qpack_compression_ratio: self.qpack_compression_ratio(),
            qpack_streams_blocked: self.qpack_streams_blocked.load(Ordering::Relaxed),
            errors_total: self.errors_frame_parse.load(Ordering::Relaxed)
                + self.errors_qpack_decompression.load(Ordering::Relaxed)
                + self.errors_message_validation.load(Ordering::Relaxed)
                + self.errors_connection.load(Ordering::Relaxed)
                + self.errors_stream.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of metrics.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub requests_received: u64,
    pub responses_sent: u64,
    pub requests_in_flight: usize,
    pub requests_completed: u64,
    pub requests_failed: u64,
    pub request_bytes_received: u64,
    pub response_bytes_sent: u64,
    pub qpack_compression_ratio: Option<f64>,
    pub qpack_streams_blocked: u64,
    pub errors_total: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "H3Metrics{{ requests: {}/{} in_flight: {} completed: {} failed: {} \
             rx_bytes: {} tx_bytes: {} qpack_ratio: {:.2}% blocked_streams: {} errors: {} }}",
            self.requests_received,
            self.responses_sent,
            self.requests_in_flight,
            self.requests_completed,
            self.requests_failed,
            self.request_bytes_received,
            self.response_bytes_sent,
            self.qpack_compression_ratio.map(|r| r * 100.0).unwrap_or(0.0),
            self.qpack_streams_blocked,
            self.errors_total,
        )
    }
}
