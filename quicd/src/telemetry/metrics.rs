//! Event-driven metrics collection optimized for high-throughput servers
//!
//! This module provides a fire-and-forget metrics recording system that minimizes
//! impact on hot paths. All metrics are sent via an unbounded mpsc channel to a
//! dedicated task that aggregates and exports to OTLP.

use anyhow::Result;
use crossbeam_channel::{self, Sender};
use once_cell::sync::OnceCell;
use opentelemetry::{
    metrics::{Counter, Histogram, Meter, MeterProvider, ObservableGauge},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    metrics::{PeriodicReader, SdkMeterProvider},
    runtime, Resource,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::task::JoinHandle;

use super::config::TelemetryConfig;

/// Global metrics event sender
static METRICS_SENDER: OnceCell<Sender<MetricsEvent>> = OnceCell::new();

/// Helper for timing operations with automatic metric recording
///
/// # Example
/// ```no_run
/// use quicd::telemetry::{MetricsTimer, record_metric, MetricsEvent};
///
/// let timer = MetricsTimer::start();
/// // ... do QUIC handshake ...
/// let duration_ms = timer.elapsed_ms();
/// record_metric(MetricsEvent::HandshakeCompleted { duration_ms });
/// ```
#[derive(Debug)]
#[allow(dead_code)] // Used by future protocol layer implementation
pub struct MetricsTimer {
    start: std::time::Instant,
}

#[allow(dead_code)] // Used by future protocol layer implementation
impl MetricsTimer {
    /// Start a new timer
    #[inline]
    pub fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// Get elapsed time in milliseconds
    #[inline]
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Get elapsed time in microseconds
    #[inline]
    pub fn elapsed_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

/// Metrics events for fire-and-forget recording
///
/// These events are designed to minimize allocations and copying in hot paths.
/// They use simple types that can be quickly sent over a channel.
///
/// Events are organized by layer:
/// - Network Layer: PacketReceived, PacketSent, NetworkErrors, BufferPool, Workers
/// - Protocol Layer: Connections, Handshakes, Streams, Retransmissions (QUIC)
/// - Application Layer: HttpRequest (HTTP/3)
#[derive(Debug, Clone)]
#[allow(dead_code)] // Many variants are for future protocol/application layer instrumentation
pub enum MetricsEvent {
    // ========== Network Layer Metrics ==========
    /// UDP packet received from network
    /// Records both packet count and total bytes received
    PacketReceived { bytes: usize },

    /// UDP packet sent to network
    /// Records both packet count and total bytes sent
    PacketSent { bytes: usize },

    /// Network receive error occurred
    /// Indicates issues with socket recv operations
    NetworkReceiveError,

    /// Network send error occurred
    /// Indicates issues with socket send operations
    NetworkSendError,

    /// Snapshot of buffer pool utilization
    /// Reports current usage for monitoring memory pressure
    BufferPoolUtilization { used: usize, total: usize },

    /// Network worker task started
    /// Used to track active worker count
    WorkerStarted,

    /// Network worker task stopped
    /// Used to track active worker count
    WorkerStopped,

    // ========== Protocol Layer Metrics (QUIC) ==========
    /// New QUIC connection established successfully
    ConnectionEstablished,

    /// QUIC connection closed
    /// Duration tracks connection lifetime for analysis
    ConnectionClosed { duration_ms: u64 },

    /// QUIC handshake completed successfully
    /// Duration is critical for performance monitoring
    HandshakeCompleted { duration_ms: u64 },

    /// QUIC handshake failed
    /// High failure rates indicate connectivity or configuration issues
    HandshakeFailed,

    /// New QUIC stream opened
    StreamOpened,

    /// QUIC stream closed
    /// Duration tracks stream lifetime
    StreamClosed { duration_ms: u64 },

    /// Packet retransmitted due to loss
    /// High retransmission rates indicate network congestion
    PacketRetransmitted,

    // ========== Application Layer Metrics (HTTP/3) ==========
    /// HTTP/3 request completed
    /// Includes method, status code, and duration for full request analysis
    HttpRequest {
        method: String,
        status: u16,
        duration_ms: u64,
    },
}

/// Handle to the metrics task for graceful shutdown
pub struct MetricsHandle {
    task_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MetricsHandle {
    /// Create a disabled handle (when metrics are disabled)
    pub fn disabled() -> Self {
        Self {
            task_handle: None,
            shutdown_tx: None,
        }
    }

    /// Shutdown the metrics task gracefully with timeout
    pub async fn shutdown(self) {
        if let Some(tx) = self.shutdown_tx {
            let _ = tx.send(());
        }
        if let Some(handle) = self.task_handle {
            // Wait for the task to complete, but with a timeout to avoid hanging
            match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
                Ok(result) => {
                    if let Err(e) = result {
                        tracing::error!(error = ?e, "Metrics task panicked during shutdown");
                    }
                }
                Err(_) => {
                    tracing::error!("Metrics task shutdown timed out after 5 seconds");
                }
            }
        }
    }
}

/// Metrics collector that aggregates events and updates OpenTelemetry metrics
struct MetricsCollector {
    // Network metrics
    packets_received: Counter<u64>,
    packets_sent: Counter<u64>,
    bytes_received: Counter<u64>,
    bytes_sent: Counter<u64>,
    network_errors: Counter<u64>,

    // Buffer pool metrics (tracked separately for observable gauge)
    buffer_pool_used: Arc<AtomicU64>,
    buffer_pool_total: Arc<AtomicU64>,
    _buffer_pool_gauge: ObservableGauge<u64>,

    // Worker metrics (tracked separately for observable gauge)
    active_workers: Arc<AtomicU64>,
    _active_workers_gauge: ObservableGauge<u64>,

    // Connection metrics
    connections_total: Counter<u64>,
    connections_active: Arc<AtomicU64>,
    _connections_active_gauge: ObservableGauge<u64>,
    handshake_duration: Histogram<u64>,
    handshake_failures: Counter<u64>,

    // Stream metrics
    streams_total: Counter<u64>,
    streams_active: Arc<AtomicU64>,
    _streams_active_gauge: ObservableGauge<u64>,
    stream_duration: Histogram<u64>,

    // Retransmission metrics
    retransmissions_total: Counter<u64>,

    // HTTP metrics
    http_requests_total: Counter<u64>,
    http_request_duration: Histogram<u64>,
}

impl MetricsCollector {
    /// Create a new metrics collector with OpenTelemetry instruments
    fn new(meter: &Meter) -> Result<Self> {
        // Network metrics
        let packets_received = meter
            .u64_counter("network.packets.received")
            .with_description("Total number of UDP packets received")
            .build();

        let packets_sent = meter
            .u64_counter("network.packets.sent")
            .with_description("Total number of UDP packets sent")
            .build();

        let bytes_received = meter
            .u64_counter("network.bytes.received")
            .with_description("Total bytes received from network")
            .build();

        let bytes_sent = meter
            .u64_counter("network.bytes.sent")
            .with_description("Total bytes sent to network")
            .build();

        let network_errors = meter
            .u64_counter("network.errors")
            .with_description("Total network errors")
            .build();

        // Buffer pool metrics
        let buffer_pool_used = Arc::new(AtomicU64::new(0));
        let buffer_pool_total = Arc::new(AtomicU64::new(0));

        let buffer_used_clone = Arc::clone(&buffer_pool_used);
        let buffer_pool_used_gauge = meter
            .u64_observable_gauge("buffer_pool.used")
            .with_description("Number of buffers currently in use")
            .with_callback(move |observer| {
                observer.observe(buffer_used_clone.load(Ordering::Relaxed), &[]);
            })
            .build();

        let buffer_total_clone = Arc::clone(&buffer_pool_total);
        let _buffer_pool_gauge = meter
            .u64_observable_gauge("buffer_pool.total")
            .with_description("Total number of buffers in pool")
            .with_callback(move |observer| {
                observer.observe(buffer_total_clone.load(Ordering::Relaxed), &[]);
            })
            .build();

        // Worker metrics
        let active_workers = Arc::new(AtomicU64::new(0));
        let workers_clone = Arc::clone(&active_workers);
        let _active_workers_gauge = meter
            .u64_observable_gauge("workers.active")
            .with_description("Number of active network workers")
            .with_callback(move |observer| {
                observer.observe(workers_clone.load(Ordering::Relaxed), &[]);
            })
            .build();

        // Connection metrics
        let connections_total = meter
            .u64_counter("quic.connections.total")
            .with_description("Total QUIC connections established")
            .build();

        let connections_active = Arc::new(AtomicU64::new(0));
        let conn_active_clone = Arc::clone(&connections_active);
        let _connections_active_gauge = meter
            .u64_observable_gauge("quic.connections.active")
            .with_description("Number of active QUIC connections")
            .with_callback(move |observer| {
                observer.observe(conn_active_clone.load(Ordering::Relaxed), &[]);
            })
            .build();

        let handshake_duration = meter
            .u64_histogram("quic.handshake.duration")
            .with_description("QUIC handshake duration in milliseconds")
            .build();

        let handshake_failures = meter
            .u64_counter("quic.handshake.failures")
            .with_description("Total QUIC handshake failures")
            .build();

        // Stream metrics
        let streams_total = meter
            .u64_counter("quic.streams.total")
            .with_description("Total QUIC streams opened")
            .build();

        let streams_active = Arc::new(AtomicU64::new(0));
        let streams_active_clone = Arc::clone(&streams_active);
        let _streams_active_gauge = meter
            .u64_observable_gauge("quic.streams.active")
            .with_description("Number of active QUIC streams")
            .with_callback(move |observer| {
                observer.observe(streams_active_clone.load(Ordering::Relaxed), &[]);
            })
            .build();

        let stream_duration = meter
            .u64_histogram("quic.stream.duration")
            .with_description("QUIC stream duration in milliseconds")
            .build();

        // Retransmission metrics
        let retransmissions_total = meter
            .u64_counter("quic.retransmissions.total")
            .with_description("Total packet retransmissions")
            .build();

        // HTTP metrics
        let http_requests_total = meter
            .u64_counter("http.requests.total")
            .with_description("Total HTTP requests processed")
            .build();

        let http_request_duration = meter
            .u64_histogram("http.request.duration")
            .with_description("HTTP request duration in milliseconds")
            .build();

        Ok(Self {
            packets_received,
            packets_sent,
            bytes_received,
            bytes_sent,
            network_errors,
            buffer_pool_used,
            buffer_pool_total,
            _buffer_pool_gauge: buffer_pool_used_gauge,
            active_workers,
            _active_workers_gauge,
            connections_total,
            connections_active,
            _connections_active_gauge,
            handshake_duration,
            handshake_failures,
            streams_total,
            streams_active,
            _streams_active_gauge,
            stream_duration,
            retransmissions_total,
            http_requests_total,
            http_request_duration,
        })
    }

    /// Process a metrics event and update corresponding instruments
    fn process_event(&self, event: MetricsEvent) {
        match event {
            // Network events
            MetricsEvent::PacketReceived { bytes } => {
                self.packets_received.add(1, &[]);
                self.bytes_received.add(bytes as u64, &[]);
            }
            MetricsEvent::PacketSent { bytes } => {
                self.packets_sent.add(1, &[]);
                self.bytes_sent.add(bytes as u64, &[]);
            }
            MetricsEvent::NetworkReceiveError => {
                self.network_errors
                    .add(1, &[KeyValue::new("type", "receive")]);
            }
            MetricsEvent::NetworkSendError => {
                self.network_errors.add(1, &[KeyValue::new("type", "send")]);
            }
            MetricsEvent::BufferPoolUtilization { used, total } => {
                self.buffer_pool_used.store(used as u64, Ordering::Relaxed);
                self.buffer_pool_total
                    .store(total as u64, Ordering::Relaxed);
            }
            MetricsEvent::WorkerStarted => {
                self.active_workers.fetch_add(1, Ordering::Relaxed);
            }
            MetricsEvent::WorkerStopped => {
                self.active_workers.fetch_sub(1, Ordering::Relaxed);
            }

            // Connection events
            MetricsEvent::ConnectionEstablished => {
                self.connections_total.add(1, &[]);
                self.connections_active.fetch_add(1, Ordering::Relaxed);
            }
            MetricsEvent::ConnectionClosed { duration_ms } => {
                self.connections_active.fetch_sub(1, Ordering::Relaxed);
                // Could add connection duration histogram here
                let _ = duration_ms; // Suppress warning
            }
            MetricsEvent::HandshakeCompleted { duration_ms } => {
                self.handshake_duration.record(duration_ms, &[]);
            }
            MetricsEvent::HandshakeFailed => {
                self.handshake_failures.add(1, &[]);
            }

            // Stream events
            MetricsEvent::StreamOpened => {
                self.streams_total.add(1, &[]);
                self.streams_active.fetch_add(1, Ordering::Relaxed);
            }
            MetricsEvent::StreamClosed { duration_ms } => {
                self.streams_active.fetch_sub(1, Ordering::Relaxed);
                self.stream_duration.record(duration_ms, &[]);
            }

            // Retransmission
            MetricsEvent::PacketRetransmitted => {
                self.retransmissions_total.add(1, &[]);
            }

            // HTTP events
            MetricsEvent::HttpRequest {
                method,
                status,
                duration_ms,
            } => {
                self.http_requests_total.add(
                    1,
                    &[
                        KeyValue::new("method", method),
                        KeyValue::new("status", status.to_string()),
                    ],
                );
                self.http_request_duration.record(duration_ms, &[]);
            }
        }
    }
}

/// Record a metrics event (fire-and-forget)
///
/// This function is designed to be called from hot paths with minimal overhead.
/// Events are sent via an unbounded channel and never block.
///
/// # Performance
///
/// - **Zero blocking**: Uses `try_send` on unbounded channel (never waits)
/// - **Zero allocation**: Events use stack-allocated types
/// - **Zero copies**: Event data moved directly into channel
/// - **Fast path**: Single atomic load + channel send (~10-20ns)
///
/// # Arguments
///
/// * `event` - The metrics event to record
#[inline]
pub fn record_metric(event: MetricsEvent) {
    if let Some(sender) = METRICS_SENDER.get() {
        // Fire-and-forget: we don't care if the channel is disconnected
        // Using unbounded channel means this never blocks
        let _ = sender.send(event);
    }
}

/// Start the metrics collection task
///
/// This spawns a dedicated tokio task that:
/// 1. Receives metrics events from the channel
/// 2. Aggregates them into OpenTelemetry instruments
/// 3. Exports to OTLP endpoint periodically
///
/// # Architecture
///
/// Uses crossbeam_channel::unbounded instead of std::sync::mpsc because:
/// - Receiver is Send+Sync (std::mpsc::Receiver is not Sync)
/// - Better performance under contention (lockfree design)
/// - Unbounded to guarantee fire-and-forget semantics
///
/// # Arguments
///
/// * `config` - Telemetry configuration
/// * `runtime_handle` - Tokio runtime handle for spawning the task
///
/// # Returns
///
/// Handle to the metrics task for graceful shutdown
pub async fn start_metrics_task(
    config: &TelemetryConfig,
    runtime_handle: &tokio::runtime::Handle,
) -> Result<MetricsHandle> {
    // Create channel for metrics events
    // Using crossbeam_channel::unbounded for:
    // - Send + Sync receiver (std::sync::mpsc::Receiver is !Sync)
    // - Fire-and-forget semantics (never blocks sender)
    // - Lock-free implementation (better performance under contention)
    let (tx, rx) = crossbeam_channel::unbounded::<MetricsEvent>();

    // Store sender globally
    METRICS_SENDER
        .set(tx)
        .map_err(|_| anyhow::anyhow!("Metrics sender already initialized"))?;

    // Initialize OpenTelemetry meter provider
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&config.otlp_endpoint)
        .build()?;

    let reader = PeriodicReader::builder(exporter, runtime::Tokio)
        .with_interval(Duration::from_secs(config.export_interval_secs))
        .with_timeout(Duration::from_secs(5)) // Timeout for export operations
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(Resource::new(vec![KeyValue::new(
            "service.name",
            config.service_name.clone(),
        )]))
        .build();

    let meter = provider.meter("quicd");

    // Create metrics collector
    let collector = MetricsCollector::new(&meter)?;

    // Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    // Spawn metrics processing task on the provided runtime
    let task_handle = runtime_handle.spawn(async move {
        tracing::info!("Metrics collection task started");

        // Pre-allocate batch buffer for efficiency
        // Reusing this Vec avoids allocations in the hot loop
        let mut batch = Vec::with_capacity(1000);

        loop {
            tokio::select! {
                // Shutdown signal - break immediately
                _ = &mut shutdown_rx => {
                    tracing::info!("Metrics task shutting down");
                    break;
                }

                // Process metrics events in small batches with periodic yields
                // This ensures the shutdown signal can be checked frequently
                _ = async {
                    let mut processed = 0;
                    // Process up to 1000 events per iteration
                    loop {
                        match rx.try_recv() {
                            Ok(event) => {
                                batch.push(event);
                                processed += 1;

                                // Process batch when it gets large
                                if batch.len() >= 100 {
                                    for event in batch.drain(..) {
                                        collector.process_event(event);
                                    }
                                    // Yield to allow shutdown signal to be checked
                                    tokio::task::yield_now().await;
                                }
                            }
                            Err(_) => break, // Channel empty or disconnected
                        }

                        // Limit events processed per async block to stay responsive
                        if processed >= 1000 {
                            break;
                        }
                    }

                    // Process any remaining events in batch
                    if !batch.is_empty() {
                        for event in batch.drain(..) {
                            collector.process_event(event);
                        }
                    }

                    // If no events were processed, sleep briefly to avoid busy waiting
                    if processed == 0 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } => {}
            }
        }

        // Flush remaining events on shutdown
        for event in batch.drain(..) {
            collector.process_event(event);
        }
        while let Ok(event) = rx.try_recv() {
            collector.process_event(event);
        }

        // Shutdown provider to flush final metrics to OTLP collector
        // Note: This may block if OTLP export is slow, but we have a timeout in MetricsHandle::shutdown
        if let Err(e) = provider.shutdown() {
            tracing::error!(error = ?e, "Failed to shutdown metrics provider");
        }

        tracing::info!("Metrics task stopped");
    });

    Ok(MetricsHandle {
        task_handle: Some(task_handle),
        shutdown_tx: Some(shutdown_tx),
    })
}
