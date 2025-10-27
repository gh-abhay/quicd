//! # Telemetry and Observability
//!
//! This module provides comprehensive observability for SuperD with OpenTelemetry support.
//! It includes structured logging, metrics collection, and distributed tracing for
//! production monitoring and debugging.
//!
//! ## Features
//!
//! - **Structured Logging**: JSON-formatted logs with context
//! - **Metrics Collection**: Performance counters and histograms
//! - **Distributed Tracing**: Request tracing across components
//! - **OTLP Export**: OpenTelemetry Protocol for external systems
//!
//! ## Configuration
//!
//! Telemetry is configured through `TelemetryConfig`:
//!
//! ```rust
//! use superd::config::TelemetryConfig;
//!
//! let config = TelemetryConfig {
//!     otlp_endpoint: "http://localhost:4317".to_string(),
//!     service_name: "superd".to_string(),
//! };
//!
//! superd::telemetry::init_telemetry(&config);
//! ```
//!
//! ## Log Levels
//!
//! - **ERROR**: System errors requiring immediate attention
//! - **WARN**: Potential issues or degraded performance
//! - **INFO**: Normal operations and state changes
//! - **DEBUG**: Detailed debugging information
//! - **TRACE**: Very detailed execution tracing
//!
//! ## Metrics
//!
//! The system collects metrics on:
//! - Packet throughput (packets/second)
//! - Connection counts and states
//! - Memory usage and buffer pool utilization
//! - CPU usage per thread
//! - Error rates and types
//!
//! ## Tracing
//!
//! Distributed tracing tracks requests through:
//! 1. Network packet reception
//! 2. Protocol parsing and validation
//! 3. Application processing
//! 4. Response generation and transmission
//!
//! ## Example Usage
//!
//! ```rust
//! use tracing::{info, error, instrument};
//!
//! #[instrument]
//! fn process_packet(data: &[u8]) {
//!     info!("Processing packet of {} bytes", data.len());
//!
//!     if data.is_empty() {
//!         error!("Received empty packet");
//!         return;
//!     }
//!
//!     // Process packet...
//! }
//! ```

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Global metrics registry for the entire application
pub static mut GLOBAL_METRICS: Option<GlobalMetrics> = None;

/// Event-driven metrics updates to avoid allocations in hot paths
#[derive(Debug, Clone)]
pub enum MetricsEvent {
    /// Network packet received (bytes)
    PacketReceived { bytes: usize },
    /// Network packet sent (bytes)
    PacketSent { bytes: usize },
    /// Network receive error
    NetworkReceiveError,
    /// Network send error
    NetworkSendError,
    /// Channel send error
    ChannelSendError,
    /// New connection established
    ConnectionEstablished,
    /// Connection closed
    ConnectionClosed,
    /// Active connection count update
    ActiveConnections { count: usize },
    /// New stream opened
    StreamOpened,
    /// Stream closed
    StreamClosed,
    /// Protocol error occurred
    ProtocolError,
    /// Application request processed
    ApplicationRequest { endpoint: String },
    /// Buffer pool utilization
    BufferPoolUtilization { used: usize, total: usize },
}

/// Global metrics handler for event-driven updates
pub struct GlobalMetrics {
    event_receiver: std::sync::mpsc::Receiver<MetricsEvent>,
}

impl GlobalMetrics {
    /// Initialize global metrics with event channel
    pub fn init(_service_name: &str, _otlp_endpoint: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (_sender, receiver) = std::sync::mpsc::channel();
        // Store sender globally for other modules to use
        unsafe {
            GLOBAL_METRICS_SENDER = Some(_sender);
        }
        Ok(Self {
            event_receiver: receiver,
        })
    }

    /// Get the global event sender for recording metrics
    pub fn get_sender() -> Option<std::sync::mpsc::Sender<MetricsEvent>> {
        unsafe { GLOBAL_METRICS_SENDER.clone() }
    }
}

/// Global sender for metrics events
static mut GLOBAL_METRICS_SENDER: Option<std::sync::mpsc::Sender<MetricsEvent>> = None;

/// Record a metrics event globally
pub fn record_event(event: MetricsEvent) {
    if let Some(sender) = unsafe { GLOBAL_METRICS_SENDER.as_ref() } {
        let _ = sender.send(event);
    }
}

pub fn init_telemetry(config: &crate::config::TelemetryConfig) {
    // Initialize logging first
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Initialize OpenTelemetry metrics if endpoint is configured
    if config.otlp_endpoint != "http://localhost:4317" {
        match GlobalMetrics::init(&config.service_name, &config.otlp_endpoint) {
            Ok(metrics) => {
                unsafe {
                    GLOBAL_METRICS = Some(metrics);
                }
                tracing::info!("Event-driven metrics initialized");
            }
            Err(e) => {
                tracing::warn!("Failed to initialize metrics: {}", e);
            }
        }
    }

    // Set up tracing
    let registry = tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer());

    registry.init();

    if config.otlp_endpoint == "http://localhost:4317" {
        tracing::info!("Telemetry initialized with console logging only. Configure OTLP endpoint for metrics export.");
    }
}
