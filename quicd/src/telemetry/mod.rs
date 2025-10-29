//! # Telemetry and Observability
//!
//! This module provides comprehensive observability for quicd with OpenTelemetry support.
//! It includes structured logging and event-driven metrics collection optimized for
//! high-throughput, low-latency network servers.
//!
//! ## Features
//!
//! - **Structured Logging**: JSON-formatted logs with minimal overhead
//! - **Event-Driven Metrics**: Fire-and-forget metrics recording via mpsc channel
//! - **OTLP Export**: OpenTelemetry Protocol for external collectors
//! - **Zero-Copy Metrics**: Minimal allocations in hot paths
//!
//! ## Architecture
//!
//! The telemetry system uses an event-driven architecture to minimize performance impact:
//!
//! 1. **Hot Path (packet processing)**: Fire-and-forget metric events via channel
//! 2. **Metrics Task**: Dedicated tokio task aggregates and exports to OTLP
//! 3. **Logging**: Critical errors only, no per-packet logging
//!
//! ## Usage
//!
//! ```rust
//! use quicd::telemetry::{init_telemetry, record_metric, MetricsEvent};
//!
//! // Initialize telemetry at startup
//! init_telemetry(&config.telemetry).await?;
//!
//! // Record metrics in hot paths (fire-and-forget)
//! record_metric(MetricsEvent::PacketReceived { bytes: 1200 });
//! ```

pub mod config;
pub mod metrics;

pub use config::TelemetryConfig;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[allow(unused_imports)] // MetricsTimer used by protocol layer
pub use metrics::{record_metric, start_metrics_task, MetricsEvent, MetricsHandle, MetricsTimer};

/// Initialize telemetry system with logging and optional OTLP export
///
/// This sets up:
/// - Structured logging with configurable levels
/// - Event-driven metrics collection
/// - OTLP export if endpoint is configured
///
/// # Arguments
///
/// * `config` - Telemetry configuration
/// * `runtime_handle` - Tokio runtime handle for spawning tasks
///
/// # Returns
///
/// Handle to the metrics task for graceful shutdown
pub async fn init_telemetry(
    config: &TelemetryConfig,
    runtime_handle: &tokio::runtime::Handle,
) -> Result<MetricsHandle> {
    // Initialize logging
    init_logging(&config.service_name)?;

    // Initialize metrics
    let metrics_handle = if config.enable_metrics {
        tracing::info!(
            service = %config.service_name,
            endpoint = %config.otlp_endpoint,
            interval_secs = config.export_interval_secs,
            "Starting event-driven metrics system"
        );
        start_metrics_task(config, runtime_handle).await?
    } else {
        tracing::warn!("Metrics collection is disabled");
        MetricsHandle::disabled()
    };

    tracing::info!("Telemetry system initialized");
    Ok(metrics_handle)
}

/// Initialize structured logging
fn init_logging(service_name: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_line_number(true)
        .with_file(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    tracing::info!(service = %service_name, "Logging initialized");
    Ok(())
}
