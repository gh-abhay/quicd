use serde::{Deserialize, Serialize};

/// Telemetry configuration for observability.
///
/// Configures metrics and tracing export via OpenTelemetry Protocol (OTLP).
/// Metrics are exported to an OTLP collector (e.g., Jaeger, Prometheus, Grafana).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// OTLP collector endpoint (e.g., "http://localhost:4317").
    ///
    /// The endpoint where metrics and traces are exported.
    /// Must be an HTTP or HTTPS URL.
    pub otlp_endpoint: String,

    /// Service name for telemetry identification.
    ///
    /// This name appears in telemetry dashboards and helps identify
    /// metrics from this service instance.
    pub service_name: String,

    /// Enable metrics export (default: true).
    ///
    /// When enabled, the server exports performance metrics including:
    /// - Connection counts
    /// - Packet statistics
    /// - Stream metrics
    /// - Error rates
    #[serde(default = "default_true")]
    pub enable_metrics: bool,

    /// Enable tracing export (default: false, for future use).
    ///
    /// Distributed tracing support is planned for future releases.
    #[serde(default)]
    pub enable_tracing: bool,

    /// Metrics export interval in seconds (default: 60).
    ///
    /// How often metrics are exported to the OTLP collector.
    /// Lower values provide more real-time data but increase overhead.
    #[serde(default = "default_export_interval")]
    pub export_interval_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_export_interval() -> u64 {
    60
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "quicd".to_string(),
            enable_metrics: true,
            enable_tracing: false,
            export_interval_secs: 60,
        }
    }
}
