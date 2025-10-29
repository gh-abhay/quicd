use serde::{Deserialize, Serialize};

/// Telemetry configuration for observability
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// OTLP collector endpoint (e.g., "http://localhost:4317")
    pub otlp_endpoint: String,
    /// Service name for telemetry identification
    pub service_name: String,
    /// Enable metrics export (default: true)
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
    /// Enable tracing export (default: false, for future use)
    #[serde(default)]
    pub enable_tracing: bool,
    /// Metrics export interval in seconds (default: 60)
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
