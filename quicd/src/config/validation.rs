//! Configuration validation utilities.
//!
//! This module provides comprehensive validation logic for configuration
//! values, including cross-field validation and sanity checks.

use super::ServerConfig;

/// Configuration validator trait.
pub trait ConfigValidator {
    /// Validate the configuration.
    ///
    /// Returns `Ok(())` if valid, or a list of error messages if invalid.
    fn validate(&self) -> Result<(), Vec<String>>;
}

/// Validate resource limits make sense together.
///
/// This performs cross-configuration validation to ensure that
/// various limits and capacities are consistent with each other.
pub fn validate_resource_limits(config: &ServerConfig) -> Result<(), Vec<String>> {
    let mut warnings = Vec::new();

    // Check if channel capacities are reasonable for the number of workers
    let worker_count = config.global.netio.workers;
    let egress_capacity = config.global.channels.worker_egress_capacity;

    if egress_capacity < worker_count * 100 {
        warnings.push(format!(
            "worker_egress_capacity ({}) may be too small for {} workers. \
             Consider at least {} (100 per worker)",
            egress_capacity,
            worker_count,
            worker_count * 100
        ));
    }

    // Check if max_streams * stream_buffer can fit in memory
    // let max_streams = config.global.quic.max_streams_bidi;
    // let stream_buffer = config.global.channels.stream_ingress_capacity;
    // let estimated_memory_mb = (max_streams * stream_buffer as u64 * 64 * 1024) / (1024 * 1024);

    // if estimated_memory_mb > 1024 {
    //     warnings.push(format!(
    //         "Warning: max_streams_bidi ({}) * stream_ingress_capacity ({}) \
    //          may use ~{}MB per connection. Consider reducing these values.",
    //         max_streams, stream_buffer, estimated_memory_mb
    //     ));
    // }

    // Check if runtime worker threads vs network workers makes sense
    let runtime_workers = config.global.runtime.worker_threads;
    if runtime_workers < worker_count {
        warnings.push(format!(
            "runtime.worker_threads ({}) is less than netio.workers ({}). \
             This may cause contention. Consider equal or more runtime workers.",
            runtime_workers, worker_count
        ));
    }

    if warnings.is_empty() {
        Ok(())
    } else {
        // These are warnings, not errors - log them but don't fail
        for warning in &warnings {
            tracing::warn!("{}", warning);
        }
        Ok(())
    }
}

