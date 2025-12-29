//! Channel configuration for message passing between workers and applications.
//!
//! This module defines the capacity configurations for various channels used
//! throughout the system. Proper channel sizing is critical for:
//! - Preventing deadlocks (channels too small)
//! - Avoiding excessive memory usage (channels too large)
//! - Maintaining low latency (bounded backpressure)
//! - Supporting high throughput (sufficient buffering)

use serde::{Deserialize, Serialize};

/// Channel capacity configuration.
///
/// All capacities are expressed as the number of messages that can be buffered.
/// These values affect memory usage and backpressure behavior.
///
/// # Tuning Guidelines
///
/// - **Egress channels** (app → worker): Size based on expected burst writes
///   from apps. Too small = apps get backpressure, too large = excessive memory.
///
/// - **Ingress channels** (worker → app): Size based on app processing speed.
///   Too small = data loss, too large = head-of-line blocking.
///
/// - **Stream channels**: Per-stream overhead, multiply by max concurrent streams.
///   Each active stream has both ingress and egress channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Capacity of worker egress channel (app tasks → worker).
    ///
    /// This channel receives commands from all app tasks on a worker.
    /// Must be large enough to handle bursts from all connections.
    ///
    /// Default: 2048 (supports ~1000 connections with occasional bursts)
    #[serde(default = "default_worker_egress_capacity")]
    pub worker_egress_capacity: usize,

    /// Capacity of connection ingress channel (worker → app task).
    ///
    /// This channel sends events to a single app task for one connection.
    /// Size affects how much the worker can buffer before backpressure.
    ///
    /// Default: 1024 (supports bursts of events for one connection)
    #[serde(default = "default_connection_ingress_capacity")]
    pub connection_ingress_capacity: usize,

    /// Capacity of stream ingress channel (worker → app).
    ///
    /// Per-stream channel for sending data chunks to the app.
    /// Multiplied by number of concurrent streams per connection.
    ///
    /// Default: 256 (supports ~16MB buffered at 64KB chunks)
    #[serde(default = "default_stream_ingress_capacity")]
    pub stream_ingress_capacity: usize,

    /// Capacity of stream egress channel (app → worker).
    ///
    /// Per-stream channel for receiving write commands from the app.
    /// Backpressure here prevents apps from overwhelming the worker.
    ///
    /// Default: 256 (supports burst writes on a single stream)
    #[serde(default = "default_stream_egress_capacity")]
    pub stream_egress_capacity: usize,
}

fn default_worker_egress_capacity() -> usize {
    2048
}

fn default_connection_ingress_capacity() -> usize {
    1024
}

fn default_stream_ingress_capacity() -> usize {
    256
}

fn default_stream_egress_capacity() -> usize {
    256
}

impl Default for ChannelConfig {
    fn default() -> Self {
        // Default values without querying system resources
        Self {
            worker_egress_capacity: 256,
            connection_ingress_capacity: 128,
            stream_ingress_capacity: 64,
            stream_egress_capacity: 64,
        }
    }
}

impl ChannelConfig {
    /// Validate channel configuration.
    ///
    /// Ensures all capacities are reasonable and won't cause issues.
    pub fn validate(&self) -> Result<(), String> {
        if self.worker_egress_capacity < 64 {
            return Err("worker_egress_capacity must be at least 64".to_string());
        }
        if self.connection_ingress_capacity < 32 {
            return Err("connection_ingress_capacity must be at least 32".to_string());
        }
        if self.stream_ingress_capacity < 16 {
            return Err("stream_ingress_capacity must be at least 16".to_string());
        }
        if self.stream_egress_capacity < 16 {
            return Err("stream_egress_capacity must be at least 16".to_string());
        }

        // Warn if values are excessively large (likely misconfiguration)
        if self.worker_egress_capacity > 100_000 {
            tracing::warn!(
                capacity = self.worker_egress_capacity,
                "worker_egress_capacity is very large, may use excessive memory"
            );
        }
        if self.connection_ingress_capacity > 10_000 {
            tracing::warn!(
                capacity = self.connection_ingress_capacity,
                "connection_ingress_capacity is very large, may use excessive memory"
            );
        }

        Ok(())
    }

    /// Estimate memory usage per connection.
    ///
    /// Returns rough estimate in bytes for channel overhead per connection.
    /// Does not include the actual message payloads, just channel structures.
    pub fn estimate_memory_per_connection(&self, avg_streams: usize) -> usize {
        // Estimate ~100 bytes per channel slot (rough approximation for internal structures)
        const BYTES_PER_SLOT: usize = 100;

        // Connection ingress channel
        let conn_ingress = self.connection_ingress_capacity * BYTES_PER_SLOT;

        // Stream channels (both directions)
        let stream_channels = avg_streams
            * (self.stream_ingress_capacity + self.stream_egress_capacity)
            * BYTES_PER_SLOT;

        conn_ingress + stream_channels
    }
}
