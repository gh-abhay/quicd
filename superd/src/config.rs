//! Configuration module for superd - Production-Ready Architecture
//!
//! This module implements the finalized three-layer architecture:
//! 1. Network I/O Threads: UDP socket recv/send operations
//! 2. QUIC Protocol Handlers: QUIC packet processing
//! 3. Connection Management: Tokio async tasks
//!
//! All settings follow production-proven patterns from Cloudflare, Kafka, and Discord.

use std::net::SocketAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};

// Re-export types from network crate for backwards compatibility
pub use network::{ThreadPriority, CpuAffinityStrategy};

/// Main configuration for superd daemon
///
/// # Architecture
///
/// This configuration implements a three-layer architecture optimized for
/// maximum throughput (1M+ pps) and maximum concurrent connections (100K+):
///
/// ```text
/// Layer 1: Network I/O Threads (pinned OS threads)
///          └─ UDP socket recv/send operations
/// Layer 2: QUIC Protocol Handlers (pinned OS threads)
///          └─ QUIC packet processing, crypto, state management
/// Layer 3: Connection Management (Tokio async tasks)
///          └─ Per-connection application logic
/// ```
///
/// # Performance Targets
///
/// - 100,000+ concurrent connections
/// - 1,000,000+ packets per second
/// - Sub-millisecond latency
/// - Zero packet loss under normal load
///
/// # Examples
///
/// ```no_run
/// use superd::Config;
///
/// // Auto-detect optimal settings
/// let config = Config::default();
///
/// // Custom settings
/// let mut config = Config::default();
/// config.network_io.threads = 4;
/// config.quic_protocol.threads = 4;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network I/O layer configuration
    pub network_io: NetworkIoConfig,
    
    /// QUIC protocol handler configuration
    pub quic_protocol: QuicProtocolConfig,
    
    /// Tokio runtime configuration
    pub tokio_runtime: TokioRuntimeConfig,
    
    /// Server configuration
    pub server: ServerConfig,
    
    /// Monitoring and metrics configuration
    pub monitoring: MonitoringConfig,
}

/// Network I/O layer configuration
///
/// Controls the threads responsible for UDP socket operations.
/// These threads are CPU-pinned, NUMA-aware, and use SO_REUSEPORT
/// for kernel-level load balancing.
///
/// # Performance Characteristics
///
/// - Per thread capacity: 500K pps (Cloudflare proven)
/// - CPU usage per thread: ~30% @ 500K pps
/// - Latency: <1µs (direct kernel path)
///
/// # Tuning Guide
///
/// - **1-4 cores**: 1 thread (sufficient for most workloads)
/// - **5-8 cores**: 2 threads (balanced)
/// - **9-16 cores**: 4 threads (high throughput)
/// - **17+ cores**: 8 threads (maximum, diminishing returns beyond)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIoConfig {
    /// Number of dedicated network I/O threads
    ///
    /// Default: Auto-detected (25% of CPUs, min=1, max=8)
    ///
    /// Each thread:
    /// - Binds to the same port using SO_REUSEPORT
    /// - Gets pinned to a specific CPU core
    /// - Runs a tight recv/send loop with single-threaded Tokio runtime
    ///
    /// Formula: `min(max(cpu_count / 4, 1), 8)`
    pub threads: usize,
    
    /// Enable CPU pinning for network I/O threads
    ///
    /// Default: true
    ///
    /// When enabled:
    /// - Each thread is pinned to a specific CPU core
    /// - Hot cache (L1/L2) for socket operations
    /// - Zero context switches during packet RX/TX
    /// - Predictable performance
    ///
    /// Disable only for:
    /// - Containerized environments without CPU affinity support
    /// - Testing/debugging
    pub enable_cpu_pinning: bool,
    
    /// Enable NUMA-aware thread placement
    ///
    /// Default: true (if system supports NUMA)
    ///
    /// When enabled:
    /// - Threads are placed on the same NUMA node as the NIC
    /// - Avoids 4x cross-NUMA memory access penalty
    /// - Critical for >1M pps throughput
    ///
    /// Automatically disabled on non-NUMA systems.
    pub enable_numa_awareness: bool,
    
    /// Thread priority
    ///
    /// Default: High
    ///
    /// Network I/O threads get high priority to minimize packet loss.
    /// They preempt other threads when packets arrive.
    pub thread_priority: ThreadPriority,
    
    /// CPU core affinity strategy
    ///
    /// Default: Interleaved
    ///
    /// - Interleaved: I/O on even cores (0,2,4...), QUIC on odd cores (1,3,5...)
    /// - Sequential: I/O on first N cores, QUIC on next N cores
    /// - Auto: System decides (no pinning)
    pub cpu_affinity_strategy: CpuAffinityStrategy,
}

/// QUIC protocol handler configuration
///
/// Controls the threads responsible for QUIC packet processing.
/// These threads read packets from channels, decrypt, parse, and
/// update connection state.
///
/// # Performance Characteristics
///
/// - Per thread capacity: 500K pps (matches I/O thread 1:1)
/// - CPU usage per thread: ~40-85% @ 500K pps (depends on crypto)
/// - Latency: 1-3µs per packet (QUIC processing)
///
/// # Architecture
///
/// Uses 1:1 mapping with network I/O threads:
/// ```text
/// I/O Thread 0 → Channel 0 → QUIC Handler 0
/// I/O Thread 1 → Channel 1 → QUIC Handler 1
/// ...
/// ```
///
/// This eliminates channel contention and provides predictable performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicProtocolConfig {
    /// Number of QUIC protocol handler threads
    ///
    /// Default: Auto-detected (equals network_io.threads)
    ///
    /// **Must equal network_io.threads for optimal performance.**
    ///
    /// Each handler:
    /// - Reads from a dedicated channel (1:1 with I/O thread)
    /// - Processes QUIC packets (decrypt, parse, state update)
    /// - Spawns Tokio tasks for connection management
    /// - Pinned to CPU core (interleaved with I/O thread)
    pub threads: usize,
    
    /// Enable CPU pinning for QUIC handlers
    ///
    /// Default: true
    ///
    /// When enabled:
    /// - Each handler is pinned to a specific CPU core
    /// - Placed adjacent to its corresponding I/O thread (cache locality)
    /// - Zero context switches during processing
    pub enable_cpu_pinning: bool,
    
    /// Thread priority
    ///
    /// Default: Normal (High for low-latency mode)
    ///
    /// QUIC handlers run at normal priority by default.
    /// For ultra-low latency (<100µs), use High priority.
    pub thread_priority: ThreadPriority,
    
    /// Channel buffer size per handler
    ///
    /// Default: 8192 packets
    ///
    /// Each I/O thread → QUIC handler pair has a dedicated channel.
    /// Larger buffers prevent backpressure during bursts.
    pub channel_buffer_size: usize,
}

/// Tokio runtime configuration
///
/// Controls the multi-threaded Tokio runtime that executes
/// connection management tasks (one task per connection).
///
/// # CPU Allocation Strategy
///
/// Two modes available:
///
/// ## Dedicated CPUs (Default, Conservative)
/// ```text
/// 8-core: 2 I/O + 2 QUIC + 4 Tokio (dedicated)
/// Workers only use CPUs 4-7 (no sharing with I/O/QUIC)
/// ```
/// - Safe: Zero cache pollution
/// - Predictable: No context switch interference
/// - Proven: Matches production systems
///
/// ## Shared CPUs (Experimental, Efficient)
/// ```text
/// 8-core: 2 I/O + 2 QUIC + 8 Tokio (shared)
/// Workers can use all CPUs (work-stealing)
/// ```
/// - Efficient: Uses idle CPU cycles from I/O/QUIC
/// - Requires: I/O+QUIC < 50% CPU usage (verify with profiling)
/// - Risky: Can cause cache pollution if I/O/QUIC > 75% CPU
///
/// **Recommendation:** Start with Dedicated, switch to Shared after profiling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokioRuntimeConfig {
    /// Number of Tokio worker threads
    ///
    /// Default: Auto-detected based on cpu_mode
    ///
    /// - Dedicated mode: `num_cpus - (io_threads + quic_threads)`
    /// - Shared mode: `num_cpus` (all CPUs)
    ///
    /// Set to `None` to use default, or specify explicit count.
    pub worker_threads: Option<usize>,
    
    /// CPU allocation mode
    ///
    /// Default: Dedicated (safe, predictable)
    ///
    /// - Dedicated: Tokio workers use only unpinned CPUs
    /// - Shared: Tokio workers can use all CPUs (work-stealing)
    ///
    /// After profiling, switch to Shared if I/O+QUIC < 50% CPU.
    pub cpu_mode: TokioCpuMode,
    
    /// Enable thread pinning for Tokio workers
    ///
    /// Default: false (let work-stealing scheduler decide)
    ///
    /// When enabled:
    /// - Each Tokio worker is pinned to a specific CPU
    /// - Reduces cache misses but prevents work-stealing benefits
    /// - Only useful for specialized workloads
    pub enable_cpu_pinning: bool,
    
    /// Thread stack size for Tokio workers
    ///
    /// Default: 2MB (Tokio default)
    ///
    /// Increase only if you see stack overflow errors.
    pub thread_stack_size: Option<usize>,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// UDP socket address to bind to
    pub listen_addr: SocketAddr,
    
    /// Maximum concurrent QUIC connections
    ///
    /// Default: 100,000
    ///
    /// Memory estimation:
    /// - Per connection: ~8.5 KB (8KB QUIC + 500B Tokio task)
    /// - 100K connections: ~850 MB
    /// - 1M connections: ~8.5 GB
    pub max_connections: usize,
    
    /// Socket receive buffer size (SO_RCVBUF)
    ///
    /// Default: 8 MB
    ///
    /// Cloudflare-proven large buffers prevent packet loss.
    /// Kernel allocates this much memory per socket.
    pub socket_recv_buffer_size: usize,
    
    /// Socket send buffer size (SO_SNDBUF)
    ///
    /// Default: 8 MB
    pub socket_send_buffer_size: usize,
    
    /// Enable SO_REUSEPORT
    ///
    /// Default: true
    ///
    /// Required for multi-threaded network I/O.
    /// Kernel load-balances incoming packets across threads.
    pub enable_reuseport: bool,
    
    /// Connection idle timeout
    ///
    /// Default: 30 seconds
    ///
    /// Connections without activity are closed after this duration.
    pub idle_timeout: Duration,
    
    /// Connection cleanup interval
    ///
    /// Default: 60 seconds
    ///
    /// How often to scan and prune stale connections.
    pub cleanup_interval: Duration,
}

/// Monitoring and metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable metrics collection
    ///
    /// Default: true
    pub enable_metrics: bool,
    
    /// Metrics logging interval
    ///
    /// Default: 10 seconds
    pub metrics_interval: Duration,
    
    /// Enable detailed debug logging
    ///
    /// Default: false
    ///
    /// Only enable for troubleshooting (impacts performance).
    pub debug_mode: bool,
    
    /// Enable performance profiling hooks
    ///
    /// Default: false
    ///
    /// Enables integration with perf, flamegraph, etc.
    pub enable_profiling: bool,
}

/// Tokio CPU allocation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokioCpuMode {
    /// Tokio workers use only CPUs not used by I/O/QUIC (safe, default)
    Dedicated,
    /// Tokio workers can use all CPUs via work-stealing (efficient, experimental)
    Shared,
}

impl Default for Config {
    fn default() -> Self {
        let cpu_count = num_cpus::get();
        let io_threads = Self::calculate_io_threads(cpu_count);
        let quic_threads = io_threads; // Always 1:1
        
        Self {
            network_io: NetworkIoConfig {
                threads: io_threads,
                enable_cpu_pinning: true,
                enable_numa_awareness: Self::is_numa_available(),
                thread_priority: ThreadPriority::High,
                cpu_affinity_strategy: CpuAffinityStrategy::Interleaved,
            },
            quic_protocol: QuicProtocolConfig {
                threads: quic_threads,
                enable_cpu_pinning: true,
                thread_priority: ThreadPriority::Normal,
                channel_buffer_size: 8192,
            },
            tokio_runtime: TokioRuntimeConfig {
                worker_threads: None, // Auto-detect based on cpu_mode
                cpu_mode: TokioCpuMode::Dedicated,
                enable_cpu_pinning: false,
                thread_stack_size: None,
            },
            server: ServerConfig {
                listen_addr: "0.0.0.0:4433".parse().unwrap(),
                max_connections: 100_000,
                socket_recv_buffer_size: 8 * 1024 * 1024, // 8 MB
                socket_send_buffer_size: 8 * 1024 * 1024, // 8 MB
                enable_reuseport: true,
                idle_timeout: Duration::from_secs(30),
                cleanup_interval: Duration::from_secs(60),
            },
            monitoring: MonitoringConfig {
                enable_metrics: true,
                metrics_interval: Duration::from_secs(10),
                debug_mode: false,
                enable_profiling: false,
            },
        }
    }
}

impl Config {
    /// Calculate optimal number of network I/O threads
    ///
    /// Formula: `min(max(cpu_count / 4, 1), 8)`
    ///
    /// Examples:
    /// - 1 core: 1 thread
    /// - 2-4 cores: 1 thread
    /// - 5-8 cores: 2 threads
    /// - 9-16 cores: 4 threads
    /// - 17-32 cores: 8 threads
    /// - 33+ cores: 8 threads (cap)
    fn calculate_io_threads(cpu_count: usize) -> usize {
        match cpu_count {
            1 => 1,
            2..=4 => 1,
            5..=8 => 2,
            9..=16 => 4,
            _ => 8,
        }
    }
    
    /// Calculate number of Tokio worker threads based on CPU mode
    pub fn tokio_worker_count(&self) -> usize {
        if let Some(count) = self.tokio_runtime.worker_threads {
            return count;
        }
        
        let cpu_count = num_cpus::get();
        match self.tokio_runtime.cpu_mode {
            TokioCpuMode::Dedicated => {
                // Use only unpinned CPUs
                let pinned = self.network_io.threads + self.quic_protocol.threads;
                cpu_count.saturating_sub(pinned).max(1)
            }
            TokioCpuMode::Shared => {
                // Use all CPUs (work-stealing)
                cpu_count
            }
        }
    }
    
    /// Check if NUMA is available on this system
    fn is_numa_available() -> bool {
        // TODO: Implement actual NUMA detection
        // For now, assume single-node systems
        false
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Network I/O validation
        if self.network_io.threads == 0 {
            return Err("network_io.threads must be > 0".to_string());
        }
        if self.network_io.threads > 128 {
            return Err("network_io.threads too large (max 128)".to_string());
        }
        
        // QUIC protocol validation
        if self.quic_protocol.threads == 0 {
            return Err("quic_protocol.threads must be > 0".to_string());
        }
        if self.quic_protocol.threads != self.network_io.threads {
            return Err(
                "quic_protocol.threads must equal network_io.threads (1:1 mapping required)"
                    .to_string()
            );
        }
        if self.quic_protocol.channel_buffer_size == 0 {
            return Err("quic_protocol.channel_buffer_size must be > 0".to_string());
        }
        
        // Server validation
        if self.server.max_connections == 0 {
            return Err("server.max_connections must be > 0".to_string());
        }
        if self.server.socket_recv_buffer_size < 64 * 1024 {
            return Err("server.socket_recv_buffer_size should be >= 64KB".to_string());
        }
        if self.server.socket_send_buffer_size < 64 * 1024 {
            return Err("server.socket_send_buffer_size should be >= 64KB".to_string());
        }
        
        // Tokio validation
        let cpu_count = num_cpus::get();
        let tokio_workers = self.tokio_worker_count();
        if tokio_workers == 0 {
            return Err("tokio_runtime.worker_threads must be > 0".to_string());
        }
        if tokio_workers > cpu_count * 2 {
            log::warn!(
                "tokio_runtime.worker_threads ({}) exceeds 2x CPU count ({})",
                tokio_workers,
                cpu_count
            );
        }
        
        Ok(())
    }
    
    /// Display configuration summary
    pub fn display_summary(&self) {
        let cpu_count = num_cpus::get();
        let tokio_workers = self.tokio_worker_count();
        
        log::info!("╔═══════════════════════════════════════════════════════════════╗");
        log::info!("║         superd - Production-Ready Architecture               ║");
        log::info!("╠═══════════════════════════════════════════════════════════════╣");
        log::info!("║ CPU Configuration                                             ║");
        log::info!("║   Total CPUs: {}                                             ║", cpu_count);
        log::info!("║   Network I/O threads: {} ({}%)                            ║",
            self.network_io.threads,
            (self.network_io.threads * 100) / cpu_count);
        log::info!("║   QUIC Protocol handlers: {} ({}%)                         ║",
            self.quic_protocol.threads,
            (self.quic_protocol.threads * 100) / cpu_count);
        log::info!("║   Tokio workers: {} ({}%)                                  ║",
            tokio_workers,
            (tokio_workers * 100) / cpu_count);
        log::info!("║                                                               ║");
        log::info!("║ Performance Settings                                          ║");
        log::info!("║   Max connections: {}                                    ║", self.server.max_connections);
        log::info!("║   Channel buffer: {} packets                             ║", self.quic_protocol.channel_buffer_size);
        log::info!("║   Socket buffers: {}MB / {}MB (RX/TX)                     ║",
            self.server.socket_recv_buffer_size / (1024 * 1024),
            self.server.socket_send_buffer_size / (1024 * 1024));
        log::info!("║                                                               ║");
        log::info!("║ Thread Placement                                              ║");
        log::info!("║   Network I/O pinning: {}                                   ║",
            if self.network_io.enable_cpu_pinning { "enabled" } else { "disabled" });
        log::info!("║   QUIC handler pinning: {}                                  ║",
            if self.quic_protocol.enable_cpu_pinning { "enabled" } else { "disabled" });
        log::info!("║   NUMA awareness: {}                                        ║",
            if self.network_io.enable_numa_awareness { "enabled" } else { "disabled" });
        log::info!("║   CPU affinity: {:?}                                   ║", self.network_io.cpu_affinity_strategy);
        log::info!("║   Tokio CPU mode: {:?}                                 ║", self.tokio_runtime.cpu_mode);
        log::info!("╚═══════════════════════════════════════════════════════════════╝");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_io_thread_calculation() {
        assert_eq!(Config::calculate_io_threads(1), 1);
        assert_eq!(Config::calculate_io_threads(2), 1);
        assert_eq!(Config::calculate_io_threads(4), 1);
        assert_eq!(Config::calculate_io_threads(8), 2);
        assert_eq!(Config::calculate_io_threads(16), 4);
        assert_eq!(Config::calculate_io_threads(32), 8);
        assert_eq!(Config::calculate_io_threads(64), 8);
    }
    
    #[test]
    fn test_tokio_worker_count_dedicated() {
        let mut config = Config::default();
        config.tokio_runtime.cpu_mode = TokioCpuMode::Dedicated;
        config.network_io.threads = 2;
        config.quic_protocol.threads = 2;
        
        // On 8-core: 8 - (2+2) = 4 workers
        if num_cpus::get() >= 8 {
            assert_eq!(config.tokio_worker_count(), num_cpus::get() - 4);
        }
    }
    
    #[test]
    fn test_tokio_worker_count_shared() {
        let mut config = Config::default();
        config.tokio_runtime.cpu_mode = TokioCpuMode::Shared;
        
        assert_eq!(config.tokio_worker_count(), num_cpus::get());
    }
    
    #[test]
    fn test_validation_quic_threads_mismatch() {
        let mut config = Config::default();
        config.network_io.threads = 4;
        config.quic_protocol.threads = 2; // Mismatch!
        
        assert!(config.validate().is_err());
    }
}
