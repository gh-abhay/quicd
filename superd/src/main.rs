//! superd - High-Performance QUIC Multi-Service Daemon
//!
//! Command-line interface implementing the finalized three-layer architecture.
//!
//! # Architecture
//!
//! - Layer 1: Network I/O threads (UDP socket recv/send)
//! - Layer 2: QUIC protocol handlers (packet processing)
//! - Layer 3: Connection management (Tokio async tasks)
//!
//! # Usage
//!
//! ```bash
//! # Run with auto-detected optimal settings
//! superd
//!
//! # Custom thread counts
//! superd --network-io-threads 4 --quic-handlers 4
//!
//! # Disable CPU pinning (for containers)
//! superd --no-pin-io --no-pin-quic
//!
//! # Shared CPU mode (experimental, after profiling)
//! superd --tokio-cpu-mode shared
//!
//! # Load from config file
//! superd --config /etc/superd/config.toml
//! ```

use clap::Parser;
use std::path::PathBuf;

use superd::config::{CpuAffinityStrategy, ThreadPriority, TokioCpuMode};
use superd::{Config, Superd};

#[derive(Parser)]
#[command(name = "superd")]
#[command(version = "2.0.0")]
#[command(about = "High-performance QUIC daemon with production-proven architecture")]
#[command(long_about = "\
superd - High-Performance QUIC Multi-Service Daemon

Architecture:
  • Layer 1: Network I/O threads (CPU-pinned, NUMA-aware)
  • Layer 2: QUIC protocol handlers (CPU-pinned, 1:1 with I/O)
  • Layer 3: Connection management (Tokio async tasks)

Performance targets:
  • 100,000+ concurrent connections
  • 1,000,000+ packets/sec throughput
  • Sub-millisecond latency

Inspired by production systems at Cloudflare, Kafka, and Discord.
")]
struct Cli {
    // ========================================================================
    // Server Configuration
    // ========================================================================
    /// Address to listen on
    #[arg(short, long, default_value = "0.0.0.0:4433", env = "SUPERD_LISTEN")]
    listen: String,

    /// Maximum concurrent connections
    #[arg(long, env = "SUPERD_MAX_CONNECTIONS")]
    max_connections: Option<usize>,

    // ========================================================================
    // Network I/O Layer Configuration
    // ========================================================================
    /// Number of network I/O threads
    ///
    /// Default: auto-detected (25% of CPUs, min=1, max=8)
    ///
    /// Each thread handles UDP recv/send operations.
    /// More threads = higher throughput (up to kernel limits).
    #[arg(long, env = "SUPERD_NETWORK_IO_THREADS")]
    network_io_threads: Option<usize>,

    /// Disable CPU pinning for network I/O threads
    ///
    /// By default, I/O threads are pinned to specific CPU cores
    /// for cache locality. Disable in containers without CPU affinity.
    #[arg(long, env = "SUPERD_NO_PIN_IO")]
    no_pin_io: bool,

    /// Disable NUMA-aware thread placement
    ///
    /// By default, threads are placed on the same NUMA node as the NIC.
    /// Disable on non-NUMA systems or for testing.
    #[arg(long, env = "SUPERD_NO_NUMA")]
    no_numa: bool,

    /// Network I/O thread priority (low, normal, high, max)
    #[arg(long, default_value = "high", env = "SUPERD_IO_PRIORITY")]
    io_priority: String,

    /// CPU affinity strategy (auto, interleaved, sequential)
    ///
    /// - auto: No pinning (let OS decide)
    /// - interleaved: I/O on even cores, QUIC on odd cores
    /// - sequential: I/O on first N cores, QUIC on next N cores
    #[arg(long, default_value = "interleaved", env = "SUPERD_CPU_AFFINITY")]
    cpu_affinity: String,

    // ========================================================================
    // QUIC Protocol Layer Configuration
    // ========================================================================
    /// Number of QUIC protocol handler threads
    ///
    /// Default: auto-detected (equals network_io_threads)
    ///
    /// MUST equal network_io_threads for 1:1 channel mapping.
    #[arg(long, env = "SUPERD_QUIC_HANDLERS")]
    quic_handlers: Option<usize>,

    /// Disable CPU pinning for QUIC protocol handlers
    #[arg(long, env = "SUPERD_NO_PIN_QUIC")]
    no_pin_quic: bool,

    /// QUIC handler thread priority (low, normal, high, max)
    #[arg(long, default_value = "normal", env = "SUPERD_QUIC_PRIORITY")]
    quic_priority: String,

    /// Channel buffer size (packets per I/O thread)
    #[arg(long, default_value = "8192", env = "SUPERD_CHANNEL_BUFFER")]
    channel_buffer: usize,

    // ========================================================================
    // Tokio Runtime Configuration
    // ========================================================================
    /// Number of Tokio worker threads
    ///
    /// Default: auto-detected based on tokio_cpu_mode
    ///
    /// - dedicated mode: num_cpus - (io + quic)
    /// - shared mode: num_cpus
    #[arg(long, env = "SUPERD_TOKIO_WORKERS")]
    tokio_workers: Option<usize>,

    /// Tokio CPU allocation mode (dedicated, shared)
    ///
    /// - dedicated: Tokio uses only unpinned CPUs (safe, default)
    /// - shared: Tokio can use all CPUs (efficient, experimental)
    ///
    /// Use "shared" only after profiling confirms I/O+QUIC < 50% CPU.
    #[arg(long, default_value = "dedicated", env = "SUPERD_TOKIO_CPU_MODE")]
    tokio_cpu_mode: String,

    // ========================================================================
    // Socket Configuration
    // ========================================================================
    /// Socket receive buffer size (bytes)
    #[arg(long, default_value = "8388608", env = "SUPERD_SOCKET_RECV_BUF")]
    socket_recv_buffer: usize,

    /// Socket send buffer size (bytes)
    #[arg(long, default_value = "8388608", env = "SUPERD_SOCKET_SEND_BUF")]
    socket_send_buffer: usize,

    /// Disable SO_REUSEPORT (not recommended)
    #[arg(long, env = "SUPERD_NO_REUSEPORT")]
    no_reuseport: bool,

    // ========================================================================
    // Monitoring Configuration
    // ========================================================================
    /// Metrics logging interval (seconds)
    #[arg(long, default_value = "10", env = "SUPERD_METRICS_INTERVAL")]
    metrics_interval: u64,

    /// Enable debug logging
    #[arg(short, long, env = "SUPERD_DEBUG")]
    debug: bool,

    /// Enable profiling hooks
    #[arg(long, env = "SUPERD_PROFILING")]
    profiling: bool,

    // ========================================================================
    // Configuration File
    // ========================================================================
    /// Load configuration from TOML file
    ///
    /// CLI arguments override config file values.
    #[arg(short, long, env = "SUPERD_CONFIG")]
    config: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.debug {
        log::LevelFilter::Debug
    } else {
        std::env::var("RUST_LOG")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(log::LevelFilter::Info)
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    log::info!("superd v2.0.0 - High-Performance QUIC Daemon");
    log::info!("Architecture: Three-layer (I/O → QUIC → Tokio)");

    // Load or create configuration
    let mut config = if let Some(ref config_path) = cli.config {
        log::info!("Loading configuration from {}", config_path.display());
        load_config_from_file(config_path)?
    } else {
        log::info!("Using default configuration (auto-detected optimal settings)");
        Config::default()
    };

    // Override with CLI arguments
    apply_cli_overrides(&mut config, &cli)?;

    // Validate configuration
    config
        .validate()
        .map_err(|e| format!("Invalid configuration: {}", e))?;

    // Create and run daemon
    log::info!("Creating daemon...");
    let daemon = Superd::new(config).map_err(|e| format!("Failed to create daemon: {}", e))?;

    log::info!("Starting daemon...");
    daemon.run().map_err(|e| format!("Daemon error: {}", e))?;

    Ok(())
}

/// Load configuration from TOML file
fn load_config_from_file(path: &PathBuf) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

/// Apply CLI argument overrides to configuration
fn apply_cli_overrides(config: &mut Config, cli: &Cli) -> Result<(), String> {
    // Server configuration
    config.server.listen_addr = cli
        .listen
        .parse()
        .map_err(|e| format!("Invalid listen address: {}", e))?;

    if let Some(max_conn) = cli.max_connections {
        config.server.max_connections = max_conn;
    }

    // Network I/O configuration
    if let Some(threads) = cli.network_io_threads {
        config.network_io.threads = threads;
    }

    if cli.no_pin_io {
        config.network_io.enable_cpu_pinning = false;
    }

    if cli.no_numa {
        config.network_io.enable_numa_awareness = false;
    }

    config.network_io.thread_priority = parse_priority(&cli.io_priority)?;
    config.network_io.cpu_affinity_strategy = parse_affinity(&cli.cpu_affinity)?;

    // QUIC protocol configuration
    if let Some(handlers) = cli.quic_handlers {
        config.quic_protocol.threads = handlers;
    }

    if cli.no_pin_quic {
        config.quic_protocol.enable_cpu_pinning = false;
    }

    config.quic_protocol.thread_priority = parse_priority(&cli.quic_priority)?;
    config.quic_protocol.channel_buffer_size = cli.channel_buffer;

    // Tokio runtime configuration
    if let Some(workers) = cli.tokio_workers {
        config.tokio_runtime.worker_threads = Some(workers);
    }

    config.tokio_runtime.cpu_mode = parse_cpu_mode(&cli.tokio_cpu_mode)?;

    // Socket configuration
    config.server.socket_recv_buffer_size = cli.socket_recv_buffer;
    config.server.socket_send_buffer_size = cli.socket_send_buffer;

    if cli.no_reuseport {
        config.server.enable_reuseport = false;
    }

    // Monitoring configuration
    config.monitoring.metrics_interval = std::time::Duration::from_secs(cli.metrics_interval);
    config.monitoring.debug_mode = cli.debug;
    config.monitoring.enable_profiling = cli.profiling;

    Ok(())
}

/// Parse thread priority from string
fn parse_priority(s: &str) -> Result<ThreadPriority, String> {
    match s.to_lowercase().as_str() {
        "low" => Ok(ThreadPriority::Low),
        "normal" => Ok(ThreadPriority::Normal),
        "high" => Ok(ThreadPriority::High),
        "max" => Ok(ThreadPriority::Max),
        _ => Err(format!(
            "Invalid priority: {} (must be: low, normal, high, max)",
            s
        )),
    }
}

/// Parse CPU affinity strategy from string
fn parse_affinity(s: &str) -> Result<CpuAffinityStrategy, String> {
    match s.to_lowercase().as_str() {
        "auto" => Ok(CpuAffinityStrategy::Auto),
        "interleaved" => Ok(CpuAffinityStrategy::Interleaved),
        "sequential" => Ok(CpuAffinityStrategy::Sequential),
        _ => Err(format!(
            "Invalid affinity: {} (must be: auto, interleaved, sequential)",
            s
        )),
    }
}

/// Parse Tokio CPU mode from string
fn parse_cpu_mode(s: &str) -> Result<TokioCpuMode, String> {
    match s.to_lowercase().as_str() {
        "dedicated" => Ok(TokioCpuMode::Dedicated),
        "shared" => Ok(TokioCpuMode::Shared),
        _ => Err(format!(
            "Invalid CPU mode: {} (must be: dedicated, shared)",
            s
        )),
    }
}
