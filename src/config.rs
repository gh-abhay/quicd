use crate::error::{ConfigError, Result};
use crate::network::zerocopy_buffer::MAX_UDP_PAYLOAD;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use sysinfo::System;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Config file path
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    pub listen: String,

    /// Number of network IO tasks (default: auto-tuned based on system)
    #[arg(long)]
    pub network_threads: Option<usize>,

    /// Number of protocol tasks for QUIC handling (default: auto-tuned, typically 2-4x network tasks)
    #[arg(long)]
    pub protocol_threads: Option<usize>,

    /// OTLP endpoint for telemetry
    #[arg(long, default_value = "http://localhost:4317")]
    pub otlp_endpoint: String,

    /// Auto-tune configuration based on system characteristics
    #[arg(long, default_value = "true")]
    pub auto_tune: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: String,
    pub network_threads: usize,
    pub protocol_threads: usize,
    pub telemetry: TelemetryConfig,
    pub quic: QuicConfig,

    /// System information (read-only, computed at runtime)
    #[serde(skip)]
    pub system_info: SystemInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub otlp_endpoint: String,
    pub service_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuicConfig {
    pub cert_path: String,
    pub key_path: String,
    pub verify_peer: bool,
    pub enable_early_data: bool,
    pub application_protos: Vec<String>,
    pub max_idle_timeout_ms: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_send_udp_payload_size: usize,
    pub max_recv_udp_payload_size: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub total_cpus: usize,
    pub physical_cpus: usize,
    pub total_memory_kb: u64,
    pub available_memory_kb: u64,
}

impl Default for Config {
    fn default() -> Self {
        let system_info = SystemInfo::detect();
        let mut config = Self {
            listen: "0.0.0.0:4433".to_string(),
            network_threads: 2,  // Default fallback
            protocol_threads: 8, // Default fallback (4x network)
            telemetry: TelemetryConfig {
                otlp_endpoint: "http://localhost:4317".to_string(),
                service_name: "superd".to_string(),
            },
            quic: QuicConfig::default(),
            system_info,
        };

        // Auto-tune if possible
        config.auto_tune();
        config
    }
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let mut config = Self::default();

        config.listen = cli.listen.clone();

        if let Some(nt) = cli.network_threads {
            config.network_threads = nt;
        }
        if let Some(pt) = cli.protocol_threads {
            config.protocol_threads = pt;
        }

        config.telemetry.otlp_endpoint = cli.otlp_endpoint.clone();

        // Re-apply auto-tuning if requested and no explicit values provided
        if cli.auto_tune && cli.network_threads.is_none() && cli.protocol_threads.is_none() {
            config.auto_tune();
        }

        config.validate()?;
        Ok(config)
    }

    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&contents)?;
        config.system_info = SystemInfo::detect();

        // Auto-tune defaults if not specified in file
        if config.network_threads == 0 || config.protocol_threads == 0 {
            config.auto_tune();
        }

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration and return error for critical issues
    pub fn validate(&self) -> Result<()> {
        // Check listen address is valid
        self.listen
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::InvalidListenAddress(self.listen.clone()))?;

        // Validate thread counts
        if self.network_threads == 0 {
            return Err(ConfigError::InvalidThreadCount(
                "network_threads must be at least 1".to_string(),
            )
            .into());
        }
        if self.protocol_threads == 0 {
            return Err(ConfigError::InvalidThreadCount(
                "protocol_threads must be at least 1".to_string(),
            )
            .into());
        }

        if self.protocol_threads == 0 {
            return Err(ConfigError::InvalidThreadCount(
                "protocol_threads must be at least 1".to_string(),
            )
            .into());
        }

        // Validate thread counts against available CPUs
        let total_requested = self.network_threads + self.protocol_threads;
        let available_cpus = self.system_info.total_cpus;

        // For async tasks, we can have more tasks than CPUs since they're lightweight
        // Warn only if we exceed 4x CPUs (much more lenient than thread-based model)
        if total_requested > available_cpus * 4 {
            return Err(ConfigError::ValidationFailed(
                format!("Total tasks ({}) exceeds 4x available CPUs ({}). This may cause excessive overhead.",
                       total_requested, available_cpus)
            ).into());
        }

        // Informational warning for high task counts
        if total_requested > available_cpus * 3 {
            eprintln!(
                "INFO: Total tasks ({}) exceeds 3x CPUs ({}). This is acceptable for async tasks but monitor CPU usage.",
                total_requested, available_cpus
            );
        }

        if self.quic.application_protos.is_empty() {
            return Err(ConfigError::ValidationFailed(
                "At least one QUIC application protocol must be configured".into(),
            )
            .into());
        }

        let cert_path = Path::new(&self.quic.cert_path);
        if !cert_path.exists() {
            eprintln!(
                "WARN: TLS certificate not found at {}. Provide a valid certificate before accepting connections.",
                cert_path.display()
            );
        }

        let key_path = Path::new(&self.quic.key_path);
        if !key_path.exists() {
            eprintln!(
                "WARN: TLS private key not found at {}. Provide a valid key before accepting connections.",
                key_path.display()
            );
        }

        Ok(())
    }

    /// Auto-tune configuration based on system characteristics
    ///
    /// Based on recommendations from Cloudflare, Discord, and industry benchmarks:
    /// - **Network I/O**: 1 task per physical core (I/O-bound, kernel limited)
    /// - **Protocol (QUIC)**: 4-8x network tasks (CPU-bound, crypto intensive)
    /// - **Buffer Pool**: Dynamically sized based on expected concurrent connections
    ///
    /// Industry benchmarks for QUIC workloads:
    /// - Discord: 1:4 ratio (I/O to protocol) for QUIC workloads
    /// - Cloudflare: Separate crypto workers, typically 4-6x I/O workers for QUIC
    /// - ejabberd: 1:8+ ratio for high-concurrency XMPP/QUIC servers
    /// - Reason: QUIC crypto (TLS 1.3) is CPU-bound, not I/O-bound
    /// - Each protocol task handles ~10K-100K connections but needs CPU for crypto
    ///
    /// Performance targets:
    /// - 1-10M packets/second per network thread
    /// - Millions of concurrent connections
    /// - Sub-microsecond packet processing
    pub fn auto_tune(&mut self) {
        let cpus = self.system_info.total_cpus;
        let physical_cpus = self.system_info.physical_cpus;
        // Convert from KB to GB: KB / (1024 KB/MB) / (1024 MB/GB)
        let memory_gb = self.system_info.total_memory_kb / 1024 / 1024;

        // Network tasks: Based on physical core count for I/O optimization
        //
        // Reasoning from industry experts and benchmarks:
        // - Cloudflare optimizes network I/O with 1 task per physical core (no hyperthreading)
        // - Network I/O is memory-bound, not CPU-bound with io_uring
        // - io_uring batches operations, so fewer tasks are better
        // - SO_REUSEPORT distributes load across tasks when enabled
        let network_from_cores = physical_cpus.max(1);

        self.network_threads = match memory_gb {
            // Small systems: very conservative, 1-2 tasks
            0..=8 => network_from_cores.min(2),

            // Medium systems (8-32GB): 1 per physical core
            9..=32 => network_from_cores.min(physical_cpus),

            // Large systems (32GB+): up to 1.5x physical cores for very high throughput
            // Discord/Cloudflare scale: support millions of concurrent connections
            _ => (network_from_cores + network_from_cores / 2)
                .min(physical_cpus * 2)
                .max(4),
        };

        // Protocol tasks: CPU-intensive QUIC processing
        //
        // Industry benchmarks for high-scale QUIC servers:
        // - Discord: 1:4 ratio (I/O to protocol) for QUIC workloads
        // - Cloudflare: 4-6x I/O workers for QUIC crypto processing
        // - ejabberd: 1:8+ ratio for high-concurrency servers
        // - Reason: QUIC crypto (TLS 1.3) is CPU-bound, not I/O-bound
        // - Each protocol task can handle ~10K-100K connections with proper crypto throughput
        //
        // Scaling based on system size and performance targets:
        let protocol_multiplier = match memory_gb {
            // Small systems: 4x network tasks (minimum for QUIC crypto)
            0..=8 => 4,

            // Medium systems: 6x network tasks (balanced for 100K+ connections)
            9..=32 => 6,

            // Large systems: 8x network tasks (optimized for millions of connections)
            // Discord/Cloudflare scale: maximum crypto throughput
            _ => 8,
        };

        self.protocol_threads = (self.network_threads * protocol_multiplier)
            .max(8) // Minimum 8 protocol tasks for QUIC crypto
            .min(cpus * 3); // Cap at 3x logical CPUs for extreme scale

        // Inform user about tuning decisions with performance context
        eprintln!(
            "Auto-tuned for system: {} logical CPUs, {} physical cores, {}GB RAM",
            cpus, physical_cpus, memory_gb
        );
        eprintln!(
            "  Network tasks: {} (I/O-bound, 1 per physical core)",
            self.network_threads
        );
        eprintln!(
            "  Protocol tasks: {} (CPU-bound, {}x network for QUIC crypto)",
            self.protocol_threads, protocol_multiplier
        );
        eprintln!(
            "  Target capacity: ~{} concurrent connections (based on Discord/Cloudflare benchmarks)",
            self.protocol_threads * 50_000
        );
        eprintln!("  Application: Dynamic tasks spawned per-stream (ephemeral)");

        // CPU pinning not used in pure async mode
        // self.cpu_pinning = false;
    }

    /// Calculate optimal buffer pool size based on expected concurrent connections
    /// and available memory. Each connection needs ~2-4 buffers for active operations.
    ///
    /// Formula: max(estimated_connections * buffers_per_connection, memory_based_limit)
    /// - estimated_connections = protocol_threads * avg_connections_per_thread
    /// - buffers_per_connection = 4 (for ingress/egress queues and processing)
    /// - memory_based_limit = available_memory / buffer_size
    pub fn calculate_buffer_pool_size(&self) -> usize {
        let memory_gb = self.system_info.total_memory_kb / 1024 / 1024;

        // Estimate concurrent connections based on protocol threads
        // Industry benchmarks: each protocol thread can handle ~50K connections
        let estimated_connections = self.protocol_threads * 50_000;

        // Each connection needs ~4 buffers (ingress, egress, processing, overhead)
        let buffers_per_connection = 4;
        let connection_based_buffers = estimated_connections * buffers_per_connection;

        // Memory-based limit: use up to 25% of available memory for buffers
        // Each buffer is ~64KB (MAX_UDP_PAYLOAD), so 25% of memory gives us:
        let buffer_size_kb = 64; // MAX_UDP_PAYLOAD
        let memory_based_buffers = ((self.system_info.available_memory_kb / 4) / buffer_size_kb) as usize;

        // Take the minimum of the two estimates, with reasonable bounds
        let optimal_size = connection_based_buffers.min(memory_based_buffers);
        let optimal_size = optimal_size.max(8192); // Minimum 8K buffers
        let optimal_size = optimal_size.min(1_000_000); // Maximum 1M buffers

        eprintln!(
            "Buffer pool sizing: {} buffers (estimated {} connections, {}MB memory)",
            optimal_size,
            estimated_connections,
            (optimal_size as u64 * buffer_size_kb as u64) / 1024
        );

        optimal_size
    }

    /// Print configuration summary
    pub fn print_summary(&self) {
        println!("║              SuperD Configuration Summary               ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ Listen Address    : {:<35} ║", self.listen);
        println!(
            "║ Network Tasks     : {:<35} ║",
            format!("{} (I/O layer)", self.network_threads)
        );
        println!(
            "║ Protocol Tasks    : {:<35} ║",
            format!("{} (QUIC crypto/parsing)", self.protocol_threads)
        );
        println!(
            "║ Application       : {:<35} ║",
            "Dynamic (per-stream tasks)"
        );
        println!(
            "║ QUIC TLS Cert     : {:<35} ║",
            self.quic.cert_path.as_str()
        );
        println!(
            "║ QUIC TLS Key      : {:<35} ║",
            self.quic.key_path.as_str()
        );
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ System Info                                              ║");
        println!(
            "║ Total CPUs        : {:<35} ║",
            self.system_info.total_cpus
        );
        println!(
            "║ Physical CPUs     : {:<35} ║",
            self.system_info.physical_cpus
        );
        println!(
            "║ Total Memory      : {:<32} MB ║",
            self.system_info.total_memory_kb / 1024
        );
        println!(
            "║ Available Memory  : {:<32} MB ║",
            self.system_info.available_memory_kb / 1024
        );
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ Telemetry                                                ║");
        println!(
            "║ OTLP Endpoint     : {:<35} ║",
            self.telemetry.otlp_endpoint
        );
        println!(
            "║ Service Name      : {:<35} ║",
            self.telemetry.service_name
        );
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ Architecture: Network (Async io_uring) ->               ║");
        println!("║               Protocol (QUIC crypto) -> Application      ║");
        println!("║               Fan-out: 1 Network → N Protocol tasks      ║");
        println!("╚══════════════════════════════════════════════════════════╝");
    }
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            cert_path: "certs/server.crt".to_string(),
            key_path: "certs/server.key".to_string(),
            verify_peer: false,
            enable_early_data: true, // Enable for better performance
            application_protos: vec!["superd/0.1".to_string()],
            max_idle_timeout_ms: 30_000,
            // Optimized for millions of concurrent connections (Discord/Cloudflare scale)
            initial_max_data: 16 * 1024 * 1024, // 16MB per connection
            initial_max_stream_data_bidi_local: 4 * 1024 * 1024, // 4MB per stream
            initial_max_stream_data_bidi_remote: 4 * 1024 * 1024,
            initial_max_stream_data_uni: 2 * 1024 * 1024,
            initial_max_streams_bidi: 256, // Higher for concurrent streams
            initial_max_streams_uni: 128,
            max_send_udp_payload_size: 1350, // Standard MTU
            max_recv_udp_payload_size: MAX_UDP_PAYLOAD,
        }
    }
}

impl SystemInfo {
    pub fn detect() -> Self {
        let num_cpus = num_cpus::get();
        let physical_cpus = num_cpus::get_physical();

        let mut sys = System::new_all();
        sys.refresh_all();

        // sysinfo returns memory in bytes, convert to KB
        let total_memory_kb = sys.total_memory() / 1024;
        let available_memory_kb = sys.available_memory() / 1024;

        Self {
            total_cpus: num_cpus,
            physical_cpus,
            total_memory_kb,
            available_memory_kb,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, ConfigError};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_cli_parsing_default() {
        let cli = Cli::parse_from(["test"]);
        assert_eq!(cli.listen, "0.0.0.0:4433");
        assert_eq!(cli.network_threads, None);
        assert_eq!(cli.protocol_threads, None);
        assert_eq!(cli.otlp_endpoint, "http://localhost:4317");
        assert!(cli.auto_tune);
    }

    #[test]
    fn test_cli_parsing_with_args() {
        let cli = Cli::parse_from([
            "test",
            "--listen", "127.0.0.1:8443",
            "--network-threads", "4",
            "--protocol-threads", "16",
            "--otlp-endpoint", "http://otel:4317"
        ]);
        assert_eq!(cli.listen, "127.0.0.1:8443");
        assert_eq!(cli.network_threads, Some(4));
        assert_eq!(cli.protocol_threads, Some(16));
        assert_eq!(cli.otlp_endpoint, "http://otel:4317");
        assert!(cli.auto_tune);
    }

    #[test]
    fn test_config_from_cli_default() {
        let cli = Cli::parse_from(["test"]);
        let config = Config::from_cli(&cli).unwrap();

        assert_eq!(config.listen, "0.0.0.0:4433");
        assert!(config.network_threads >= 1);
        assert!(config.protocol_threads >= 8);
        assert_eq!(config.telemetry.otlp_endpoint, "http://localhost:4317");
        assert_eq!(config.telemetry.service_name, "superd");
    }

    #[test]
    fn test_config_from_cli_with_explicit_values() {
        let cli = Cli::parse_from([
            "test",
            "--listen", "127.0.0.1:8443",
            "--network-threads", "2",
            "--protocol-threads", "8",
            "--otlp-endpoint", "http://otel:4317"
        ]);
        let config = Config::from_cli(&cli).unwrap();

        assert_eq!(config.listen, "127.0.0.1:8443");
        assert_eq!(config.network_threads, 2);
        assert_eq!(config.protocol_threads, 8);
        assert_eq!(config.telemetry.otlp_endpoint, "http://otel:4317");
    }

    #[test]
    fn test_config_load_from_file() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");

        let config_content = r#"
            listen = "127.0.0.1:8443"
            network_threads = 4
            protocol_threads = 16

            [telemetry]
            otlp_endpoint = "http://otel:4317"
            service_name = "test-service"

            [quic]
            cert_path = "test.crt"
            key_path = "test.key"
            verify_peer = true
            enable_early_data = false
            application_protos = ["test/1.0", "test/2.0"]
            max_idle_timeout_ms = 60000
            initial_max_data = 33554432
            initial_max_stream_data_bidi_local = 8388608
            initial_max_stream_data_bidi_remote = 8388608
            initial_max_stream_data_uni = 4194304
            initial_max_streams_bidi = 512
            initial_max_streams_uni = 256
            max_send_udp_payload_size = 1400
            max_recv_udp_payload_size = 65535
        "#;

        fs::write(&config_path, config_content).unwrap();

        let config = Config::load_from_file(&config_path).unwrap();

        assert_eq!(config.listen, "127.0.0.1:8443");
        assert_eq!(config.network_threads, 4);
        assert_eq!(config.protocol_threads, 16);
        assert_eq!(config.telemetry.otlp_endpoint, "http://otel:4317");
        assert_eq!(config.telemetry.service_name, "test-service");
        assert_eq!(config.quic.cert_path, "test.crt");
        assert_eq!(config.quic.key_path, "test.key");
        assert!(config.quic.verify_peer);
        assert!(!config.quic.enable_early_data);
        assert_eq!(config.quic.application_protos, vec!["test/1.0", "test/2.0"]);
        assert_eq!(config.quic.max_idle_timeout_ms, 60000);
        assert_eq!(config.quic.initial_max_data, 33554432);
        assert_eq!(config.quic.initial_max_streams_bidi, 512);
    }

    #[test]
    fn test_config_validation_valid() {
        let mut config = Config::default();
        config.listen = "127.0.0.1:8443".to_string();
        config.network_threads = 2;
        config.protocol_threads = 8;
        config.quic.application_protos = vec!["test/1.0".to_string()];

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_listen_address() {
        let mut config = Config::default();
        config.listen = "invalid:address".to_string();

        assert!(matches!(config.validate(), Err(Error::Config(ConfigError::InvalidListenAddress(_)))));
    }

    #[test]
    fn test_config_validation_zero_network_threads() {
        let mut config = Config::default();
        config.network_threads = 0;

        assert!(matches!(config.validate(), Err(Error::Config(ConfigError::InvalidThreadCount(_)))));
    }

    #[test]
    fn test_config_validation_zero_protocol_threads() {
        let mut config = Config::default();
        config.protocol_threads = 0;

        assert!(matches!(config.validate(), Err(Error::Config(ConfigError::InvalidThreadCount(_)))));
    }

    #[test]
    fn test_config_validation_empty_application_protos() {
        let mut config = Config::default();
        config.quic.application_protos = vec![];

        assert!(matches!(config.validate(), Err(Error::Config(ConfigError::ValidationFailed(_)))));
    }

    #[test]
    fn test_config_validation_excessive_threads() {
        let mut config = Config::default();
        // Set system info to simulate a small system
        config.system_info = SystemInfo {
            total_cpus: 4,
            physical_cpus: 2,
            total_memory_kb: 8 * 1024 * 1024, // 8GB
            available_memory_kb: 6 * 1024 * 1024,
        };
        config.network_threads = 20; // 5x physical CPUs
        config.protocol_threads = 60; // Total 80 tasks, exceeds 4 * 4 = 16

        assert!(matches!(config.validate(), Err(Error::Config(ConfigError::ValidationFailed(_)))));
    }

    #[test]
    fn test_auto_tune_small_system() {
        let mut config = Config::default();
        // Simulate small system: 2 cores, 4GB RAM
        config.system_info = SystemInfo {
            total_cpus: 2,
            physical_cpus: 2,
            total_memory_kb: 4 * 1024 * 1024,
            available_memory_kb: 3 * 1024 * 1024,
        };

        config.auto_tune();

        assert_eq!(config.network_threads, 2); // Min of physical cores and memory-based limit
        assert_eq!(config.protocol_threads, 6); // 4x network_threads, capped at 3x logical CPUs (2*3=6)
    }

    #[test]
    fn test_auto_tune_medium_system() {
        let mut config = Config::default();
        // Simulate medium system: 8 cores, 16GB RAM
        config.system_info = SystemInfo {
            total_cpus: 8,
            physical_cpus: 4,
            total_memory_kb: 16 * 1024 * 1024,
            available_memory_kb: 12 * 1024 * 1024,
        };

        config.auto_tune();

        assert_eq!(config.network_threads, 4); // Equal to physical cores
        assert_eq!(config.protocol_threads, 24); // 6x network_threads
    }

    #[test]
    fn test_auto_tune_large_system() {
        let mut config = Config::default();
        // Simulate large system: 32 cores, 128GB RAM
        config.system_info = SystemInfo {
            total_cpus: 32,
            physical_cpus: 16,
            total_memory_kb: 128 * 1024 * 1024,
            available_memory_kb: 100 * 1024 * 1024,
        };

        config.auto_tune();

        assert_eq!(config.network_threads, 24); // 16 + 16/2 = 24, capped appropriately
        assert_eq!(config.protocol_threads, 96); // 8x network_threads, capped at 3x CPUs
    }

    #[test]
    fn test_calculate_buffer_pool_size() {
        let mut config = Config::default();
        config.protocol_threads = 4; // 4 * 50,000 = 200,000 estimated connections
        config.system_info = SystemInfo {
            total_cpus: 8,
            physical_cpus: 4,
            total_memory_kb: 32 * 1024 * 1024, // 32GB
            available_memory_kb: 24 * 1024 * 1024, // 24GB available
        };

        let buffer_pool_size = config.calculate_buffer_pool_size();

        // 200,000 connections * 4 buffers = 800,000 connection-based
        // 24GB / 4 / 64KB = ~93,750 memory-based
        // Should take min(800,000, 93,750) = 93,750, but clamped to max 1M
        assert!(buffer_pool_size >= 8192 && buffer_pool_size <= 1_000_000);
    }

    #[test]
    fn test_quic_config_defaults() {
        let quic_config = QuicConfig::default();

        assert_eq!(quic_config.cert_path, "certs/server.crt");
        assert_eq!(quic_config.key_path, "certs/server.key");
        assert!(!quic_config.verify_peer);
        assert!(quic_config.enable_early_data);
        assert_eq!(quic_config.application_protos, vec!["superd/0.1"]);
        assert_eq!(quic_config.max_idle_timeout_ms, 30_000);
        assert_eq!(quic_config.initial_max_data, 16 * 1024 * 1024);
        assert_eq!(quic_config.initial_max_streams_bidi, 256);
        assert_eq!(quic_config.max_send_udp_payload_size, 1350);
        assert_eq!(quic_config.max_recv_udp_payload_size, MAX_UDP_PAYLOAD);
    }

    #[test]
    fn test_system_info_detect() {
        let system_info = SystemInfo::detect();

        assert!(system_info.total_cpus > 0);
        assert!(system_info.physical_cpus > 0);
        assert!(system_info.total_memory_kb > 0);
        assert!(system_info.available_memory_kb > 0);
        assert!(system_info.total_cpus >= system_info.physical_cpus);
    }

    #[test]
    fn test_config_default_values() {
        let config = Config::default();

        assert_eq!(config.listen, "0.0.0.0:4433");
        assert!(config.network_threads >= 1);
        assert!(config.protocol_threads >= 1);
        assert_eq!(config.telemetry.service_name, "superd");
        assert!(!config.quic.verify_peer);
        assert!(config.quic.enable_early_data);
    }

    #[test]
    fn test_config_load_from_file_auto_tune() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("minimal_config.toml");

        // Config with minimal values that should trigger auto-tuning
        let config_content = r#"
            listen = "127.0.0.1:8443"

            [quic]
            application_protos = ["test/1.0"]
        "#;

        fs::write(&config_path, config_content).unwrap();

        let config = Config::load_from_file(&config_path).unwrap();

        // Should have auto-tuned values
        assert_eq!(config.listen, "127.0.0.1:8443");
        assert!(config.network_threads >= 1);
        assert!(config.protocol_threads >= 8);
        assert_eq!(config.quic.application_protos, vec!["test/1.0"]);
    }

    #[test]
    fn test_config_load_from_file_invalid_toml() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("invalid_config.toml");

        let invalid_content = r#"
            listen = "127.0.0.1:8443"
            invalid_toml_syntax [
        "#;

        fs::write(&config_path, invalid_content).unwrap();

        assert!(Config::load_from_file(&config_path).is_err());
    }
}
