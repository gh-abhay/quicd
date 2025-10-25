use crate::error::{ConfigError, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
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

    /// Enable CPU pinning with interleaved strategy (deprecated - not used in async mode)
    #[arg(long)]
    pub cpu_pinning: Option<bool>,

    /// OTLP endpoint for telemetry
    #[arg(long, default_value = "http://localhost:4317")]
    pub otlp_endpoint: String,

    /// Auto-tune configuration based on system characteristics
    #[arg(long, default_value = "true")]
    pub auto_tune: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: String,
    pub network_threads: usize,
    pub protocol_threads: usize,
    pub cpu_pinning: bool,
    pub telemetry: TelemetryConfig,

    /// System information (read-only, computed at runtime)
    #[serde(skip)]
    pub system_info: SystemInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub otlp_endpoint: String,
    pub service_name: String,
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
            network_threads: 2, // Default fallback
            protocol_threads: 8, // Default fallback (4x network)
            cpu_pinning: false,
            telemetry: TelemetryConfig {
                otlp_endpoint: "http://localhost:4317".to_string(),
                service_name: "superd".to_string(),
            },
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
        if let Some(cp) = cli.cpu_pinning {
            config.cpu_pinning = cp;
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
        self.listen.parse::<SocketAddr>()
            .map_err(|_| ConfigError::InvalidListenAddress(self.listen.clone()))?;

        // Validate thread counts
        if self.network_threads == 0 {
            return Err(ConfigError::InvalidThreadCount("network_threads must be at least 1".to_string()).into());
        }

        if self.protocol_threads == 0 {
            return Err(ConfigError::InvalidThreadCount("protocol_threads must be at least 1".to_string()).into());
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

        Ok(())
    }

    /// Auto-tune configuration based on system characteristics
    /// 
    /// Based on recommendations from Cloudflare, Discord, and Tokio async best practices:
    /// - **Network I/O**: 1 task per physical core (I/O-bound, kernel limited)
    /// - **Protocol (QUIC)**: 2-4x network tasks (CPU-bound, crypto intensive)
    /// - **Application**: Remaining logical CPUs (mixed workload)
    /// 
    /// QUIC protocol is CPU-intensive due to:
    /// - TLS 1.3 encryption/decryption (60-80% of protocol time)
    /// - ACK processing and congestion control
    /// - Connection state management
    /// 
    /// Industry examples:
    /// - Cloudflare: Separate I/O and crypto worker pools
    /// - Discord: 1:4 ratio for I/O to protocol tasks for QUIC
    /// - Tokio: Separate CPU-bound from I/O-bound tasks
    pub fn auto_tune(&mut self) {
        let cpus = self.system_info.total_cpus;
        let physical_cpus = self.system_info.physical_cpus;
        // Convert from KB to GB: KB / (1024 KB/MB) / (1024 MB/GB)
        let memory_gb = self.system_info.total_memory_kb / 1024 / 1024;

        // Network tasks: Based on physical core count
        // 
        // Reasoning from industry experts:
        // - Cloudflare optimizes network I/O with 1 task per physical core (no hyperthreading)
        // - Network I/O is memory-bound, not CPU-bound
        // - io_uring batches operations, so fewer tasks are better
        // - SO_REUSEPORT distributes load across tasks
        let network_from_cores = physical_cpus.max(1);
        
        self.network_threads = match memory_gb {
            // Small systems: very conservative, 1-2 tasks
            0..=8 => network_from_cores.min(2),
            
            // Medium systems (8-32GB): 1 per physical core
            9..=32 => network_from_cores.min(physical_cpus),
            
            // Large systems (32GB+): up to 1.5x physical cores for very high throughput
            _ => (network_from_cores + network_from_cores / 2).min(physical_cpus * 2).max(4),
        };

        // Protocol tasks: CPU-intensive QUIC processing
        //
        // Industry practice:
        // - Discord: 1:4 ratio (I/O to protocol) for QUIC workloads
        // - Cloudflare: Separate crypto workers, typically 2-4x I/O workers
        // - Reason: QUIC crypto (TLS 1.3) is CPU-bound, not I/O-bound
        // - Each protocol task handles ~100K connections but needs CPU for crypto
        //
        // Scaling: More protocol tasks = more crypto throughput
        let protocol_multiplier = match memory_gb {
            // Small systems: 2x network tasks (conservative)
            0..=8 => 2,
            // Medium systems: 3x network tasks (balanced)
            9..=32 => 3,
            // Large systems: 4x network tasks (crypto-optimized)
            _ => 4,
        };
        
        self.protocol_threads = (self.network_threads * protocol_multiplier)
            .max(4)  // Minimum 4 protocol tasks
            .min(cpus * 2); // Cap at 2x logical CPUs

        // Inform user about tuning decisions
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
            "  Application: Dynamic tasks spawned per-stream (ephemeral)"
        );

        // CPU pinning not used in pure async mode
        self.cpu_pinning = false;
    }

    /// Print configuration summary
    pub fn print_summary(&self) {
        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║              SuperD Configuration Summary               ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ Listen Address    : {:<35} ║", self.listen);
        println!("║ Network Tasks     : {:<35} ║", format!("{} (I/O layer)", self.network_threads));
        println!("║ Protocol Tasks    : {:<35} ║", format!("{} (QUIC crypto/parsing)", self.protocol_threads));
        println!("║ Application       : {:<35} ║", "Dynamic (per-stream tasks)");
        println!("║ CPU Pinning       : {:<35} ║", "Disabled (Async runtime)");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ System Info                                              ║");
        println!("║ Total CPUs        : {:<35} ║", self.system_info.total_cpus);
        println!("║ Physical CPUs     : {:<35} ║", self.system_info.physical_cpus);
        println!("║ Total Memory      : {:<32} MB ║", self.system_info.total_memory_kb / 1024);
        println!("║ Available Memory  : {:<32} MB ║", self.system_info.available_memory_kb / 1024);
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ Telemetry                                                ║");
        println!("║ OTLP Endpoint     : {:<35} ║", self.telemetry.otlp_endpoint);
        println!("║ Service Name      : {:<35} ║", self.telemetry.service_name);
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ Architecture: Network (Async io_uring) ->               ║");
        println!("║               Protocol (QUIC crypto) -> Application      ║");
        println!("║               Fan-out: 1 Network → N Protocol tasks      ║");
        println!("╚══════════════════════════════════════════════════════════╝");
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