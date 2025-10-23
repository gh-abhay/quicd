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

    /// Number of network IO threads (default: auto-tuned based on system)
    #[arg(long)]
    pub network_threads: Option<usize>,

    /// Number of application threads/tokio workers (default: auto-tuned)
    /// Protocol layer (QUIC) also runs on this Tokio runtime
    #[arg(long)]
    pub app_threads: Option<usize>,

    /// Enable CPU pinning with interleaved strategy
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
    pub app_threads: usize,
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
            app_threads: 6,     // Default fallback
            cpu_pinning: true,
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
        if let Some(at) = cli.app_threads {
            config.app_threads = at;
        }
        if let Some(cp) = cli.cpu_pinning {
            config.cpu_pinning = cp;
        }

        config.telemetry.otlp_endpoint = cli.otlp_endpoint.clone();

        // Re-apply auto-tuning if requested and no explicit values provided
        if cli.auto_tune && cli.network_threads.is_none() && cli.app_threads.is_none() {
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
        if config.network_threads == 0 || config.app_threads == 0 {
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

        if self.app_threads == 0 {
            return Err(ConfigError::InvalidThreadCount("app_threads must be at least 1".to_string()).into());
        }

        // Validate thread counts against available CPUs
        let total_requested = self.network_threads + self.app_threads;
        let available_cpus = self.system_info.total_cpus;

        if total_requested > available_cpus * 3 {
            return Err(ConfigError::ValidationFailed(
                format!("Total threads ({}) exceeds 3x available CPUs ({}). This will cause severe context switching overhead.",
                       total_requested, available_cpus)
            ).into());
        }

        // Warn about suboptimal configurations
        if self.cpu_pinning && self.network_threads > available_cpus / 2 {
            eprintln!(
                "WARNING: CPU pinning requested but network_threads ({}) > 50% of available CPUs ({}). \
                 Consider reducing network_threads or disabling CPU pinning.",
                self.network_threads, available_cpus
            );
        }

        if total_requested > available_cpus * 2 {
            eprintln!(
                "WARNING: Total threads ({}) exceeds 2x available CPUs ({}). \
                 Performance may be impacted by context switching.",
                total_requested, available_cpus
            );
        }

        Ok(())
    }

    /// Auto-tune configuration based on system characteristics
    pub fn auto_tune(&mut self) {
        let cpus = self.system_info.total_cpus;
        let memory_gb = self.system_info.total_memory_kb / (1024 * 1024);

        // Network threads: 25-40% of CPUs based on memory
        let network_ratio = if memory_gb >= 64 {
            0.4 // Large memory system: more network threads
        } else if memory_gb >= 32 {
            0.35 // Medium memory system
        } else {
            0.25 // Small memory system: fewer network threads
        };
        self.network_threads = ((cpus as f64 * network_ratio).ceil() as usize).max(1).min(cpus);

        // Application threads: remaining CPUs, but not more than network threads * 2
        let remaining_cpus = cpus.saturating_sub(self.network_threads);
        self.app_threads = remaining_cpus.max(1).min(self.network_threads * 2);

        // Enable CPU pinning if we have enough cores and hyperthreading
        self.cpu_pinning = cpus >= 8 && self.system_info.physical_cpus < cpus;
    }

    /// Print configuration summary
    pub fn print_summary(&self) {
        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║              SuperD Configuration Summary               ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║ Listen Address    : {:<35} ║", self.listen);
        println!("║ Network Threads   : {:<35} ║", self.network_threads);
        println!("║ App Threads       : {:<35} ║", format!("{} (Protocol + Application on Tokio)", self.app_threads));
        println!("║ CPU Pinning       : {:<35} ║", if self.cpu_pinning { "Enabled (Network only)" } else { "Disabled" });
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
        println!("║ Architecture: Network (native + io_uring) -> Protocol   ║");
        println!("║               (Tokio async) -> Application (Tokio async) ║");
        println!("╚══════════════════════════════════════════════════════════╝");
    }
}

impl SystemInfo {
    pub fn detect() -> Self {
        let num_cpus = num_cpus::get();
        let physical_cpus = num_cpus::get_physical();

        let mut sys = System::new_all();
        sys.refresh_all();

        let total_memory_kb = sys.total_memory();
        let available_memory_kb = sys.available_memory();

        Self {
            total_cpus: num_cpus,
            physical_cpus,
            total_memory_kb,
            available_memory_kb,
        }
    }
}