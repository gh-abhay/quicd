//! # SuperD Server Entry Point
//!
//! This is the main entry point for the SuperD high-performance network server.
//! SuperD is designed for million-user scale with sub-microsecond latency and
//! zero-copy networking using io_uring and Sans-IO architecture.
//!
//! ## Architecture Overview
//!
//! SuperD uses a multi-layer async architecture:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SuperD Server                            │
//! │                                                             │
//! │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────┐  │
//! │  │   Network       │    │   Protocol      │    │   App   │  │
//! │  │   Tasks         │◄──►│   Tasks         │◄──►│   Tasks │  │
//! │  │   (4 tasks)     │    │   (12 tasks)    │    │(Dynamic)│  │
//! │  │                 │    │                 │    │         │  │
//! │  │ • Async io_uring│    │ • QUIC crypto   │    │ • Spawned│  │
//! │  │ • SO_REUSEPORT  │    │ • Parsing       │    │ • Per-stream│
//! │  │ • Zero-copy I/O │    │ • State mgmt    │    │ • ALPN-based│
//! │  └─────────────────┘    └─────────────────┘    └─────────┘  │
//! │         │                       │                       │     │
//! │    Fan-out 1→N            State per conn           Ephemeral │
//! │                                                                │
//! │                    ┌────────────────────────────┐              │
//! │                    │   Shared State             │              │
//! │                    │   • Buffer pools           │              │
//! │                    │   • Conn registry          │              │
//! │                    │   • Metrics                │              │
//! │                    └────────────────────────────┘              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Performance Targets
//!
//! - **Throughput**: 1-10M packets/second per network thread
//! - **Latency**: Sub-microsecond packet processing
//! - **Connections**: Millions of concurrent connections
//! - **Memory**: ~28-50KB per active connection
//!
//! ## Command Line Usage
//!
//! ```bash
//! # Start with default configuration
//! ./superd
//!
//! # Start with custom config file
//! ./superd --config config.toml
//!
//! # Start with CLI configuration
//! ./superd --listen 0.0.0.0:4433 --network-threads 4 --protocol-threads 8
//!
//! # Enable debug logging
//! RUST_LOG=debug ./superd
//! ```
//!
//! ## Configuration
//!
//! SuperD supports configuration via:
//! - Command line arguments
//! - Configuration file (TOML format)
//! - Environment variables
//! - Auto-tuning based on system capabilities
//!
//! ## Example Configuration File
//!
//! ```toml
//! listen = "0.0.0.0:4433"
//! network_threads = 4
//! protocol_threads = 8
//! cpu_pinning = false
//!
//! [telemetry]
//! otlp_endpoint = "http://localhost:4317"
//! service_name = "superd"
//!
//! [quic]
//! cert_path = "certs/server.crt"
//! key_path = "certs/server.key"
//! verify_peer = false
//! enable_early_data = false
//! application_protos = ["superd/0.1"]
//! ```
//!
//! ## Monitoring
//!
//! SuperD provides comprehensive observability:
//! - Structured logging with tracing
//! - Performance metrics and histograms
//! - Health checks and status endpoints
//! - OpenTelemetry integration for external monitoring
//!
//! ## Scaling
//!
//! For high-scale deployments:
//! - Configure buffer pools appropriately
//! - Enable SO_REUSEPORT for load balancing
//! - Monitor system resources and adjust task counts
//!
//! ## Safety
//!
//! SuperD is written in Rust and provides memory safety guarantees.
//! All network operations use safe abstractions over io_uring.

use clap::Parser;
use tokio::sync::{broadcast, mpsc};
use tracing::info;

use superd::config::{Cli, Config};
use superd::telemetry;

fn main() {
    tokio_uring::start(async {
        // Initialize basic logging first
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", "info");
        }

        let cli = Cli::parse();

        // Load config
        let config = if let Some(config_path) = &cli.config {
            match Config::load_from_file(config_path) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Failed to load config: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            match Config::from_cli(&cli) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Failed to create config from CLI: {}", e);
                    std::process::exit(1);
                }
            }
        };

        // Initialize telemetry
        telemetry::init_telemetry(&config.telemetry);

        // Print configuration summary
        config.print_summary();

        info!("Starting superd server");
        info!(
            "Configuration: {} network tasks, {} protocol tasks (dynamic app tasks per-stream)",
            config.network_threads, config.protocol_threads
        );

        // Create dedicated channels for network <-> protocol communication
        // Architecture:
        // - Ingress (Network → Protocol): protocol_threads channels (hash CID to route)
        // - Egress (Protocol → Network): network_threads channels (each protocol task needs all network senders)
        
        // INGRESS: Network → Protocol (M channels, one per protocol task)
        let mut to_protocol_senders = Vec::new();
        let mut to_protocol_receivers = Vec::new();

        for i in 0..config.protocol_threads {
            let (tx, rx) = mpsc::unbounded_channel();
            to_protocol_senders.push(tx);
            to_protocol_receivers.push(rx);
            info!("Created ingress channel {} (Network → Protocol task {})", i, i);
        }

        // EGRESS: Protocol → Network (N channels, one per network task)
        let mut from_protocol_senders = Vec::new();
        let mut from_protocol_receivers = Vec::new();

        for i in 0..config.network_threads {
            let (tx, rx) = mpsc::unbounded_channel();
            from_protocol_senders.push(tx);
            from_protocol_receivers.push(rx);
            info!("Created egress channel {} (Protocol → Network task {})", i, i);
        }

        // Create shared shutdown signal for graceful shutdown (broadcast)
        // All tasks subscribe to this signal for event-driven shutdown
        let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

        // Start network layer (async tasks with io_uring)
        info!("Starting network I/O layer with io_uring...");
        if let Err(e) = superd::network::io_uring_net::start_network_layer(
            &config,
            to_protocol_senders,
            from_protocol_receivers,
            shutdown_tx.clone(),
        ) {
            eprintln!("Failed to listen address: {}", e);
            std::process::exit(1);
        };

        info!("Network layer started successfully");

        // Create channels for protocol <-> application communication
        let (to_application_tx, to_application_rx) = mpsc::unbounded_channel();
        let (from_application_tx, from_application_rx) = mpsc::unbounded_channel();

        // Start protocol layer (async tasks)
        info!("Starting QUIC protocol layer...");
        if let Err(e) = superd::protocol::quic_handler::start_protocol_layer(
            &config,
            to_protocol_receivers,
            from_protocol_senders,
            to_application_tx,
            shutdown_tx.clone(),
        ) {
            eprintln!("Failed to start protocol layer: {}", e);
            std::process::exit(1);
        }
        info!("Protocol layer started successfully");

        // Start application layer (dynamic per-stream tasks)
        info!("Starting application layer...");
        if let Err(e) = superd::application::dispatcher::start_application_layer(
            to_application_rx,
            from_application_tx,
        ) {
            eprintln!("Failed to start application layer: {}", e);
            std::process::exit(1);
        }
        info!("Application layer started successfully");

        info!("SuperD server is running. Press Ctrl+C to stop.");

        // Setup signal handlers for graceful shutdown
        let shutdown_tx_for_signal = shutdown_tx.clone();
        let shutdown_handle = tokio_uring::spawn(async move {
            setup_signal_handlers(shutdown_tx_for_signal).await;
        });

        // Wait for shutdown signal to be processed
        let _ = shutdown_handle.await;

        info!("SuperD server stopped");
    });
}

async fn setup_signal_handlers(shutdown_tx: broadcast::Sender<()>) {
    if let Err(e) = tokio::signal::ctrl_c().await {
        eprintln!("Failed to listen for Ctrl+C: {}", e);
    }
    println!("\nReceived Ctrl+C, shutting down...");

    // Broadcast shutdown signal to all tasks (event-driven, no polling!)
    if let Err(e) = shutdown_tx.send(()) {
        eprintln!("Failed to send shutdown signal: {}", e);
    }
}
