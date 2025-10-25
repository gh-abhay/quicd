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
//! ./superd --network-threads 4 --app-threads 2 --port 8080
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
//! [network]
//! threads = 4
//! port = 8080
//! buffer_pool_size = 2048
//!
//! [application]
//! threads = 2
//!
//! [telemetry]
//! log_level = "info"
//! otlp_endpoint = "http://localhost:4317"
//! service_name = "superd"
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
    // Each network task gets its own pair of channels to/from protocol layer
    let mut to_protocol_senders = Vec::new();
    let mut to_protocol_receivers = Vec::new();
    let mut from_protocol_senders = Vec::new();
    let mut from_protocol_receivers = Vec::new();

    for i in 0..config.network_threads {
        let (to_proto_tx, to_proto_rx) = mpsc::unbounded_channel();
        let (from_proto_tx, from_proto_rx) = mpsc::unbounded_channel();
        
        to_protocol_senders.push(to_proto_tx);
        to_protocol_receivers.push(to_proto_rx);
        from_protocol_senders.push(from_proto_tx);
        from_protocol_receivers.push(from_proto_rx);
        
        info!("Created channel pair {} for network-protocol communication", i);
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

    // TODO: Start protocol layer (async tasks)
    // Protocol layer will use:
    // - to_protocol_receivers: receive ingress packets from network tasks
    // - from_protocol_senders: send egress packets to network tasks
    // 
    // let protocol_handles = superd::protocol::quic_handler::start_protocol_layer(
    //     &config,
    //     to_protocol_receivers,
    //     from_protocol_senders,
    //     shutdown_tx.clone(),
    // );

    // TODO: Start application layer (dynamic per-stream tasks)
    // 
    // Application architecture:
    // - No pre-allocated threads
    // - Tasks spawned dynamically per QUIC stream
    // - Each stream gets its own task based on ALPN/stream type
    // - Tasks are ephemeral: created when stream opens, destroyed when stream closes
    // - Multiplexed streams over single QUIC connection run different apps
    // 
    // Example:
    // - HTTP/3 request: spawn http handler task
    // - WebSocket stream: spawn websocket handler task
    // - Custom protocol: spawn custom handler task
    // 
    // All tasks share the same tokio_uring runtime (no dedicated worker threads)

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