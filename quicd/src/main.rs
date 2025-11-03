mod config;
mod netio;
mod quic;
mod runtime;
mod telemetry;
mod worker;

use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::info;

fn main() -> anyhow::Result<()> {
    let config = config::load_config()?;

    info!(?config, "configuration loaded");

    let bind_addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .with_context(|| "invalid bind address")?;
    let netio_cfg = config.netio.clone();
    let quic_cfg = config.quic.clone();
    let telemetry_cfg = config.telemetry.clone();

    // Create tokio runtime for non-critical async tasks (telemetry, future app logic)
    info!("Creating tokio runtime for async tasks");
    let tokio_runtime = runtime::create_runtime(&config.runtime)
        .with_context(|| "failed to create tokio runtime")?;

    // Get runtime handle for explicit task spawning
    let runtime_handle = tokio_runtime.handle().clone();

    // Initialize telemetry on tokio runtime
    let metrics_handle = tokio_runtime.block_on(async {
        telemetry::init_telemetry(&telemetry_cfg, &runtime_handle)
            .await
            .with_context(|| "failed to initialize telemetry")
    })?;

    info!("Telemetry system initialized");

    // Initialize eBPF-based routing for connection affinity
    info!("Initializing eBPF-based QUIC routing");
    crate::quic::routing::initialize_router()
        .with_context(|| "failed to initialize eBPF routing")?;

    info!("eBPF routing initialized successfully");

    // Spawn network workers as native threads (NOT on tokio runtime)
    info!("Spawning network worker threads");
    let netio_handle = worker::spawn(bind_addr, netio_cfg, quic_cfg)
        .with_context(|| "failed to spawn network layer")?;

    info!(
        %bind_addr,
        workers = netio_handle.worker_count(),
        "Network IO layer started with native threads"
    );

    // Setup signal handler on tokio runtime
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_notify_clone = Arc::clone(&shutdown_notify);

    tokio_runtime.spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            eprintln!("Failed to install Ctrl+C handler: {}", e);
            return;
        }
        info!("Shutdown signal received");
        shutdown_notify_clone.notify_one();
    });

    // Wait for shutdown signal (blocks main thread)
    tokio_runtime.block_on(async {
        shutdown_notify.notified().await;
    });

    info!("Initiating graceful shutdown");

    // Shutdown network layer (blocks until workers exit)
    netio_handle.shutdown();

    // Shutdown telemetry
    tokio_runtime.block_on(async {
        metrics_handle.shutdown().await;
    });

    // Shutdown tokio runtime
    info!("Shutting down tokio runtime");
    tokio_runtime.shutdown_timeout(std::time::Duration::from_secs(5));

    info!("Shutdown complete");
    Ok(())
}
