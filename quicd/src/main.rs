mod apps;
mod channel_config;
mod config;
mod netio;
mod routing;
mod runtime;
mod telemetry;
mod worker;

use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::info;

fn main() -> anyhow::Result<()> {
    // Check if running with sufficient privileges for eBPF
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!("quicd must be run with root privileges (sudo) for eBPF functionality");
    }
    let config = config::load_config()?;

    info!("Configuration loaded successfully");

    // Build application registry from configuration
    let app_registry = apps::build_registry(&config.applications)
        .with_context(|| "failed to build application registry")?;

    info!(
        "Application registry initialized with {} ALPN(s): {}",
        app_registry.len(),
        app_registry.alpns().join(", ")
    );

    let bind_addr: SocketAddr = format!(
        "{}:{}",
        config.global.network.host, config.global.network.port
    )
    .parse()
    .with_context(|| "invalid bind address")?;
    let netio_cfg = config.global.netio.clone();
    let telemetry_cfg = config.global.telemetry.clone();

    // Create tokio runtime for non-critical async tasks (telemetry, future app logic)
    info!("Creating tokio runtime for async tasks");
    let tokio_runtime = runtime::create_runtime(&config.global.runtime)
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
    crate::routing::initialize_router().with_context(|| {
        "failed to initialize eBPF routing - eBPF is mandatory for connection affinity"
    })?;

    info!("eBPF routing initialized successfully");

    // TLS configuration is now handled at the QUIC connection level using BoringSSL
    // Certificate paths are validated but loading is deferred to connection establishment
    info!("Validating TLS configuration");
    let cert_path = config.global.tls.cert_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing certificate path"))?;
    let key_path = config.global.tls.key_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing private key path"))?;

    // Verify files exist
    if !std::path::Path::new(cert_path).exists() {
        anyhow::bail!("Certificate file not found: {}", cert_path.display());
    }
    if !std::path::Path::new(key_path).exists() {
        anyhow::bail!("Private key file not found: {}", key_path.display());
    }
    
    info!("TLS certificate and key files validated");

    // Spawn network workers as native threads (NOT on tokio runtime)
    info!("Spawning network worker threads");
    let netio_handle = worker::spawn(
        bind_addr,
        netio_cfg,
        config.global.channels.clone(),
        runtime_handle.clone(),
        cert_path.clone(),
        key_path.clone(),
    )
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
