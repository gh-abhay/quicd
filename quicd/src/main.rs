mod netio;
mod config;
mod runtime;
mod telemetry;

use anyhow::Context;
use std::net::SocketAddr;
use tokio::signal;
use tracing::info;

fn main() -> anyhow::Result<()> {
    let config = config::load_config()?;

    info!(?config, "configuration loaded");

    let bind_addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .with_context(|| "invalid bind address")?;
    let netio_cfg = config.netio.clone();
    let telemetry_cfg = config.telemetry.clone();

    // Use tokio-uring runtime for io_uring support
    info!("Starting tokio-uring runtime");
    tokio_uring::start(async move {
        // Initialize telemetry (logging + metrics)
        let metrics_handle = telemetry::init_telemetry(&telemetry_cfg)
            .await
            .with_context(|| "failed to initialize telemetry")?;

        info!("Telemetry system initialized");

        let netio_handle = netio::spawn(bind_addr, netio_cfg)
            .with_context(|| "failed to spawn network layer")?;

        info!(
            %bind_addr,
            workers = netio_handle.worker_count(),
            "Network IO layer started"
        );

        // Wait for Ctrl+C signal
        signal::ctrl_c()
            .await
            .context("failed to install Ctrl+C handler")?;

        info!("Shutdown signal received");

        // Gracefully shutdown network layer
        netio_handle.shutdown().await;

        // Shutdown telemetry
        metrics_handle.shutdown().await;

        Ok::<(), anyhow::Error>(())
    })
}