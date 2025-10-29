mod netio;
mod config;
mod runtime;

use anyhow::Context;
use std::net::SocketAddr;
use tokio::signal;
use tracing::{info, warn};

fn main() -> anyhow::Result<()> {
    let config = config::load_config()?;

    init_tracing(&config.log_level)?;
    info!(?config, "configuration loaded");

    let bind_addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .with_context(|| "invalid bind address")?;
    let netio_cfg = config.netio.clone();

    // Use tokio-uring runtime for io_uring support
    info!("Starting tokio-uring runtime");
    tokio_uring::start(async move {
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

        Ok::<(), anyhow::Error>(())
    })
}

fn init_tracing(level: &str) -> anyhow::Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_new(level)
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))?;

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .finish();

    if tracing::subscriber::set_global_default(subscriber).is_err() {
        warn!("tracing subscriber already initialized");
    }

    Ok(())
}