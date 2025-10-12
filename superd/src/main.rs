//! superd - High-Performance QUIC Multi-Service Daemon
//!
//! Command-line interface for the superd daemon.

use clap::Parser;
use superd::{Superd, Config};

#[derive(Parser)]
#[command(name = "superd")]
#[command(about = "High-performance QUIC daemon optimized for maximum throughput and low latency")]
#[command(version)]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    listen: String,

    /// Maximum number of concurrent connections
    #[arg(long)]
    max_connections: Option<usize>,

    /// Channel buffer size for inter-task communication
    #[arg(long)]
    channel_buffer_size: Option<usize>,

    /// Socket receive buffer size in KB
    #[arg(long)]
    socket_recv_buffer_kb: Option<usize>,

    /// Socket send buffer size in KB
    #[arg(long)]
    socket_send_buffer_kb: Option<usize>,

    /// Enable debug mode (more verbose logging)
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    if std::env::var("RUST_LOG").is_ok() {
        // Use RUST_LOG if set
        env_logger::Builder::from_default_env().init();
    } else {
        // Default to info level
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    let args = Args::parse();
    let listen_addr = args.listen.parse()?;

    // Create configuration with best-in-class defaults
    let mut config = Config::new(listen_addr);

    // Override with CLI arguments if provided
    if let Some(max_conn) = args.max_connections {
        config.max_connections = max_conn;
    }
    if let Some(buf_size) = args.channel_buffer_size {
        config.channel_buffer_size = buf_size;
    }
    if let Some(recv_kb) = args.socket_recv_buffer_kb {
        config.socket_recv_buffer_size = recv_kb * 1024;
    }
    if let Some(send_kb) = args.socket_send_buffer_kb {
        config.socket_send_buffer_size = send_kb * 1024;
    }
    if args.debug {
        config.debug_mode = true;
    }

    // Validate configuration
    if let Err(e) = config.validate() {
        log::error!("Invalid configuration: {}", e);
        return Err(e.into());
    }

    // Log configuration
    log::info!("Starting superd with best-in-class performance settings");
    log::info!("  Listen address: {}", config.listen_addr);
    log::info!("  Max connections: {}", config.max_connections);
    log::info!("  Channel buffer: {} packets", config.channel_buffer_size);
    log::info!("  Socket buffers: {}MB recv, {}MB send", 
        config.socket_recv_buffer_size / (1024 * 1024),
        config.socket_send_buffer_size / (1024 * 1024));

    // Create and run the daemon
    let daemon = Superd::new(config).await?;
    daemon.run().await?;

    Ok(())
}