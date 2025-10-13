//! Configuration module for superd
//!
//! This module defines the configuration structure for the superd daemon,
//! with defaults optimized for maximum performance and scalability.

use std::net::SocketAddr;
use std::time::Duration;

/// Server configuration optimized for high-performance production deployments
///
/// # Performance Philosophy
///
/// All defaults are set to achieve maximum throughput and scalability on modern hardware.
/// These settings are inspired by proven systems like Discord and Cloudflare:
///
/// - **Large buffers**: Prevent blocking and packet loss under heavy load
/// - **High connection limits**: Support massive concurrent user bases
/// - **Aggressive cleanup**: Keep resource usage lean
/// - **Efficient monitoring**: Low-overhead observability
///
/// All values can be customized via CLI arguments or code.
#[derive(Debug, Clone)]
pub struct Config {
    /// UDP socket address to bind to
    pub listen_addr: SocketAddr,
    
    /// Maximum number of concurrent QUIC connections
    /// 
    /// Default: 100,000 connections
    /// Inspired by Discord's architecture (millions of concurrent users)
    pub max_connections: usize,
    
    /// Channel buffer size for inter-task communication
    ///
    /// Default: 8192 packets
    /// Large buffers prevent backpressure and maximize throughput
    pub channel_buffer_size: usize,
    
    /// Metrics logging interval
    ///
    /// Default: 10 seconds
    /// How often to log performance statistics
    pub metrics_interval: Duration,
    
    /// Connection cleanup interval
    ///
    /// Default: 60 seconds
    /// How often to prune stale connections
    pub cleanup_interval: Duration,
    
    /// Enable detailed debug logging
    ///
    /// Default: false
    /// Only enable for troubleshooting (impacts performance)
    pub debug_mode: bool,
    
    /// Socket buffer sizes (SO_RCVBUF, SO_SNDBUF)
    ///
    /// Default: 8MB each
    /// Cloudflare-inspired large buffers prevent packet loss at high throughput
    pub socket_recv_buffer_size: usize,
    pub socket_send_buffer_size: usize,
    
    /// Number of dedicated network I/O threads
    ///
    /// Default: Number of CPU cores (up to 8)
    /// Each thread gets its own socket with SO_REUSEPORT for kernel-level load balancing
    pub network_threads: usize,
    
    /// Enable SO_REUSEPORT for multi-threaded network I/O
    ///
    /// Default: true
    /// Allows multiple threads to bind to the same port, with kernel load balancing
    pub reuse_port: bool,
}

impl Config {
    /// Create a new configuration with best-in-class defaults
    ///
    /// All defaults are optimized for maximum performance and scalability.
    /// These settings are production-ready out of the box.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::SocketAddr;
    /// use superd::Config;
    ///
    /// let addr: SocketAddr = "0.0.0.0:4433".parse().unwrap();
    /// let config = Config::new(addr);
    /// 
    /// // Customize specific values as needed
    /// let mut custom_config = Config::new(addr);
    /// custom_config.max_connections = 50_000;
    /// custom_config.debug_mode = true;
    /// ```
    pub fn new(listen_addr: SocketAddr) -> Self {
        // Determine optimal number of network threads
        // Use min(num_cpus, 8) - more threads don't help for UDP
        let network_threads = num_cpus::get().min(8).max(1);
        
        Self {
            listen_addr,
            // Best-of-the-best defaults for maximum performance
            max_connections: 100_000,
            channel_buffer_size: 8192,
            metrics_interval: Duration::from_secs(10),
            cleanup_interval: Duration::from_secs(60),
            debug_mode: false,
            socket_recv_buffer_size: 8 * 1024 * 1024, // 8MB
            socket_send_buffer_size: 8 * 1024 * 1024, // 8MB
            network_threads,
            reuse_port: true,
        }
    }
    
    /// Validate configuration values
    ///
    /// Returns an error if any configuration value is invalid
    pub fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0 {
            return Err("max_connections must be greater than 0".to_string());
        }
        
        if self.channel_buffer_size == 0 {
            return Err("channel_buffer_size must be greater than 0".to_string());
        }
        
        if self.socket_recv_buffer_size < 64 * 1024 {
            return Err("socket_recv_buffer_size should be at least 64KB".to_string());
        }
        
        if self.socket_send_buffer_size < 64 * 1024 {
            return Err("socket_send_buffer_size should be at least 64KB".to_string());
        }
        
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new("0.0.0.0:4433".parse().unwrap())
    }
}
