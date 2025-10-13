//! superd - High-Performance QUIC Multi-Service Daemon (Architecture V2)
//!
//! This is the main entry point implementing the finalized three-layer architecture.

use std::sync::Arc;
use tokio::sync::Mutex;
use crossbeam::channel::bounded;

use crate::config_v2::ConfigV2;
use crate::thread_mgmt::ThreadPlacement;
use crate::network_io_thread::{NetworkIoThread, ReceivedPacket};
use crate::quic_protocol_thread::{QuicProtocolThread, QuicEngine};

/// Main daemon struct implementing the three-layer architecture
///
/// # Architecture
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │                  superd Architecture V2                      │
/// ├─────────────────────────────────────────────────────────────┤
/// │                                                               │
/// │  Layer 1: Network I/O Threads (OS threads, CPU-pinned)       │
/// │  ├─ Thread 0: UDP recv/send → Channel 0                     │
/// │  ├─ Thread 1: UDP recv/send → Channel 1                     │
/// │  └─ ...                                                       │
/// │                                                               │
/// │  Layer 2: QUIC Protocol Handlers (OS threads, CPU-pinned)    │
/// │  ├─ Handler 0: Channel 0 → QUIC processing                  │
/// │  ├─ Handler 1: Channel 1 → QUIC processing                  │
/// │  └─ ...                                                       │
/// │                                                               │
/// │  Layer 3: Connection Management (Tokio tasks)                │
/// │  ├─ Task 1: Connection 1                                     │
/// │  ├─ Task 2: Connection 2                                     │
/// │  └─ ... (100K+ tasks)                                        │
/// │                                                               │
/// │  Tokio Runtime: Multi-threaded work-stealing runtime         │
/// │  └─ Workers: Dedicated or Shared CPUs (configurable)        │
/// │                                                               │
/// └─────────────────────────────────────────────────────────────┘
/// ```
pub struct SuperdV2 {
    /// Configuration
    config: ConfigV2,
    
    /// Network I/O threads
    io_threads: Vec<NetworkIoThread>,
    
    /// QUIC protocol handler threads
    quic_threads: Vec<QuicProtocolThread>,
    
    /// Shared QUIC engine
    quic_engine: Arc<Mutex<QuicEngine>>,
    
    /// Tokio runtime handle
    runtime: tokio::runtime::Runtime,
}

impl SuperdV2 {
    /// Create a new superd instance
    ///
    /// # Arguments
    ///
    /// - `config`: Configuration (use `ConfigV2::default()` for optimal settings)
    ///
    /// # Returns
    ///
    /// A new `SuperdV2` instance ready to run
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration validation fails
    /// - Tokio runtime creation fails
    /// - Thread spawning fails
    pub fn new(config: ConfigV2) -> Result<Self, String> {
        // Validate configuration
        config.validate()?;
        
        // Display configuration summary
        config.display_summary();
        
        // Create Tokio runtime based on configuration
        let tokio_workers = config.tokio_worker_count();
        let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
        runtime_builder.worker_threads(tokio_workers);
        runtime_builder.thread_name("superd-tokio");
        runtime_builder.enable_all();
        
        if let Some(stack_size) = config.tokio_runtime.thread_stack_size {
            runtime_builder.thread_stack_size(stack_size);
        }
        
        let runtime = runtime_builder
            .build()
            .map_err(|e| format!("Failed to create Tokio runtime: {}", e))?;
        
        log::info!("✓ Tokio runtime created with {} workers", tokio_workers);
        
        // Create shared QUIC engine
        let quic_engine = Arc::new(Mutex::new(QuicEngine::new()));
        log::info!("✓ QUIC engine initialized");
        
        Ok(Self {
            config,
            io_threads: Vec::new(),
            quic_threads: Vec::new(),
            quic_engine,
            runtime,
        })
    }
    
    /// Start the daemon
    ///
    /// This spawns all threads and starts processing.
    ///
    /// # Errors
    ///
    /// Returns an error if thread spawning fails.
    pub fn start(&mut self) -> Result<(), String> {
        let num_threads = self.config.network_io.threads;
        let listen_addr = self.config.server.listen_addr;
        let channel_size = self.config.quic_protocol.channel_buffer_size;
        
        log::info!("Starting superd with {} I/O threads...", num_threads);
        
        // Create thread placement manager
        let mut placement = ThreadPlacement::new(
            self.config.network_io.cpu_affinity_strategy
        );
        
        // Spawn network I/O threads and QUIC protocol handlers (1:1 pairs)
        for i in 0..num_threads {
            // Create channel for this I/O thread → QUIC handler pair
            let (tx, rx) = bounded::<ReceivedPacket>(channel_size);
            
            // Spawn network I/O thread
            let io_thread = NetworkIoThread::spawn(
                i,
                listen_addr,
                &self.config.network_io,
                self.config.server.enable_reuseport,
                tx,
                &mut placement,
            )?;
            
            log::info!("✓ Network I/O thread {} spawned", i);
            self.io_threads.push(io_thread);
            
            // Spawn QUIC protocol handler thread
            let quic_thread = QuicProtocolThread::spawn(
                i,
                &self.config.quic_protocol,
                rx,
                Arc::clone(&self.quic_engine),
                &mut placement,
            )?;
            
            log::info!("✓ QUIC protocol handler {} spawned", i);
            self.quic_threads.push(quic_thread);
        }
        
        log::info!("╔═══════════════════════════════════════════════════════════╗");
        log::info!("║  superd is running!                                       ║");
        log::info!("║                                                           ║");
        log::info!("║  Listening on: {}                              ║", listen_addr);
        log::info!("║  Network I/O threads: {}                                ║", num_threads);
        log::info!("║  QUIC handlers: {}                                      ║", num_threads);
        log::info!("║  Tokio workers: {}                                      ║", self.config.tokio_worker_count());
        log::info!("║                                                           ║");
        log::info!("║  Ready to serve 100K+ concurrent connections              ║");
        log::info!("║  Target: 1M+ packets/sec                                  ║");
        log::info!("╚═══════════════════════════════════════════════════════════╝");
        
        Ok(())
    }
    
    /// Wait for all threads to complete
    ///
    /// This blocks until the daemon is shut down.
    pub fn wait(self) -> Result<(), String> {
        log::info!("Waiting for threads to complete...");
        
        // Join all I/O threads
        for (i, thread) in self.io_threads.into_iter().enumerate() {
            thread.join()
                .map_err(|e| format!("I/O thread {} failed: {}", i, e))?;
        }
        
        // Join all QUIC threads
        for (i, thread) in self.quic_threads.into_iter().enumerate() {
            thread.join()
                .map_err(|e| format!("QUIC thread {} failed: {}", i, e))?;
        }
        
        // Shutdown Tokio runtime
        self.runtime.shutdown_timeout(std::time::Duration::from_secs(5));
        
        log::info!("All threads completed successfully");
        Ok(())
    }
    
    /// Run the daemon (start + wait)
    ///
    /// Convenience method that calls `start()` followed by `wait()`.
    pub fn run(mut self) -> Result<(), String> {
        self.start()?;
        self.wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_daemon_creation() {
        let config = ConfigV2::default();
        let daemon = SuperdV2::new(config);
        assert!(daemon.is_ok());
    }
    
    #[test]
    fn test_default_config_validation() {
        let config = ConfigV2::default();
        assert!(config.validate().is_ok());
    }
}
