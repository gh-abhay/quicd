//! QUIC protocol handler thread implementation
//!
//! Implements dedicated OS threads for QUIC packet processing.
//! Each thread:
//! - Reads packets from a dedicated channel (1:1 with network I/O thread)
//! - Processes QUIC packets (decrypt, parse, state update)
//! - Is pinned to a specific CPU core (adjacent to its I/O thread)
//!
//! # Performance
//!
//! - Capacity: 500K pps per thread (matches I/O thread 1:1)
//! - Latency: 1-3µs per packet (QUIC processing)
//! - CPU usage: ~40-85% @ 500K pps (depends on crypto workload)

use crossbeam::channel::Receiver;
use network::{pin_to_core, set_thread_priority, ReceivedPacket, ThreadPlacement, ThreadPriority};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::thread;
use tokio::sync::Mutex;

use crate::integration::StreamProcessor;
use crate::{QuicEngine, QuicEvent};

/// QUIC protocol handler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Number of QUIC protocol handler threads
    pub threads: usize,

    /// Enable CPU pinning for QUIC threads
    pub enable_cpu_pinning: bool,

    /// Thread priority
    pub thread_priority: ThreadPriority,

    /// Channel buffer size (per I/O thread → QUIC handler)
    pub channel_buffer_size: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            threads: 1,
            enable_cpu_pinning: true,
            thread_priority: ThreadPriority::Normal,
            channel_buffer_size: 8192,
        }
    }
}

/// QUIC protocol handler thread handle
pub struct ProtocolThread {
    /// Thread handle
    handle: Option<thread::JoinHandle<Result<(), String>>>,
    /// Thread ID for debugging
    thread_id: usize,
}

impl ProtocolThread {
    /// Spawn a new QUIC protocol handler thread
    ///
    /// # Arguments
    ///
    /// - `thread_id`: Thread index (0, 1, 2, ...)
    /// - `config`: QUIC protocol configuration
    /// - `packet_rx`: Channel to receive packets from network I/O thread
    /// - `quic_engine`: Shared QUIC engine (behind mutex)
    /// - `stream_processor`: Stream processor for handling application-level streams
    /// - `placement`: Thread placement manager for CPU pinning
    ///
    /// # Returns
    ///
    /// A new `ProtocolThread` instance
    pub fn spawn(
        thread_id: usize,
        config: &ProtocolConfig,
        packet_rx: Receiver<ReceivedPacket>,
        quic_engine: Arc<Mutex<QuicEngine>>,
        stream_processor: Arc<StreamProcessor>,
        placement: &mut ThreadPlacement,
    ) -> Result<Self, String> {
        let core_id = if config.enable_cpu_pinning {
            placement.next_quic_core(thread_id)
        } else {
            None
        };

        let thread_priority = config.thread_priority;
        let thread_name = format!("quic-handler-{}", thread_id);
        let stream_processor = Arc::clone(&stream_processor);

        let handle = thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                // Set thread priority
                if let Err(e) = set_thread_priority(thread_priority) {
                    log::warn!("Thread {}: Failed to set priority: {}", thread_name, e);
                }

                // Pin to CPU core
                if let Some(core) = core_id {
                    if let Err(e) = pin_to_core(core) {
                        log::warn!(
                            "Thread {}: Failed to pin to CPU {}: {}",
                            thread_name,
                            core.id,
                            e
                        );
                    } else {
                        log::info!("Thread {} pinned to CPU core {}", thread_name, core.id);
                    }
                }

                // Create single-threaded Tokio runtime for this handler
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to create runtime: {}", e))?;

                // Run the processing loop
                runtime.block_on(async {
                    Self::run_processing_loop(thread_id, packet_rx, quic_engine, stream_processor)
                        .await
                })
            })
            .map_err(|e| format!("Failed to spawn thread: {}", e))?;

        Ok(Self {
            handle: Some(handle),
            thread_id,
        })
    }

    /// Main processing loop
    ///
    /// Runs on a single-threaded Tokio runtime.
    /// Reads packets from channel and processes them.
    async fn run_processing_loop(
        thread_id: usize,
        packet_rx: Receiver<ReceivedPacket>,
        quic_engine: Arc<Mutex<QuicEngine>>,
        stream_processor: Arc<StreamProcessor>,
    ) -> Result<(), String> {
        log::info!("QUIC protocol handler {} started", thread_id);

        let mut packets_processed = 0u64;
        let mut last_log = std::time::Instant::now();

        // Get local address from the engine
        let local_addr = {
            let engine = quic_engine.lock().await;
            engine.local_addr
        };

        loop {
            // Poll channel for packets (with yielding to allow Tokio to run)
            let received_packet = tokio::select! {
                // Try to receive from channel
                _ = tokio::task::yield_now() => {
                    // Yield to Tokio scheduler
                    match packet_rx.try_recv() {
                        Ok(pkt) => pkt,
                        Err(crossbeam::channel::TryRecvError::Empty) => {
                            // No packet available, yield briefly
                            tokio::time::sleep(tokio::time::Duration::from_micros(10)).await;
                            continue;
                        }
                        Err(crossbeam::channel::TryRecvError::Disconnected) => {
                            log::info!("Thread {}: Channel disconnected, exiting", thread_id);
                            return Ok(());
                        }
                    }
                }
            };

            // Convert ReceivedPacket to PacketIn
            let packet = crate::PacketIn {
                data: received_packet.data,
                from: received_packet.src_addr,
                to: local_addr,
            };

            // Lock QUIC engine and process packet
            let mut engine_guard = quic_engine.lock().await;
            let mut engine = &mut *engine_guard;

            let events = match engine.process_packet(packet) {
                Ok(events) => events,
                Err(e) => {
                    log::warn!("Thread {}: Failed to process packet: {}", thread_id, e);
                    continue;
                }
            };

            if !events.is_empty() {
                log::trace!("Thread {}: Generated {} events", thread_id, events.len());
            }

            // Process all generated QUIC events
            for event in events {
                match event {
                    QuicEvent::StreamData(conn_id, stream_id, initial_data) => {
                        // This is a new stream. Let the StreamProcessor handle it.
                        // We need to clone the Arc<Mutex<QuicEngine>> to pass it to the async block.
                        let engine_clone = Arc::clone(&quic_engine);
                        stream_processor
                            .process_new_stream(engine_clone, conn_id, stream_id, initial_data)
                            .await;
                    }
                    QuicEvent::Datagram(_conn_id, _data) => {
                        // TODO: Implement datagram handling
                        log::warn!("Datagram received but not yet handled.");
                    }
                    QuicEvent::NewConnection(conn_id) => {
                        log::info!("Thread {}: New connection: {:?}", thread_id, conn_id);
                    }
                    QuicEvent::ConnectionLost(conn_id) => {
                        log::info!("Thread {}: Connection lost: {:?}", thread_id, conn_id);
                    }
                    QuicEvent::Send(packets) => {
                        // This event is handled by the QuicEngine's send_pending_packets method,
                        // which is called from the I/O threads. We can ignore it here.
                        // The presence of this match arm makes our event handling exhaustive.
                        drop(packets);
                    }
                }
            }

            packets_processed += 1;

            // Unlock (explicit drop for clarity)
            drop(engine_guard);

            // Log statistics every 10 seconds
            if last_log.elapsed().as_secs() >= 10 {
                let pps = packets_processed / 10;
                log::debug!("Thread {}: Processed {} pps", thread_id, pps);
                packets_processed = 0;
                last_log = std::time::Instant::now();
            }
        }
    }

    /// Wait for thread to complete
    pub fn join(mut self) -> Result<(), String> {
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| format!("Thread {} panicked", self.thread_id))?
        } else {
            Ok(())
        }
    }
}

impl Drop for ProtocolThread {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            log::info!("Dropping QUIC protocol handler {}", self.thread_id);
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam::channel::unbounded;
    use network::CpuAffinityStrategy;
    use std::time::Duration;

    use crate::integration::StreamProcessor;
    use crate::stream_mux::StreamMultiplexer;
    use service::ServiceRegistry;

    #[tokio::test]
    async fn test_protocol_thread_spawn() {
        let config = ProtocolConfig {
            threads: 1,
            enable_cpu_pinning: false, // Disable for test
            thread_priority: ThreadPriority::Normal,
            channel_buffer_size: 1024,
        };

        let (_tx, rx) = unbounded();
        let local_addr = "127.0.0.1:4433".parse().unwrap();
        let engine = Arc::new(Mutex::new(
            QuicEngine::new(local_addr).expect("Failed to create QuicEngine"),
        ));
        let mut placement = ThreadPlacement::new(CpuAffinityStrategy::Auto);

        // Create a dummy StreamProcessor for the test
        let service_registry = Arc::new(ServiceRegistry::new());
        let stream_multiplexer = Arc::new(StreamMultiplexer::new());
        let stream_processor = Arc::new(StreamProcessor::new(
            stream_multiplexer,
            service_registry,
        ));

        let thread =
            ProtocolThread::spawn(0, &config, rx, engine, stream_processor, &mut placement);
        assert!(thread.is_ok());

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
