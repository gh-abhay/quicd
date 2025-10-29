//! Network worker tasks using pure event-driven async I/O with tokio-uring.
//!
//! Each worker is an async task that uses tokio::select! to wait on multiple
//! events without any polling:
//! - Ingress: io_uring recv completions
//! - Egress: TODO - will receive from upper protocol layer
//! - Shutdown: broadcast signal

use super::buffer::{UringBuffer, MAX_UDP_PAYLOAD};
use super::config::NetIoConfig;
use super::socket::bind_udp_socket;
use anyhow::Result;
use quiche::RecvInfo;
use std::io;
use std::net::SocketAddr;
use tokio::select;
use tokio::sync::broadcast;
use tokio_uring::net::UdpSocket;
use tracing::{debug, info, trace, warn};

/// Network worker task - purely event-driven with async/await
pub struct NetworkWorker {
    id: usize,
    socket: UdpSocket,
    local_addr: SocketAddr,
    shutdown_rx: broadcast::Receiver<()>,
}

impl NetworkWorker {
    /// Create a new network worker
    pub fn new(
        id: usize,
        bind_addr: SocketAddr,
        config: &NetIoConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<Self> {
        let std_socket = bind_udp_socket(bind_addr, config)?;
        let local_addr = std_socket.local_addr()?;
        let socket = UdpSocket::from_std(std_socket);

        debug!(
            worker_id = id,
            addr = %local_addr,
            "Network worker created"
        );

        Ok(Self {
            id,
            socket,
            local_addr,
            shutdown_rx,
        })
    }

    /// Run the event-driven worker loop
    pub async fn run(self) {
        info!(
            worker_id = self.id,
            addr = %self.local_addr,
            "Network worker starting event loop"
        );

        // Extract fields to avoid borrow checker issues in select!
        let mut socket = self.socket;
        let local_addr = self.local_addr;
        let worker_id = self.id;
        let mut shutdown_rx = self.shutdown_rx;

        loop {
            select! {
                // Event 1: Ingress - packet received from network
                recv_result = recv_packet(&mut socket) => {
                    match recv_result {
                        Ok((buffer, peer, bytes_read)) => {
                            handle_ingress(worker_id, local_addr, buffer, peer, bytes_read);
                        }
                        Err(e) => {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                warn!(
                                    worker_id,
                                    error = %e,
                                    "UDP receive error"
                                );
                            }
                        }
                    }
                }

                // Event 2: Shutdown signal
                _ = shutdown_rx.recv() => {
                    info!(worker_id, "Received shutdown signal");
                    break;
                }

                // TODO: Event 3: Egress - packets from upper protocol layer to send
            }
        }

        info!(worker_id, "Network worker shutting down");
    }
}

/// Receive a packet from the network using io_uring
async fn recv_packet(socket: &mut UdpSocket) -> io::Result<(UringBuffer, SocketAddr, usize)> {
    let mut buffer = UringBuffer::new();

    // Receive into a temporary Vec since tokio-uring requires owned buffer
    let temp_buf = vec![0u8; MAX_UDP_PAYLOAD];
    let (result, temp_buf) = socket.recv_from(temp_buf).await;
    let (bytes_read, peer_addr) = result?;

    // Copy received data into our pooled buffer
    buffer.copy_from_slice(&temp_buf[..bytes_read]);

    Ok((buffer, peer_addr, bytes_read))
}

/// Handle an ingress packet
fn handle_ingress(
    worker_id: usize,
    local_addr: SocketAddr,
    buffer: UringBuffer,
    from: SocketAddr,
    bytes_read: usize,
) {
    let recv_info = RecvInfo {
        from,
        to: local_addr,
    };

    trace!(
        worker_id,
        bytes = bytes_read,
        from = %recv_info.from,
        to = %recv_info.to,
        "Datagram received"
    );

    // TODO: Pass buffer and recv_info to upper protocol layer
    drop(buffer);
}
