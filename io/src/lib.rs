use tokio::net::UdpSocket;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use thiserror::Error;
use futures::future;

#[derive(Error, Debug)]
pub enum IoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, IoError>;

/// Input packet from network
#[derive(Debug)]
pub struct PacketIn {
    pub data: Bytes,
    pub from: SocketAddr,
    pub to: SocketAddr,
}

/// Output packet to network
#[derive(Debug)]
pub struct PacketOut {
    pub data: Bytes,
    pub to: SocketAddr,
}

/// Sans-IO I/O reactor for batched UDP operations
pub struct IoReactor {
    socket: UdpSocket,
    recv_buffer: BytesMut,
    max_batch_size: usize,
}

impl IoReactor {
    pub fn new(socket: UdpSocket, max_batch_size: usize) -> Self {
        Self {
            socket,
            recv_buffer: BytesMut::with_capacity(65536),
            max_batch_size,
        }
    }

    /// Receive batched packets
    pub async fn recv_packets(&mut self) -> Result<Vec<PacketIn>> {
        // For now, receive one packet at a time
        // TODO: Implement recvmmsg for batching
        let mut packets = Vec::new();

        // Try to receive up to max_batch_size packets
        for _ in 0..self.max_batch_size {
            self.recv_buffer.clear();
            match self.socket.try_recv_buf_from(&mut self.recv_buffer) {
                Ok((len, from)) => {
                    let data = self.recv_buffer.split_to(len).freeze();
                    let to = self.socket.local_addr()?;
                    packets.push(PacketIn { data, from, to });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No more packets available
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(packets)
    }

    /// Send batched packets
    pub async fn send_packets(&self, packets: Vec<PacketOut>) -> Result<()> {
        // For now, send one by one
        // TODO: Implement sendmmsg for batching
        for packet in packets {
            self.socket.send_to(&packet.data, &packet.to).await?;
        }
        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}