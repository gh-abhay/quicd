use tokio::net::UdpSocket;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use thiserror::Error;

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

/// Sans-IO I/O reactor for low-latency UDP operations
pub struct IoReactor {
    socket: UdpSocket,
    recv_buffer: BytesMut,
}

impl IoReactor {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            recv_buffer: BytesMut::with_capacity(65536),
        }
    }

    /// Receive a single packet for low latency
    pub async fn recv_packet(&mut self) -> Result<PacketIn> {
        self.recv_buffer.clear();
        let (len, from) = self.socket.recv_from(&mut self.recv_buffer).await?;
        let to = self.socket.local_addr()?;
        let data = self.recv_buffer.split_to(len).freeze();
        Ok(PacketIn { data, from, to })
    }

    /// Send a single packet immediately
    pub async fn send_packet(&self, packet: PacketOut) -> Result<()> {
        self.socket.send_to(&packet.data, &packet.to).await?;
        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}