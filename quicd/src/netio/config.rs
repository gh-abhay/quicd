use serde::{Deserialize, Serialize};

/// Sensible defaults for QUIC datagram payloads.
pub const DEFAULT_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BufferPoolConfig {
    /// Maximum number of buffers kept in the global shared pool.
    /// This is the total across all workers.
    pub max_buffers: usize,
    /// Size in bytes to trim buffers to when returning to pool.
    /// Actual buffer capacity can grow beyond this during use.
    pub datagram_size: usize,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            max_buffers: 8192,
            datagram_size: DEFAULT_DATAGRAM_SIZE,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetIoConfig {
    /// Number of network I/O worker tasks to spawn.
    pub workers: usize,
    /// Enable SO_REUSEPORT so multiple workers can share the same UDP port.
    pub reuse_port: bool,
    /// Number of io_uring submission entries to request per worker.
    pub uring_entries: u32,
    /// Optional kernel receive buffer size.
    pub socket_recv_buffer_size: Option<usize>,
    /// Optional kernel send buffer size.
    pub socket_send_buffer_size: Option<usize>,
    /// Buffer pool tuning knobs.
    #[serde(default)]
    pub buffer_pool: BufferPoolConfig,
}

impl Default for NetIoConfig {
    fn default() -> Self {
        Self {
            workers: num_cpus::get().max(1),
            reuse_port: true,
            uring_entries: 512,
            socket_recv_buffer_size: None,
            socket_send_buffer_size: None,
            buffer_pool: BufferPoolConfig::default(),
        }
    }
}
