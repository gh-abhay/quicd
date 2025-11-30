use serde::{Deserialize, Serialize};

/// Sensible defaults for QUIC datagram payloads.
pub const DEFAULT_DATAGRAM_SIZE: usize = 1350;

/// Default number of io_uring submission queue entries.
/// Power of 2 for optimal io_uring performance.
pub const DEFAULT_URING_ENTRIES: u32 = 2048;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BufferPoolConfig {
    /// Maximum number of buffers per worker pool.
    /// Each worker gets its own dedicated pool with this capacity.
    /// This is completely isolated - no sharing between workers.
    pub max_buffers_per_worker: usize,
    /// Size in bytes to trim buffers to when returning to pool.
    /// Actual buffer capacity can grow beyond this during use.
    pub datagram_size: usize,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            max_buffers_per_worker: 2048, // Per worker, not global
            datagram_size: DEFAULT_DATAGRAM_SIZE,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetIoConfig {
    /// Number of network I/O worker threads to spawn.
    /// Each worker is a native OS thread pinned to a CPU core.
    /// Defaults to number of CPU cores.
    pub workers: usize,

    /// Enable SO_REUSEPORT so multiple workers can share the same UDP port.
    /// This distributes incoming packets across workers at the kernel level.
    pub reuse_port: bool,

    /// Pin each worker thread to a specific CPU core for cache locality.
    /// Highly recommended for maximum performance.
    #[serde(default = "default_true")]
    pub pin_to_cpu: bool,

    /// Number of io_uring submission queue entries per worker.
    /// Must be a power of 2. Higher values allow more in-flight operations
    /// but consume more memory. Typical values: 1024, 2048, 4096.
    #[serde(default = "default_uring_entries")]
    pub uring_entries: u32,

    /// Optional kernel receive buffer size (SO_RCVBUF).
    /// Larger buffers reduce packet loss under burst traffic.
    pub socket_recv_buffer_size: Option<usize>,

    /// Optional kernel send buffer size (SO_SNDBUF).
    /// Larger buffers improve throughput for high-rate sending.
    pub socket_send_buffer_size: Option<usize>,

    /// Buffer pool configuration (per worker).
    /// Each worker has its own isolated buffer pool - zero sharing.
    #[serde(default)]
    pub buffer_pool: BufferPoolConfig,

    /// Enable UDP GRO (Generic Receive Offload) for batch packet receiving.
    ///
    /// When enabled, the kernel coalesces multiple UDP packets into a single
    /// buffer, reducing per-packet overhead and improving throughput.
    ///
    /// **Platform**: Linux 5.0+ only (gracefully degrades on other platforms)
    /// **Impact**: 2-3x improvement in receive throughput for high packet rates
    /// **Used by**: Cloudflare, Discord, and other high-performance UDP services
    #[serde(default = "default_true")]
    pub enable_gro: bool,

    /// Enable UDP GSO (Generic Segmentation Offload) for batch packet sending.
    ///
    /// When enabled, allows sending multiple packets in a single sendmsg() call,
    /// with the kernel handling segmentation. Dramatically reduces syscall overhead.
    ///
    /// **Platform**: Linux 4.18+ only (gracefully degrades on other platforms)
    /// **Impact**: 3-5x improvement in send throughput at high packet rates
    /// **Used by**: Cloudflare (QUIC servers), kernel bypass alternatives
    #[serde(default = "default_true")]
    pub enable_gso: bool,

    /// Maximum size for coalesced UDP packets (default: 1400 bytes).
    ///
    /// When sending multiple packets to the same destination, they are coalesced
    /// into a single datagram up to this size to reduce syscall overhead.
    /// Should be ≤ MTU to avoid fragmentation.
    #[serde(default = "default_max_coalesced_size")]
    pub max_coalesced_size: usize,
}

fn default_true() -> bool {
    true
}

fn default_uring_entries() -> u32 {
    DEFAULT_URING_ENTRIES
}

fn default_max_coalesced_size() -> usize {
    1400
}

impl Default for NetIoConfig {
    fn default() -> Self {
        Self {
            workers: num_cpus::get().max(1),
            reuse_port: true,
            pin_to_cpu: true,
            uring_entries: DEFAULT_URING_ENTRIES,
            socket_recv_buffer_size: None,
            socket_send_buffer_size: None,
            buffer_pool: BufferPoolConfig::default(),
            enable_gro: true, // Enable by default (no-op on unsupported platforms)
            enable_gso: true, // Enable by default (no-op on unsupported platforms)
            max_coalesced_size: default_max_coalesced_size(),
        }
    }
}
