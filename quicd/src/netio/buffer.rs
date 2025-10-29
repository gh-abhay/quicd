//! Per-worker buffer pool for zero-copy operations.
//!
//! **Critical Design Principle**: Each worker thread owns its own buffer pool with
//! **ZERO SHARING** between workers. This eliminates all synchronization overhead
//! and maximizes cache locality.
//!
//! # Architecture
//!
//! - Each worker creates its own isolated `WorkerBufPool` at startup
//! - Buffers never cross thread boundaries
//! - No atomic operations, no locks, no contention in hot path
//! - Pool lives for entire worker lifetime (leaked with 'static lifetime)
//!
//! # Performance Benefits
//!
//! - **Zero contention**: No shared state = no cache line bouncing
//! - **Cache locality**: Buffers stay in L1/L2 cache of single core
//! - **Predictable latency**: No lock/unlock overhead
//! - **Linear scaling**: N workers = N independent pools

use crate::netio::config::BufferPoolConfig;
use buffer_pool::{Pool, Pooled};
use std::ops::{Deref, DerefMut};

/// Maximum UDP payload size (IPv6 jumbo frame)
/// This is the absolute maximum for a single UDP datagram
pub const MAX_UDP_PAYLOAD: usize = 65536;

/// Type alias for worker-local buffer pool.
///
/// Using single shard (1) because:
/// - This pool is thread-local (only accessed by one worker)
/// - No need for sharding overhead
/// - Simpler and faster than multi-shard design
pub type WorkerBufPool = Pool<1, buffer_pool::ConsumeBuffer>;

/// Type alias for a pooled buffer
pub type PooledBuf = Pooled<buffer_pool::ConsumeBuffer>;

/// Create a new per-worker buffer pool.
///
/// **Must be called once per worker thread during initialization.**
/// The returned pool should be leaked (Box::leak) to get 'static lifetime
/// since it lives for the entire worker thread lifetime.
///
/// # Arguments
///
/// * `config` - Buffer pool configuration
///
/// # Returns
///
/// A new, isolated buffer pool for this worker
pub fn create_worker_pool(config: &BufferPoolConfig) -> WorkerBufPool {
    WorkerBufPool::new(config.max_buffers_per_worker, config.datagram_size)
}

/// Buffer wrapper for io_uring operations.
///
/// This wraps the pooled buffer and provides safe APIs for:
/// - Receiving datagrams into the buffer
/// - Tracking received data length
/// - Zero-copy access to received data
pub struct WorkerBuffer {
    inner: PooledBuf,
    /// Actual length of received data (buffer capacity may be larger)
    len: usize,
}

impl WorkerBuffer {
    /// Create a new buffer from the worker's local pool.
    ///
    /// # Safety
    ///
    /// The pool reference must have 'static lifetime. In our architecture,
    /// we leak the pool at worker startup, so this is safe.
    ///
    /// # Arguments
    ///
    /// * `pool` - Reference to the leaked worker pool
    ///
    /// # Returns
    ///
    /// A new buffer ready for I/O operations
    pub unsafe fn new_from_leaked(pool: &'static WorkerBufPool) -> Self {
        Self {
            inner: pool.get_empty(),
            len: 0,
        }
    }

    /// Get the length of received data
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get buffer as a slice (only the received portion)
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner[..self.len]
    }

    /// Get buffer as a mutable slice for I/O operations.
    ///
    /// Ensures buffer has capacity for maximum UDP payload size.
    /// This is used for both recv and send operations with io_uring.
    #[inline]
    pub fn as_mut_slice_for_io(&mut self) -> &mut [u8] {
        // Ensure buffer can hold max UDP datagram
        let current_capacity = self.inner.len();
        if current_capacity < MAX_UDP_PAYLOAD {
            self.inner.expand(MAX_UDP_PAYLOAD - current_capacity);
        }
        &mut self.inner[..]
    }

    /// Set the actual received length after I/O completion.
    ///
    /// Called by io_uring completion handler after recvmsg completes.
    #[inline]
    pub fn set_received_len(&mut self, len: usize) {
        debug_assert!(
            len <= self.inner.len(),
            "received length exceeds buffer capacity"
        );
        self.len = len;
    }

    /// Get the inner buffer (for advanced use cases)
    #[inline]
    pub fn into_inner(self) -> PooledBuf {
        self.inner
    }
}

impl Deref for WorkerBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for WorkerBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
