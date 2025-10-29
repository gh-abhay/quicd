//! Global buffer pool using buffer-pool crate for zero-copy operations.
//!
//! Uses ConsumeBuffer for efficient buffer management and pre-allocated pools
//! to minimize runtime allocations.

use crate::netio::config::BufferPoolConfig;
use buffer_pool::{Pool, Pooled};
use once_cell::sync::OnceCell;
use std::ops::{Deref, DerefMut};
use tokio_uring::buf::{IoBuf, IoBufMut};

/// Maximum UDP payload size (standard IPv6 jumbo frame)
pub const MAX_UDP_PAYLOAD: usize = 65536;

/// Type alias for the shared buffer pool with 8 shards for reduced contention
pub type BufPool = Pool<8, buffer_pool::ConsumeBuffer>;

/// Type alias for a pooled buffer
pub type PooledBuf = Pooled<buffer_pool::ConsumeBuffer>;

/// Global buffer pool instance shared across all network workers
static BUFFER_POOL: OnceCell<BufPool> = OnceCell::new();

/// Initialize the global buffer pool. Must be called once before any workers start.
///
/// # Panics
/// Panics if called more than once.
pub fn init_buffer_pool(config: &BufferPoolConfig) {
    let pool = BufPool::new(config.max_buffers, config.datagram_size);
    BUFFER_POOL
        .set(pool)
        .expect("Buffer pool already initialized");
}

/// Get a reference to the global buffer pool.
///
/// # Panics
/// Panics if buffer pool has not been initialized.
pub fn get_buffer_pool() -> &'static BufPool {
    BUFFER_POOL
        .get()
        .expect("Buffer pool not initialized - call init_buffer_pool first")
}

/// Wrapper around PooledBuf that implements tokio-uring IoBuf traits.
///
/// This allows zero-copy buffer usage with io_uring while maintaining
/// the benefits of buffer pooling.
pub struct UringBuffer {
    inner: PooledBuf,
}

#[allow(dead_code)]
impl UringBuffer {
    /// Create a new buffer from the global pool
    pub fn new() -> Self {
        let pool = get_buffer_pool();
        Self {
            inner: pool.get_empty(),
        }
    }

    /// Get the length of initialized data
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Expand the buffer to hold more data
    pub fn expand(&mut self, additional: usize) {
        self.inner.expand(additional);
    }

    /// Copy data from a slice into the buffer
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        self.expand(src.len());
        self.inner[..src.len()].copy_from_slice(src);
    }
}

impl Default for UringBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for UringBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for UringBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// SAFETY: UringBuffer wraps ConsumeBuffer from buffer-pool, which provides
// stable memory addresses. The Pooled wrapper ensures the buffer stays alive
// for the duration of the I/O operation, and tokio-uring ensures operations
// complete before the buffer is dropped.
unsafe impl IoBuf for UringBuffer {
    fn stable_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.inner.len()
    }

    fn bytes_total(&self) -> usize {
        MAX_UDP_PAYLOAD
    }
}

unsafe impl IoBufMut for UringBuffer {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }

    unsafe fn set_init(&mut self, pos: usize) {
        // ConsumeBuffer handles length internally via expand
        let current_len = self.inner.len();
        if pos > current_len {
            self.inner.expand(pos - current_len);
        }
    }
}
