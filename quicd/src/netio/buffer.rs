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
//! - **LIFO allocation**: Most recently returned buffers are reused first (cache-hot)
//! - Pool lives for entire worker lifetime (Arc-managed)
//!
//! # Performance Benefits
//!
//! - **Zero contention**: No shared state = no cache line bouncing
//! - **Cache locality**: Buffers stay in L1/L2 cache of single core (LIFO maximizes this)
//! - **Predictable latency**: No lock/unlock overhead
//! - **Linear scaling**: N workers = N independent pools
//! - **LIFO optimization**: Recently returned buffers are hottest in cache
//!
//! # LIFO Strategy
//!
//! Stack-based allocation ensures that the most recently returned buffer is reused
//! first. This dramatically improves cache hit rates because:
//! - Recently freed buffers are still hot in L1/L2/L3 cache
//! - Memory access patterns are predictable for CPU prefetcher
//! - Reduces cache pollution from cold buffers

use crate::netio::config::BufferPoolConfig;
use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Maximum UDP payload size (IPv6 jumbo frame)
/// This is the absolute maximum for a single UDP datagram
pub const MAX_UDP_PAYLOAD: usize = 65536;

/// LIFO buffer pool for single-threaded worker use.
///
/// This pool uses a simple Vec-based stack for O(1) push/pop operations.
/// Designed for **single-threaded** use (one per worker thread).
///
/// # LIFO Benefits
///
/// - Most recently returned buffers are reused first
/// - Maximizes CPU cache hit rates (L1/L2/L3)
/// - Predictable memory access patterns for hardware prefetching
/// - Simple Vec-based implementation with minimal overhead
///
/// # Thread Safety
///
/// Although this type implements `Sync`, it is **only safe to use from a single thread**.
/// The `Sync` implementation allows it to be wrapped in `Arc` for lifetime management
/// within a single worker thread. The pool is created in the main thread, passed to
/// a worker thread via `Arc`, and then accessed exclusively by that worker.
///
/// **SAFETY CONTRACT**: All buffers obtained from this pool must be dropped before
/// the worker thread terminates. The pool is never accessed concurrently from
/// multiple threads.
pub struct WorkerBufPool {
    /// Stack of available buffers (LIFO order)
    /// Last element is next to be allocated
    buffers: RefCell<Vec<Vec<u8>>>,
    /// Maximum number of buffers to keep in pool
    max_buffers: usize,
    /// Target size for each buffer
    buffer_size: usize,
}

// SAFETY: Although WorkerBufPool contains RefCell (which is !Sync), we manually
// implement Sync because the pool is only ever accessed from a single worker thread.
// The Arc<WorkerBufPool> is used solely for lifetime management (RAII) to ensure
// buffers can return to the pool when dropped. The Arc is never used to share
// access across multiple threads.
//
// This is safe because:
// 1. Pool is created in main thread
// 2. Arc is moved into exactly one worker thread
// 3. Worker thread accesses pool exclusively (no concurrent access)
// 4. All buffers are dropped before worker thread terminates
unsafe impl Sync for WorkerBufPool {}

impl WorkerBufPool {
    /// Create a new LIFO buffer pool.
    ///
    /// # Arguments
    ///
    /// * `max_buffers` - Maximum buffers to keep in pool
    /// * `buffer_size` - Target size for each buffer
    pub fn new(max_buffers: usize, buffer_size: usize) -> Self {
        Self {
            buffers: RefCell::new(Vec::with_capacity(max_buffers)),
            max_buffers,
            buffer_size,
        }
    }

    /// Get a buffer from the pool (LIFO order).
    ///
    /// If pool is empty, allocates a new buffer.
    /// Otherwise pops from the end of the Vec (most recently returned).
    fn take(&self) -> Vec<u8> {
        self.buffers
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.buffer_size))
    }

    /// Return a buffer to the pool (LIFO order).
    ///
    /// Buffer is pushed to the end of the Vec, making it the next
    /// to be allocated. If pool is full, buffer is dropped.
    fn put(&self, mut buffer: Vec<u8>) {
        let mut buffers = self.buffers.borrow_mut();
        
        // Only keep buffer if pool isn't full
        if buffers.len() < self.max_buffers {
            // Trim buffer to target size to prevent unbounded growth
            buffer.clear();
            buffer.shrink_to(self.buffer_size);
            
            // Push to end (LIFO: next to be allocated)
            buffers.push(buffer);
        }
        // else: buffer is dropped, returning memory to allocator
    }

    /// Get current number of buffers in pool
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.buffers.borrow().len()
    }

    /// Check if pool is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.buffers.borrow().is_empty()
    }
}

/// Create a new per-worker buffer pool wrapped in Arc.
///
/// **Must be called once per worker thread during initialization.**
/// Uses Arc for proper RAII - the pool will be automatically dropped
/// when all references are released.
///
/// # Arguments
///
/// * `config` - Buffer pool configuration
///
/// # Returns
///
/// An Arc-wrapped, isolated LIFO buffer pool for this worker
pub fn create_worker_pool(config: &BufferPoolConfig) -> Arc<WorkerBufPool> {
    Arc::new(WorkerBufPool::new(
        config.max_buffers_per_worker,
        config.datagram_size,
    ))
}

/// RAII wrapper for a pooled buffer.
///
/// When dropped, automatically returns the buffer to the pool (LIFO).
pub struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    pool: Arc<WorkerBufPool>,
}

impl PooledBuffer {
    /// Create a new pooled buffer
    fn new(buffer: Vec<u8>, pool: Arc<WorkerBufPool>) -> Self {
        Self {
            buffer: Some(buffer),
            pool,
        }
    }

    /// Take the inner buffer, preventing return to pool
    fn take(&mut self) -> Vec<u8> {
        self.buffer.take().expect("buffer already taken")
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            // Return to pool (LIFO: pushed to end of Vec)
            self.pool.put(buffer);
        }
    }
}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().expect("buffer was taken")
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().expect("buffer was taken")
    }
}

/// Buffer wrapper for io_uring operations.
///
/// This wraps the pooled buffer and provides safe APIs for:
/// - Receiving datagrams into the buffer
/// - Tracking received data length
/// - Zero-copy access to received data
/// - Automatic LIFO return to pool on drop
///
/// Holds an Arc to the buffer pool to ensure it remains alive
/// while this buffer is in use.
pub struct WorkerBuffer {
    inner: PooledBuffer,
    /// Actual length of received data (buffer capacity may be larger)
    len: usize,
}

impl WorkerBuffer {
    /// Create a new buffer from the worker's pool.
    ///
    /// Uses Arc for safe shared ownership of the buffer pool.
    /// Buffer is allocated from the pool in LIFO order (cache-hot).
    ///
    /// # Arguments
    ///
    /// * `pool` - Arc reference to the worker's buffer pool
    ///
    /// # Returns
    ///
    /// A new buffer ready for I/O operations
    pub fn new_from_pool(pool: Arc<WorkerBufPool>) -> Self {
        let buffer = pool.take();
        Self {
            inner: PooledBuffer::new(buffer, pool),
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
        let inner = &mut *self.inner;
        
        // Ensure buffer can hold max UDP datagram
        if inner.capacity() < MAX_UDP_PAYLOAD {
            inner.reserve(MAX_UDP_PAYLOAD - inner.capacity());
        }
        
        // Resize to max capacity for recvmsg
        inner.resize(MAX_UDP_PAYLOAD, 0);
        
        inner.as_mut_slice()
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

    /// Get mutable reference to the inner buffer for advanced use cases
    #[allow(dead_code)]
    #[inline]
    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.inner
    }
}

impl Deref for WorkerBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner[..self.len]
    }
}

// No DerefMut to prevent accidental modification of the length tracking
