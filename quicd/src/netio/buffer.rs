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
//!
//! # Design Inspired by Cloudflare Quiche
//!
//! This implementation incorporates best practices from Cloudflare's quiche buffer-pool:
//! - `Reuse` trait for proper buffer cleanup and validation before pooling
//! - Only pool buffers with non-zero capacity (avoid wasting pool slots)
//! - `ConsumeBuffer` for zero-copy front consumption without data shifting
//! - Clear separation of concerns: pool management vs buffer usage

use crate::netio::config::BufferPoolConfig;
use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Maximum UDP payload size (IPv6 jumbo frame)
/// This is the absolute maximum for a single UDP datagram
pub const MAX_UDP_PAYLOAD: usize = 65536;

/// Trait for preparing items to be returned to the pool.
///
/// Inspired by Cloudflare's quiche buffer-pool. This trait ensures proper
/// cleanup and validation before buffers are returned to the pool.
///
/// Returns `true` if the item should be returned to the pool, `false` if
/// it should be dropped. This prevents pooling of unusable buffers.
pub trait Reuse {
    /// Prepare the item for reuse by cleaning it up.
    ///
    /// # Arguments
    ///
    /// * `trim` - Target capacity to shrink to
    ///
    /// # Returns
    ///
    /// `true` if the item has non-zero capacity and should be pooled,
    /// `false` if it should be dropped (e.g., zero capacity)
    fn reuse(&mut self, trim: usize) -> bool;
}

impl Reuse for Vec<u8> {
    fn reuse(&mut self, trim: usize) -> bool {
        self.clear();
        self.shrink_to(trim);
        // Only pool buffers with actual capacity
        // Empty buffers are a waste of pool slots
        self.capacity() > 0
    }
}

/// A convenience wrapper around Vec that allows consuming data from the
/// front **without** shifting.
///
/// Inspired by Cloudflare's quiche ConsumeBuffer. This is more ergonomic
/// and efficient than VecDeque for our use case:
/// - Single contiguous slice (not two like VecDeque)
/// - Zero-copy front consumption via head pointer adjustment
/// - Compatible with unsafe `set_len` for kernel I/O operations
///
/// # Use Cases
///
/// - Parsing protocol frames from received packets
/// - Progressive consumption of buffered data without reallocations
/// - Zero-copy packet processing pipelines
#[derive(Default, Debug)]
pub struct ConsumeBuffer {
    inner: Vec<u8>,
    /// Head offset - data before this point has been consumed
    head: usize,
}

impl ConsumeBuffer {
    /// Create a ConsumeBuffer from an existing Vec
    pub fn from_vec(inner: Vec<u8>) -> Self {
        ConsumeBuffer { inner, head: 0 }
    }

    /// Convert back to Vec, removing consumed data
    pub fn into_vec(self) -> Vec<u8> {
        let mut inner = self.inner;
        inner.drain(0..self.head);
        inner
    }

    /// Consume `count` bytes from the front without shifting memory
    ///
    /// # Panics
    ///
    /// Panics if `count` exceeds available data
    pub fn pop_front(&mut self, count: usize) {
        assert!(self.head + count <= self.inner.len());
        self.head += count;
    }

    /// Expand buffer capacity and set length
    ///
    /// # Safety
    ///
    /// Caller must ensure expanded bytes are initialized before reading
    pub fn expand(&mut self, count: usize) {
        self.inner.reserve_exact(count);
        // SAFETY: u8 is always initialized and we reserved the capacity.
        unsafe { self.inner.set_len(count) };
    }

    /// Truncate buffer to keep only first `count` bytes of unconsumed data
    pub fn truncate(&mut self, count: usize) {
        self.inner.truncate(self.head + count);
    }

    /// Add a prefix before the head pointer (zero-copy prepend)
    ///
    /// Returns `false` if there's insufficient consumed space for the prefix
    pub fn add_prefix(&mut self, prefix: &[u8]) -> bool {
        if self.head < prefix.len() {
            return false;
        }

        self.head -= prefix.len();
        self.inner[self.head..self.head + prefix.len()].copy_from_slice(prefix);

        true
    }

    /// Get remaining capacity available for writing
    pub fn remaining_capacity(&self) -> usize {
        self.inner.capacity() - self.inner.len()
    }
}

impl Deref for ConsumeBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner[self.head..]
    }
}

impl DerefMut for ConsumeBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner[self.head..]
    }
}

impl<'a> Extend<&'a u8> for ConsumeBuffer {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}

impl Reuse for ConsumeBuffer {
    fn reuse(&mut self, trim: usize) -> bool {
        self.inner.clear();
        self.inner.shrink_to(trim);
        self.head = 0;
        self.inner.capacity() > 0
    }
}

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
/// # Improved Pooling Strategy (from Cloudflare)
///
/// - Uses `Reuse` trait to validate and cleanup buffers before pooling
/// - Rejects zero-capacity buffers (waste of pool slots)
/// - Smart shrink_to logic to balance memory usage vs. reallocation cost
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
    /// Target size for shrinking buffers before pooling
    trim_size: usize,
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
    /// * `trim_size` - Target size for shrinking buffers before pooling
    pub fn new(max_buffers: usize, trim_size: usize) -> Self {
        Self {
            buffers: RefCell::new(Vec::with_capacity(max_buffers)),
            max_buffers,
            trim_size,
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
            .unwrap_or_else(|| Vec::with_capacity(self.trim_size))
    }

    /// Return a buffer to the pool (LIFO order) using Reuse trait.
    ///
    /// Buffer is pushed to the end of the Vec, making it the next
    /// to be allocated. If pool is full or buffer fails reuse validation,
    /// buffer is dropped.
    ///
    /// Following Cloudflare's pattern: only pool buffers with non-zero capacity.
    fn put(&self, mut buffer: Vec<u8>) {
        let mut buffers = self.buffers.borrow_mut();

        // Only keep buffer if pool isn't full AND buffer passes reuse validation
        if buffers.len() < self.max_buffers && buffer.reuse(self.trim_size) {
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

/// RAII wrapper for a pooled buffer with automatic return to pool on drop.
///
/// Inspired by Cloudflare's `Pooled<T>`. This wrapper ensures buffers are
/// always returned to the pool when dropped, following RAII principles.
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

    /// Take ownership of the inner buffer, preventing return to pool
    ///
    /// Use this when you need to transfer ownership and don't want the
    /// buffer to return to the pool on drop.
    pub fn into_inner(mut self) -> Vec<u8> {
        self.buffer.take().expect("buffer already taken")
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            // Return to pool (LIFO: pushed to end of Vec)
            // Reuse trait handles cleanup and validation
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

/// Buffer wrapper for io_uring operations with zero-copy guarantees.
///
/// This wraps the pooled buffer and provides safe APIs for:
/// - Receiving datagrams into the buffer
/// - Tracking received data length
/// - Zero-copy access to received data
/// - Automatic LIFO return to pool on drop
///
/// # Performance Optimizations
///
/// - Single allocation reused across many I/O operations
/// - LIFO pooling keeps buffers cache-hot
/// - Unsafe `set_len` avoids zero-initialization for kernel writes
/// - Clear separation between buffer capacity and data length
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

    /// Create a buffer from existing data.
    ///
    /// Takes a Vec, copies its data into a pooled buffer. Used for
    /// sending application-generated packets.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to copy into buffer
    /// * `pool` - Buffer pool reference
    pub fn from_vec(data: Vec<u8>, pool: &Arc<WorkerBufPool>) -> Self {
        let mut buf = pool.take();
        buf.clear();
        buf.extend_from_slice(&data);
        let len = data.len();
        Self {
            inner: PooledBuffer::new(buf, pool.clone()),
            len,
        }
    }

    /// Create a buffer from a slice (zero-copy if possible).
    ///
    /// # Arguments
    ///
    /// * `data` - Data to copy into buffer
    /// * `pool` - Buffer pool reference
    pub fn from_slice(data: &[u8], pool: &Arc<WorkerBufPool>) -> Self {
        let mut buf = pool.take();
        buf.clear();
        buf.extend_from_slice(data);
        Self {
            inner: PooledBuffer::new(buf, pool.clone()),
            len: data.len(),
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
    ///
    /// # Safety
    ///
    /// Uses unsafe `set_len` to avoid zero-initialization. The kernel
    /// will write to this buffer before we read from it, so uninitialized
    /// memory is acceptable. This provides significant performance benefit
    /// by avoiding memset operations on every buffer reuse.
    #[inline]
    pub fn as_mut_slice_for_io(&mut self) -> &mut [u8] {
        let inner = &mut *self.inner;

        // Ensure buffer has capacity for max UDP datagram
        if inner.capacity() < MAX_UDP_PAYLOAD {
            // Reserve the difference to reach MAX_UDP_PAYLOAD capacity
            inner.reserve(MAX_UDP_PAYLOAD - inner.capacity());
        }

        // Get the actual capacity and use that as the length
        // This way we use all available space for receiving
        let actual_capacity = inner.capacity();

        // Resize to actual capacity for recvmsg
        // SAFETY: We are passing this buffer to the kernel to fill via recvmsg.
        // We do not read the uninitialized bytes before the kernel writes to them.
        // Using set_len avoids the expensive zero-initialization of the buffer.
        unsafe {
            inner.set_len(actual_capacity);
        }

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

    /// Get the underlying buffer capacity
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Clear the buffer and reset length to zero
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
        self.len = 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reuse_trait_vec() {
        let mut vec = vec![1, 2, 3, 4, 5];
        assert!(vec.reuse(128));
        assert_eq!(vec.len(), 0);
        assert!(vec.capacity() > 0);
        assert!(vec.capacity() <= 128);

        // Zero-capacity buffers should not be pooled
        let mut empty = Vec::new();
        assert!(!empty.reuse(128));
    }

    #[test]
    fn test_consume_buffer_pop_front() {
        let mut buf = ConsumeBuffer::from_vec(vec![1, 2, 3, 4, 5]);
        assert_eq!(&buf[..], &[1, 2, 3, 4, 5]);

        buf.pop_front(2);
        assert_eq!(&buf[..], &[3, 4, 5]);

        buf.pop_front(3);
        assert_eq!(&buf[..], &[] as &[u8]);
    }

    #[test]
    fn test_consume_buffer_add_prefix() {
        let mut buf = ConsumeBuffer::from_vec(vec![0, 0, 3, 4, 5]);
        buf.pop_front(2); // Creates space at head
        assert_eq!(&buf[..], &[3, 4, 5]);

        assert!(buf.add_prefix(&[1, 2]));
        assert_eq!(&buf[..], &[1, 2, 3, 4, 5]);

        // Not enough space for larger prefix
        assert!(!buf.add_prefix(&[9, 8, 7]));
    }

    #[test]
    fn test_buffer_pool_lifo() {
        let config = BufferPoolConfig {
            max_buffers_per_worker: 4,
            datagram_size: 128,
        };
        let pool = create_worker_pool(&config);

        // Get 3 buffers
        let buf1 = pool.take();
        let buf2 = pool.take();
        let buf3 = pool.take();

        let ptr1 = buf1.as_ptr();
        let ptr2 = buf2.as_ptr();
        let ptr3 = buf3.as_ptr();

        // Return them
        pool.put(buf1);
        pool.put(buf2);
        pool.put(buf3);

        // Get them back - should be in LIFO order (3, 2, 1)
        let buf_a = pool.take();
        let buf_b = pool.take();
        let buf_c = pool.take();

        assert_eq!(buf_a.as_ptr(), ptr3);
        assert_eq!(buf_b.as_ptr(), ptr2);
        assert_eq!(buf_c.as_ptr(), ptr1);
    }

    #[test]
    fn test_pool_max_capacity() {
        let config = BufferPoolConfig {
            max_buffers_per_worker: 2,
            datagram_size: 128,
        };
        let pool = create_worker_pool(&config);

        let mut buffers = vec![];
        for _ in 0..10 {
            let mut buf = pool.take();
            buf.extend_from_slice(&[1, 2, 3]); // Give it capacity
            buffers.push(buf);
        }

        // Return all 10
        for buf in buffers {
            pool.put(buf);
        }

        // Pool should only keep 2 (max_buffers_per_worker)
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_pool_rejects_empty_buffers() {
        let config = BufferPoolConfig {
            max_buffers_per_worker: 10,
            datagram_size: 128,
        };
        let pool = create_worker_pool(&config);

        // Empty buffer should not be pooled
        let empty = Vec::new();
        pool.put(empty);
        assert_eq!(pool.len(), 0);

        // Buffer with capacity should be pooled
        let mut with_capacity = Vec::with_capacity(64);
        with_capacity.push(1);
        pool.put(with_capacity);
        assert_eq!(pool.len(), 1);
    }
}
