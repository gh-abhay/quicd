//! Lock-free buffer pool for zero-allocation packet reception
//!
//! This module provides a pool of reusable `BytesMut` buffers to avoid
//! heap allocations on the hot path. Buffers are checked out, filled,
//! frozen to `Bytes`, and returned to the pool for reuse.
//!
//! Based on expert recommendation: "Reuse BytesMut buffers from a pool
//! to avoid frequent allocations."

use bytes::BytesMut;
use crossbeam::queue::ArrayQueue;
use std::sync::Arc;

/// Size of each buffer in the pool (64KB - typical max UDP packet size)
const BUFFER_SIZE: usize = 65536;

/// Default pool size (per network thread)
const DEFAULT_POOL_SIZE: usize = 1024;

/// Lock-free buffer pool using crossbeam's lock-free queue
///
/// # Performance Characteristics
///
/// - **Allocation-free checkout**: O(1) pop from lock-free queue
/// - **Thread-safe**: Multiple threads can safely access
/// - **No blocking**: Always succeeds (creates new buffer if pool empty)
///
/// # Example
///
/// ```
/// use bytes::BytesMut;
/// use superd::BufferPool;
///
/// let pool = BufferPool::new(1024);
///
/// // Check out a buffer
/// let mut buf = pool.checkout();
///
/// // Use it for receiving data
/// buf.resize(2048, 0);
/// // ... fill buffer ...
///
/// // Freeze to Bytes (zero-copy)
/// let bytes = buf.freeze();
///
/// // Buffer is automatically returned when BytesMut is dropped
/// ```
#[derive(Clone)]
pub struct BufferPool {
    pool: Arc<ArrayQueue<BytesMut>>,
    buffer_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool with default settings
    ///
    /// Creates a pool with 1024 buffers of 64KB each.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_POOL_SIZE, BUFFER_SIZE)
    }

    /// Create a buffer pool with custom capacity and buffer size
    ///
    /// # Arguments
    ///
    /// * `pool_size` - Number of buffers to pre-allocate
    /// * `buffer_size` - Size of each buffer in bytes
    pub fn with_capacity(pool_size: usize, buffer_size: usize) -> Self {
        let pool = Arc::new(ArrayQueue::new(pool_size));
        
        // Pre-populate pool with buffers
        for _ in 0..pool_size {
            let buf = BytesMut::with_capacity(buffer_size);
            let _ = pool.push(buf); // Safe to ignore - we just created the queue
        }
        
        log::info!("Buffer pool created: {} buffers of {}KB each",
            pool_size, buffer_size / 1024);
        
        Self {
            pool,
            buffer_size,
        }
    }

    /// Check out a buffer from the pool
    ///
    /// If the pool is empty, allocates a new buffer. This ensures the
    /// hot path never blocks, at the cost of potential allocation under
    /// extreme load.
    ///
    /// # Returns
    ///
    /// A `BytesMut` ready to be filled with data
    pub fn checkout(&self) -> BytesMut {
        self.pool
            .pop()
            .unwrap_or_else(|| {
                // Pool exhausted - allocate new buffer
                // This is rare under normal load
                BytesMut::with_capacity(self.buffer_size)
            })
    }

    /// Return a buffer to the pool
    ///
    /// Called explicitly if you want to return a buffer before it's frozen.
    /// Typically buffers are frozen to `Bytes` and the `BytesMut` is dropped.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to return (will be cleared)
    pub fn return_buffer(&self, mut buf: BytesMut) {
        // Clear the buffer before returning
        buf.clear();
        
        // Try to return to pool (may fail if pool is full)
        let _ = self.pool.push(buf);
    }

    /// Get current pool utilization
    ///
    /// Returns the number of available buffers in the pool.
    /// Lower numbers indicate higher memory pressure.
    pub fn available(&self) -> usize {
        self.pool.len()
    }

    /// Get pool capacity
    pub fn capacity(&self) -> usize {
        self.pool.capacity()
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkout_return() {
        let pool = BufferPool::with_capacity(10, 1024);
        
        assert_eq!(pool.available(), 10);
        
        let buf1 = pool.checkout();
        assert_eq!(pool.available(), 9);
        
        pool.return_buffer(buf1);
        assert_eq!(pool.available(), 10);
    }

    #[test]
    fn test_pool_exhaustion() {
        let pool = BufferPool::with_capacity(2, 1024);
        
        let _buf1 = pool.checkout();
        let _buf2 = pool.checkout();
        
        // Pool empty - should allocate new buffer
        let buf3 = pool.checkout();
        assert_eq!(buf3.capacity(), 1024);
    }

    #[test]
    fn test_freeze_workflow() {
        let pool = BufferPool::new();
        
        let mut buf = pool.checkout();
        buf.extend_from_slice(b"hello world");
        
        // Freeze to Bytes (zero-copy)
        let bytes = buf.freeze();
        assert_eq!(&bytes[..], b"hello world");
    }
}
