//! # Stream Data Reassembly Buffer (RFC 9000 Section 2.2)
//!
//! This module provides abstractions for handling out-of-order stream data delivery.
//!
//! ## Problem Statement
//!
//! QUIC packets can arrive out of order due to:
//! - Network reordering
//! - Packet loss and retransmission
//! - Multiple paths
//!
//! Stream data must be delivered to the application **in order** even when
//! STREAM frames arrive with gaps.
//!
//! ## Solution: Reassembly Buffer
//!
//! The reassembly buffer tracks:
//! 1. **Contiguous data**: Data that can be delivered immediately
//! 2. **Out-of-order ranges**: Data waiting for earlier bytes to arrive
//!
//! ## Zero-Copy Design
//!
//! The buffer stores **references** to packet data (`&[u8]`) rather than copying.
//! However, for a real implementation, this requires careful lifetime management
//! (packet buffers must outlive the reassembly buffer references).
//!
//! For production use, consider:
//! - Reference-counted buffers (`bytes::Bytes`)
//! - Arena allocation for packet storage
//! - Copy-on-arrival with preallocated buffers
//!
//! ## Interface Design
//!
//! This module defines the **trait interface** for reassembly buffers, not
//! the implementation. The actual data structure can be:
//! - Interval tree (for efficient range queries)
//! - Sorted vector of ranges (simpler, slower for many gaps)
//! - Circular buffer (for sequential delivery)

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use core::ops::Range;
use alloc::vec::Vec;

// ============================================================================
// Data Range Representation
// ============================================================================

/// A range of stream data with offset
///
/// Represents bytes `[offset, offset + data.len())` in the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataRange {
    /// Starting offset in the stream
    pub offset: u64,
    
    /// Length of the data
    pub length: usize,
}

impl DataRange {
    /// Create a new data range
    pub const fn new(offset: u64, length: usize) -> Self {
        Self { offset, length }
    }
    
    /// Get the end offset (exclusive)
    pub fn end(&self) -> u64 {
        self.offset + self.length as u64
    }
    
    /// Convert to a `Range<u64>`
    pub fn as_range(&self) -> Range<u64> {
        self.offset..self.end()
    }
    
    /// Check if this range overlaps with another
    pub fn overlaps(&self, other: &DataRange) -> bool {
        self.offset < other.end() && other.offset < self.end()
    }
    
    /// Check if this range is contiguous with another (adjacent or overlapping)
    pub fn is_contiguous_with(&self, other: &DataRange) -> bool {
        self.end() >= other.offset && other.end() >= self.offset
    }
}

// ============================================================================
// Trait: Reassembly Buffer
// ============================================================================

/// Stream Data Reassembly Buffer
///
/// Manages out-of-order stream data and provides in-order delivery to the application.
///
/// ## Operations
///
/// 1. **Insert**: Add a new data range (may be out of order)
/// 2. **Read**: Get contiguous data starting from the current read offset
/// 3. **Consume**: Advance the read offset after data has been delivered
///
/// ## Invariants
///
/// - Data must not overlap with already-consumed data
/// - Final size (if known) must not be exceeded
/// - Duplicate data (same offset range) should be ignored
///
/// ## Implementation Strategy
///
/// Implementations should track:
/// - `read_offset`: Next byte expected by the application
/// - `write_offset`: Highest contiguous byte received
/// - `ranges`: Out-of-order data ranges waiting for gaps to fill
pub trait ReassemblyBuffer {
    /// Insert received stream data at a specific offset
    ///
    /// # Arguments
    /// * `offset` - Stream offset of the first byte
    /// * `data` - The data bytes (implementation may copy or store reference)
    /// * `fin` - Whether this is the final data (FIN bit set)
    ///
    /// # Returns
    /// The new contiguous read offset after inserting this data.
    ///
    /// # Errors
    /// - `FinalSizeError` if data exceeds the known final size
    /// - `ProtocolViolation` if data overlaps with different content
    ///
    /// ## Example
    ///
    /// ```text
    /// State: [0..10] contiguous, read_offset = 10
    /// 
    /// insert(20, [b'x', b'y', b'z'], false)
    /// → Stored as out-of-order range [20..23]
    /// → Returns 10 (no change to contiguous data)
    ///
    /// insert(10, [b'a'..b'j'], false)
    /// → Merges with out-of-order range
    /// → Returns 23 (now all data [0..23] is contiguous)
    /// ```
    fn insert(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<u64>;
    
    /// Read contiguous data starting from the current read offset
    ///
    /// Returns a slice of bytes that can be delivered to the application.
    /// The slice may be shorter than requested if there are gaps.
    ///
    /// # Arguments
    /// * `max_len` - Maximum number of bytes to read
    ///
    /// # Returns
    /// A slice of contiguous data, or empty slice if no data is available.
    ///
    /// **Note**: The returned slice references internal buffer storage.
    /// Call `consume()` to advance the read offset after processing.
    fn read(&self, max_len: usize) -> &[u8];
    
    /// Consume (advance read offset) after data has been delivered
    ///
    /// # Arguments
    /// * `amount` - Number of bytes to consume
    ///
    /// # Errors
    /// Returns an error if `amount` exceeds available contiguous data.
    fn consume(&mut self, amount: u64) -> Result<()>;
    
    /// Get the current read offset (next byte to deliver to application)
    fn read_offset(&self) -> u64;
    
    /// Get the highest contiguous byte received (end of deliverable data)
    fn write_offset(&self) -> u64;
    
    /// Get the final size of the stream (if known)
    ///
    /// Returns `Some(size)` if the FIN flag has been received, `None` otherwise.
    fn final_size(&self) -> Option<u64>;
    
    /// Check if all data has been received (write_offset == final_size)
    fn is_complete(&self) -> bool {
        if let Some(final_size) = self.final_size() {
            self.write_offset() >= final_size
        } else {
            false
        }
    }
    
    /// Check if all data has been consumed (read_offset == final_size)
    fn is_fully_read(&self) -> bool {
        if let Some(final_size) = self.final_size() {
            self.read_offset() >= final_size
        } else {
            false
        }
    }
    
    /// Get the number of out-of-order ranges waiting to be delivered
    fn pending_ranges(&self) -> usize;
    
    /// Reset the buffer (discard all data)
    ///
    /// Used when a RESET_STREAM frame is received.
    fn reset(&mut self);
}

// ============================================================================
// Helper: Range Merging Logic
// ============================================================================

/// Merge overlapping or adjacent data ranges
///
/// Given a sorted list of ranges, returns a new list with merged ranges.
///
/// # Example
/// ```text
/// Input:  [0..5, 5..10, 15..20, 18..25]
/// Output: [0..10, 15..25]
/// ```
///
/// This is a helper function for implementing reassembly buffers.
pub fn merge_ranges(ranges: &mut Vec<DataRange>) {
    if ranges.len() <= 1 {
        return;
    }
    
    // Sort by starting offset
    ranges.sort_by_key(|r| r.offset);
    
    let mut merged = Vec::with_capacity(ranges.len());
    let mut current = ranges[0];
    
    for range in &ranges[1..] {
        if current.is_contiguous_with(range) {
            // Merge with current range
            let new_end = core::cmp::max(current.end(), range.end());
            current.length = (new_end - current.offset) as usize;
        } else {
            // No overlap, push current and start new range
            merged.push(current);
            current = *range;
        }
    }
    
    merged.push(current);
    *ranges = merged;
}

// ============================================================================
// Simple Implementation: Contiguous Buffer
// ============================================================================

/// A simple contiguous reassembly buffer (no out-of-order support)
///
/// This implementation only handles in-order data delivery. If data arrives
/// out of order, it is dropped. This is useful for testing or scenarios where
/// out-of-order delivery is not expected.
///
/// **Not suitable for production** - use an interval tree-based implementation instead.
#[derive(Debug)]
pub struct SimpleReassemblyBuffer {
    /// Next expected byte offset
    read_offset: u64,
    
    /// Highest contiguous byte received
    write_offset: u64,
    
    /// Final size of the stream (if FIN received)
    final_size: Option<u64>,
    
    /// Buffer storage (in a real implementation, this would be more sophisticated)
    /// For now, this is just a placeholder
    _buffer: (),
}

impl SimpleReassemblyBuffer {
    /// Create a new empty reassembly buffer
    pub const fn new() -> Self {
        Self {
            read_offset: 0,
            write_offset: 0,
            final_size: None,
            _buffer: (),
        }
    }
}

impl Default for SimpleReassemblyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyBuffer for SimpleReassemblyBuffer {
    fn insert(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<u64> {
        // Check final size constraint
        let end_offset = offset + data.len() as u64;
        if let Some(final_size) = self.final_size {
            if end_offset > final_size {
                return Err(Error::Transport(TransportError::FinalSizeError));
            }
        }
        
        // Only accept data that is contiguous with write_offset
        if offset != self.write_offset {
            // Out-of-order data - in this simple implementation, we drop it
            return Ok(self.write_offset);
        }
        
        // Update write_offset
        self.write_offset = end_offset;
        
        // Set final size if FIN
        if fin {
            if let Some(existing_final) = self.final_size {
                if end_offset != existing_final {
                    return Err(Error::Transport(TransportError::FinalSizeError));
                }
            } else {
                self.final_size = Some(end_offset);
            }
        }
        
        // In a real implementation, we would store the data here
        // For this trait demonstration, we just update offsets
        
        Ok(self.write_offset)
    }
    
    fn read(&self, _max_len: usize) -> &[u8] {
        // In a real implementation, return a slice of the buffer
        // For this demonstration, return empty slice
        &[]
    }
    
    fn consume(&mut self, amount: u64) -> Result<()> {
        let new_offset = self.read_offset + amount;
        if new_offset > self.write_offset {
            return Err(Error::InvalidInput);
        }
        self.read_offset = new_offset;
        Ok(())
    }
    
    fn read_offset(&self) -> u64 {
        self.read_offset
    }
    
    fn write_offset(&self) -> u64 {
        self.write_offset
    }
    
    fn final_size(&self) -> Option<u64> {
        self.final_size
    }
    
    fn pending_ranges(&self) -> usize {
        0 // Simple buffer has no out-of-order ranges
    }
    
    fn reset(&mut self) {
        self.read_offset = 0;
        self.write_offset = 0;
        self.final_size = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_data_range_overlap() {
        let r1 = DataRange::new(0, 10);
        let r2 = DataRange::new(5, 10);
        let r3 = DataRange::new(20, 10);
        
        assert!(r1.overlaps(&r2));
        assert!(r2.overlaps(&r1));
        assert!(!r1.overlaps(&r3));
    }
    
    #[test]
    fn test_simple_buffer_in_order() {
        let mut buf = SimpleReassemblyBuffer::new();
        
        // Insert data at offset 0
        let result = buf.insert(0, b"hello", false).unwrap();
        assert_eq!(result, 5);
        assert_eq!(buf.write_offset(), 5);
    }
}
