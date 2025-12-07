//! Lock-free dynamic table for QPACK.
//!
//! Implements a zero-allocation, high-performance dynamic table with:
//! - Circular buffer with fixed capacity for stable slot indices
//! - hashbrown HashMap for O(1) lookups
//! - Reference counting for eviction safety
//! - Safe, single-threaded ownership model (Encoder/Decoder own their tables)

extern crate alloc;
use alloc::vec::Vec;
use core::hash::{BuildHasher, Hash, Hasher};

use bytes::Bytes;
use hashbrown::HashMap;
use smallvec::SmallVec;

use crate::error::{QpackError, Result};

/// Dynamic table entry overhead per RFC 9204 Section 3.2.1.
/// Entry size = name.len() + value.len() + 32
const ENTRY_OVERHEAD: usize = 32;

/// Maximum dynamic table capacity per RFC 9204 Section 3.2.2.
/// Capacity MUST NOT exceed 2^30 (1,073,741,824 bytes).
const MAX_TABLE_CAPACITY: usize = 1 << 30;

/// Dynamic table entry with zero-copy name and value.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Header field name (zero-copy via Bytes).
    pub name: Bytes,
    /// Header field value (zero-copy via Bytes).
    pub value: Bytes,
    /// Absolute insertion index (monotonically increasing).
    pub absolute_index: u64,
    /// Reference count for eviction safety.
    pub ref_count: u32,
}

impl Entry {
    /// Calculate entry size per RFC 9204.
    #[inline]
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// Zero-allocation dynamic table with circular buffer and hash indexing.
///
/// # Design
/// - Circular buffer: Vec<Option<Entry>> with head/tail indices
/// - Hash indexing: HashMap for O(1) lookup
/// - Single owner: Encoder/Decoder own the table exclusively
pub struct DynamicTable {
    /// Circular buffer of entries.
    entries: Vec<Option<Entry>>,

    /// Head index (oldest entry) in circular buffer.
    head: usize,

    /// Tail index (next insertion position) in circular buffer.
    tail: usize,

    /// Maximum number of entries in the circular buffer.
    max_entries: usize,

    /// Total insert count (absolute, monotonic).
    insert_count: u64,

    /// Current dynamic table size in bytes.
    current_size: usize,

    /// Current dynamic table capacity in bytes.
    capacity: usize,

    /// Maximum allowed capacity (hard limit set at creation).
    max_capacity: usize,

    /// Known Received Count (from decoder acknowledgements).
    known_received_count: u64,

    /// HashMap for exact (name,value) lookups.
    /// Key: (name, value)
    /// Value: List of absolute indices (newest first)
    exact_index: HashMap<(Bytes, Bytes), SmallVec<[u64; 1]>>,

    /// HashMap for name-only lookups.
    /// Key: name
    /// Value: List of absolute indices (newest first)
    name_index: HashMap<Bytes, SmallVec<[u64; 1]>>,
}

impl DynamicTable {
    /// Create a new dynamic table with given maximum capacity.
    /// 
    /// # RFC 9204 Section 3.2.2
    /// Maximum capacity MUST NOT exceed 2^30 bytes (1,073,741,824).
    /// 
    /// # Panics
    /// Panics if max_capacity > 2^30.
    pub fn new(max_capacity: usize) -> Self {
        // RFC 9204 Section 3.2.2: Capacity MUST NOT exceed 2^30
        assert!(
            max_capacity <= MAX_TABLE_CAPACITY,
            "max_capacity ({}) exceeds RFC 9204 limit of 2^30 ({})",
            max_capacity,
            MAX_TABLE_CAPACITY
        );

        // Calculate max entries based on min entry size (32 bytes overhead + empty name/value)
        // Ensure at least 16 slots to avoid edge cases with small capacities
        let max_entries = core::cmp::max(max_capacity / 32, 16);

        let mut entries = Vec::with_capacity(max_entries);
        for _ in 0..max_entries {
            entries.push(None);
        }

        Self {
            entries,
            head: 0,
            tail: 0,
            max_entries,
            insert_count: 0,
            current_size: 0,
            capacity: 0,
            max_capacity,
            known_received_count: 0,
            exact_index: HashMap::with_capacity(128),
            name_index: HashMap::with_capacity(128),
        }
    }

    /// Get current insert count (absolute).
    #[inline]
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Get known received count.
    #[inline]
    pub fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    /// Get current capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get maximum capacity (hard limit).
    #[inline]
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Get current size in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.current_size
    }

    /// Get number of entries currently in table.
    #[inline]
    pub fn len(&self) -> usize {
        if self.tail >= self.head {
            self.tail - self.head
        } else {
            self.max_entries - self.head + self.tail
        }
    }

    /// Check if table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set dynamic table capacity.
    /// May trigger eviction if current size exceeds new capacity.
    /// 
    /// # RFC 9204 Section 3.2.2
    /// Capacity MUST NOT exceed 2^30 bytes.
    pub fn set_capacity(&mut self, new_capacity: usize) -> Result<()> {
        // RFC 9204 Section 3.2.2: Capacity MUST NOT exceed 2^30
        if new_capacity > MAX_TABLE_CAPACITY {
            return Err(QpackError::TableCapacityExceeded);
        }

        // Cannot exceed the maximum capacity set at table creation
        if new_capacity > self.max_capacity {
            return Err(QpackError::TableCapacityExceeded);
        }

        self.capacity = new_capacity;

        // Evict entries if current size exceeds new capacity
        while self.size() > new_capacity && !self.is_empty() {
            self.evict_oldest()?;
        }

        Ok(())
    }

    /// Update known received count (from Insert Count Increment).
    ///
    /// RFC 9204 Section 2.1.4: Known Received Count can wrap around.
    /// We use wrapping arithmetic to handle overflow gracefully.
    pub fn update_known_received_count(&mut self, increment: u64) {
        self.known_received_count = self.known_received_count.wrapping_add(increment);
    }

    /// Update known received count to the maximum of current and new value.
    pub fn update_known_received_count_max(&mut self, count: u64) {
        if count > self.known_received_count {
            self.known_received_count = count;
        }
    }

    /// Insert an entry into the dynamic table.
    /// Returns the absolute index of the inserted entry.
    pub fn insert(&mut self, name: Bytes, value: Bytes) -> Result<u64> {
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
        let capacity = self.capacity();

        // Check if entry fits in table at all
        if entry_size > capacity {
            return Err(QpackError::TableCapacityExceeded);
        }

        // Evict entries until we have space
        while self.size() + entry_size > capacity && !self.is_empty() {
            self.evict_oldest()?;
        }

        let absolute_index = self.insert_count;

        let entry = Entry {
            name: name.clone(),
            value: value.clone(),
            absolute_index,
            ref_count: 0,
        };

        // Store entry
        self.entries[self.tail] = Some(entry);

        // Update indices
        self.exact_index
            .entry((name.clone(), value.clone()))
            .or_default()
            .insert(0, absolute_index); // newest first

        self.name_index
            .entry(name)
            .or_default()
            .insert(0, absolute_index); // newest first

        // Advance tail
        self.tail = (self.tail + 1) % self.max_entries;

        // Update counters
        self.insert_count += 1;
        self.current_size += entry_size;

        Ok(absolute_index)
    }

    /// Evict the oldest entry from the table.
    /// 
    /// RFC 9204 Section 2.1.1: Entries with non-zero reference counts cannot be evicted.
    fn evict_oldest(&mut self) -> Result<()> {
        if self.head == self.tail && self.entries[self.head].is_none() {
            return Ok(()); // Table is empty
        }

        // Check ref count
        if let Some(entry) = &self.entries[self.head] {
            if entry.ref_count > 0 {
                return Err(QpackError::Internal(
                    format!("Cannot evict entry at head {} with ref_count {}", self.head, entry.ref_count)
                ));
            }
        } else {
            // Should not happen if table is not empty
            return Ok(());
        }

        // Remove entry
        let entry = self.entries[self.head].take().unwrap();
        let entry_size = entry.size();
        self.current_size -= entry_size;

        // Remove from indices
        if let Some(indices) = self.exact_index.get_mut(&(entry.name.clone(), entry.value.clone())) {
            indices.retain(|idx| *idx != entry.absolute_index);
            if indices.is_empty() {
                self.exact_index.remove(&(entry.name.clone(), entry.value.clone()));
            }
        }

        if let Some(indices) = self.name_index.get_mut(&entry.name) {
            indices.retain(|idx| *idx != entry.absolute_index);
            if indices.is_empty() {
                self.name_index.remove(&entry.name);
            }
        }

        // Advance head
        self.head = (self.head + 1) % self.max_entries;

        Ok(())
    }

    /// Get entry by absolute index.
    pub fn get(&self, absolute_index: u64) -> Option<&Entry> {
        if absolute_index >= self.insert_count {
            return None;
        }

        // Calculate relative index from head
        // The oldest entry (at head) has absolute_index = insert_count - len
        let len = self.len() as u64;
        let oldest_index = self.insert_count.saturating_sub(len);

        if absolute_index < oldest_index {
            return None; // Evicted
        }

        // Calculate slot
        // slot = (head + (absolute_index - oldest_index)) % max_entries
        let offset = (absolute_index - oldest_index) as usize;
        let slot = (self.head + offset) % self.max_entries;

        if let Some(entry) = &self.entries[slot] {
            if entry.absolute_index == absolute_index {
                return Some(entry);
            }
        }

        None
    }

    /// Find entry by exact name and value match.
    /// Returns absolute index if found.
    #[inline]
    pub fn find_exact(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        let mut hasher = self.exact_index.hasher().build_hasher();
        (name, value).hash(&mut hasher);
        let hash = hasher.finish();

        if let Some(entry) = self.exact_index.raw_entry().from_hash(hash, |(k_name, k_value)| {
            k_name.as_ref() == name && k_value.as_ref() == value
        }) {
            entry.1.first().copied()
        } else {
            None
        }
    }

    /// Find entry by name only.
    /// Returns absolute index of first (newest) match.
    #[inline]
    pub fn find_name(&self, name: &[u8]) -> Option<u64> {
        if let Some(indices) = self.name_index.get(name) {
            if let Some(&idx) = indices.first() {
                return Some(idx);
            }
        }
        None
    }

    /// Check if an entry is in the "draining" region.
    /// Draining entries are those not yet acknowledged by the decoder.
    pub fn is_draining(&self, absolute_index: u64) -> bool {
        absolute_index >= self.known_received_count
    }

    /// Increment reference count for an entry.
    pub fn increment_ref_count(&mut self, absolute_index: u64) -> bool {
        let len = self.len() as u64;
        let oldest_index = self.insert_count.saturating_sub(len);

        if absolute_index < oldest_index || absolute_index >= self.insert_count {
            return false;
        }

        let offset = (absolute_index - oldest_index) as usize;
        let slot = (self.head + offset) % self.max_entries;

        if let Some(entry) = &mut self.entries[slot] {
            if entry.absolute_index == absolute_index {
                entry.ref_count += 1;
                return true;
            }
        }
        
        false
    }

    /// Decrement reference count for an entry.
    pub fn decrement_ref_count(&mut self, absolute_index: u64) -> bool {
        let len = self.len() as u64;
        let oldest_index = self.insert_count.saturating_sub(len);

        if absolute_index < oldest_index || absolute_index >= self.insert_count {
            return false;
        }

        let offset = (absolute_index - oldest_index) as usize;
        let slot = (self.head + offset) % self.max_entries;

        if let Some(entry) = &mut self.entries[slot] {
            if entry.absolute_index == absolute_index {
                if entry.ref_count > 0 {
                    entry.ref_count -= 1;
                }
                return true;
            }
        }
        
        false
    }

    /// Check if an entry can be evicted (ref_count == 0).
    pub fn can_evict(&self, absolute_index: u64) -> bool {
        if let Some(entry) = self.get(absolute_index) {
            return entry.ref_count == 0;
        }
        true // Already evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let mut table = DynamicTable::new(4096);
        table.set_capacity(4096).unwrap();

        let idx = table
            .insert(Bytes::from_static(b":method"), Bytes::from_static(b"GET"))
            .unwrap();

        assert_eq!(idx, 0);
        assert_eq!(table.insert_count(), 1);

        let entry = table.get(idx).unwrap();
        assert_eq!(entry.name.as_ref(), b":method");
        assert_eq!(entry.value.as_ref(), b"GET");
    }

    #[test]
    fn test_eviction() {
        let mut table = DynamicTable::new(100);
        table.set_capacity(100).unwrap();

        // Insert entries that exceed capacity
        for i in 0..5 {
            let name = Bytes::from(format!("header-{}", i));
            let value = Bytes::from("value");
            let _ = table.insert(name, value).unwrap();
        }

        // Oldest entries should be evicted
        assert!(table.get(0).is_none()); // Evicted
        assert!(table.get(4).is_some()); // Still present
    }

    #[test]
    fn test_find_exact() {
        let mut table = DynamicTable::new(4096);
        table.set_capacity(4096).unwrap();

        table
            .insert(
                Bytes::from_static(b"content-type"),
                Bytes::from_static(b"text/html"),
            )
            .unwrap();

        let idx = table.find_exact(b"content-type", b"text/html");
        assert_eq!(idx, Some(0));

        let no_match = table.find_exact(b"content-type", b"text/plain");
        assert_eq!(no_match, None);
    }

    #[test]
    fn test_find_name() {
        let mut table = DynamicTable::new(4096);
        table.set_capacity(4096).unwrap();

        table
            .insert(
                Bytes::from_static(b"accept"),
                Bytes::from_static(b"text/html"),
            )
            .unwrap();

        table
            .insert(
                Bytes::from_static(b"accept"),
                Bytes::from_static(b"application/json"),
            )
            .unwrap();

        // Should return newest entry
        let idx = table.find_name(b"accept");
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn test_capacity_change() {
        let mut table = DynamicTable::new(200);
        table.set_capacity(200).unwrap();

        table
            .insert(
                Bytes::from_static(b"large-header"),
                Bytes::from_static(b"large-value"),
            )
            .unwrap();

        // Reduce capacity, should trigger eviction
        table.set_capacity(50).unwrap();

        assert_eq!(table.len(), 0);
    }
}
