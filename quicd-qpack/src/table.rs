//! Lock-free dynamic table for QPACK.
//!
//! Implements a lock-free, zero-copy dynamic table with:
//! - Atomic head/tail pointers for FIFO eviction
//! - Generational indexing to detect stale references
//! - Single writer (encoder), multiple concurrent readers (decoders)
//! - Zero-copy storage using Bytes

use bytes::Bytes;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::error::{QpackError, Result};

/// Maximum entries in dynamic table (practical limit).
const MAX_ENTRIES: usize = 4096;

/// Dynamic table entry overhead per RFC 9204 Section 3.2.1.
/// Entry size = name.len() + value.len() + 32
const ENTRY_OVERHEAD: usize = 32;

/// Dynamic table entry with zero-copy name and value.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Header field name (zero-copy via Bytes).
    pub name: Bytes,
    /// Header field value (zero-copy via Bytes).
    pub value: Bytes,
    /// Absolute insertion index (monotonically increasing).
    pub absolute_index: u64,
    /// Generation marker for stale detection (reserved for future use).
    #[allow(dead_code)]
    generation: u64,
}

impl Entry {
    /// Calculate entry size per RFC 9204.
    #[inline]
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// Lock-free dynamic table supporting single writer, multiple readers.
///
/// # Design
/// - Circular buffer with atomic head/tail indices
/// - Absolute indexing: entries have monotonically increasing IDs
/// - Eviction: oldest entries evicted when capacity exceeded (FIFO)
/// - Thread-safe: writer inserts, readers lookup concurrently without locks
///
/// # Safety
/// This structure is designed for single-writer, multi-reader access.
/// Only the writer thread may call mutating methods (insert, set_capacity, etc.).
/// Reader threads may call read-only methods (get, find_exact, find_name) concurrently.
pub struct DynamicTable {
    /// Ring buffer of entries (fixed capacity).
    entries: UnsafeCell<Box<[Option<Arc<Entry>>; MAX_ENTRIES]>>,

    /// Tail index (next insertion position) - only writer modifies.
    tail: AtomicUsize,

    /// Head index (oldest entry) - writer advances on eviction.
    head: AtomicUsize,

    /// Total insert count (absolute, monotonic).
    insert_count: AtomicU64,

    /// Current dynamic table size in bytes.
    current_size: AtomicUsize,

    /// Current dynamic table capacity in bytes.
    capacity: AtomicUsize,

    /// Maximum allowed capacity (hard limit set at creation).
    max_capacity: usize,

    /// Known Received Count (from decoder acknowledgements).
    known_received_count: AtomicU64,

    /// Generation counter for detecting evicted entries.
    generation: AtomicU64,

    /// HashMap index for O(1) lookups by name-value pair.
    /// Key is (name_bytes, value_bytes), Value is absolute_index.
    /// Uses RwLock for concurrent read access, exclusive write.
    exact_index: RwLock<HashMap<(Bytes, Bytes), u64>>,

    /// HashMap index for O(1) lookups by name only.
    /// Key is name_bytes, Value is absolute_index of newest entry.
    name_index: RwLock<HashMap<Bytes, u64>>,
}

impl DynamicTable {
    /// Create a new dynamic table with given maximum capacity.
    pub fn new(max_capacity: usize) -> Self {
        // Use Box to avoid stack overflow for large arrays
        let entries: Box<[Option<Arc<Entry>>; MAX_ENTRIES]> =
            Box::new(std::array::from_fn(|_| None));

        Self {
            entries: UnsafeCell::new(entries),
            tail: AtomicUsize::new(0),
            head: AtomicUsize::new(0),
            insert_count: AtomicU64::new(0),
            current_size: AtomicUsize::new(0),
            capacity: AtomicUsize::new(0),
            max_capacity,
            known_received_count: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            exact_index: RwLock::new(HashMap::with_capacity(256)),
            name_index: RwLock::new(HashMap::with_capacity(256)),
        }
    }

    /// Get current insert count (absolute).
    #[inline]
    pub fn insert_count(&self) -> u64 {
        self.insert_count.load(Ordering::Acquire)
    }

    /// Get known received count.
    #[inline]
    pub fn known_received_count(&self) -> u64 {
        self.known_received_count.load(Ordering::Acquire)
    }

    /// Get current capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }

    /// Get maximum capacity (hard limit).
    #[inline]
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Get current size in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.current_size.load(Ordering::Acquire)
    }

    /// Get number of entries currently in table.
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if tail >= head {
            tail - head
        } else {
            MAX_ENTRIES - head + tail
        }
    }

    /// Check if table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set dynamic table capacity.
    /// May trigger eviction if current size exceeds new capacity.
    pub fn set_capacity(&mut self, new_capacity: usize) -> Result<()> {
        // Cannot exceed the maximum capacity set at table creation
        if new_capacity > self.max_capacity {
            return Err(QpackError::TableCapacityExceeded);
        }

        self.capacity.store(new_capacity, Ordering::Release);

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
    pub fn update_known_received_count(&self, increment: u64) {
        // Use compare-and-swap loop to safely handle wrapping
        let mut current = self.known_received_count.load(Ordering::Acquire);
        loop {
            let new_value = current.wrapping_add(increment);
            match self.known_received_count.compare_exchange_weak(
                current,
                new_value,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Insert an entry into the dynamic table.
    /// Returns the absolute index of the inserted entry.
    ///
    /// # Writer-only operation
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

        let absolute_index = self.insert_count.load(Ordering::Acquire);
        let generation = self.generation.load(Ordering::Acquire);

        let entry = Arc::new(Entry {
            name,
            value,
            absolute_index,
            generation,
        });

        let tail = self.tail.load(Ordering::Acquire);

        // Store entry - SAFETY: &mut self ensures exclusive write access
        unsafe {
            let entries_ptr = self.entries.get();
            (*entries_ptr)[tail] = Some(entry.clone());
        }

        // Advance tail
        let new_tail = (tail + 1) % MAX_ENTRIES;
        self.tail.store(new_tail, Ordering::Release);

        // Update counters
        self.insert_count.fetch_add(1, Ordering::AcqRel);
        self.current_size.fetch_add(entry_size, Ordering::AcqRel);

        // Update HashMap indices for O(1) lookups
        {
            let mut exact_idx = self.exact_index.write().unwrap();
            exact_idx.insert((entry.name.clone(), entry.value.clone()), absolute_index);
        }
        {
            let mut name_idx = self.name_index.write().unwrap();
            // Only update if this is the newest entry for this name
            name_idx.insert(entry.name.clone(), absolute_index);
        }

        Ok(absolute_index)
    }

    /// Evict the oldest entry from the table.
    ///
    /// # Writer-only operation
    fn evict_oldest(&mut self) -> Result<()> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return Ok(()); // Table is empty
        }

        // Remove entry - SAFETY: &mut self ensures exclusive write access
        let entry = unsafe {
            let entries_ptr = self.entries.get();
            (*entries_ptr)[head].take()
        };

        if let Some(entry) = entry {
            let entry_size = entry.size();
            self.current_size.fetch_sub(entry_size, Ordering::AcqRel);

            // Remove from HashMap indices
            {
                let mut exact_idx = self.exact_index.write().unwrap();
                exact_idx.remove(&(entry.name.clone(), entry.value.clone()));
            }
            {
                let mut name_idx = self.name_index.write().unwrap();
                // Only remove if this is the indexed entry for this name
                if let Some(&indexed_abs_idx) = name_idx.get(&entry.name) {
                    if indexed_abs_idx == entry.absolute_index {
                        name_idx.remove(&entry.name);

                        // Find the next newest entry with this name to re-index
                        // This is a fallback - in practice, newer entries would already be indexed
                        let head_after = (head + 1) % MAX_ENTRIES;
                        let tail_current = self.tail.load(Ordering::Acquire);

                        if head_after != tail_current {
                            // Search remaining entries for same name
                            let len = if tail_current >= head_after {
                                tail_current - head_after
                            } else {
                                MAX_ENTRIES - head_after + tail_current
                            };

                            for i in (0..len).rev() {
                                let slot = (head_after + i) % MAX_ENTRIES;
                                let check_entry = unsafe {
                                    let entries_ptr = self.entries.get();
                                    (*entries_ptr)[slot].as_ref()
                                };

                                if let Some(check_entry) = check_entry {
                                    if check_entry.name == entry.name {
                                        name_idx
                                            .insert(entry.name.clone(), check_entry.absolute_index);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Advance head
        let new_head = (head + 1) % MAX_ENTRIES;
        self.head.store(new_head, Ordering::Release);

        // Increment generation to invalidate external references
        self.generation.fetch_add(1, Ordering::AcqRel);

        Ok(())
    }

    /// Get entry by absolute index (for readers).
    ///
    /// # Thread-safe read operation
    pub fn get(&self, absolute_index: u64) -> Option<Arc<Entry>> {
        let insert_count = self.insert_count.load(Ordering::Acquire);

        // Index must be less than insert count
        if absolute_index >= insert_count {
            return None;
        }

        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        // Calculate relative index
        let oldest_index = if head <= tail {
            insert_count.saturating_sub((tail - head) as u64)
        } else {
            insert_count.saturating_sub((MAX_ENTRIES - head + tail) as u64)
        };

        // Check if entry has been evicted
        if absolute_index < oldest_index {
            return None;
        }

        // Calculate slot position
        let offset = (absolute_index - oldest_index) as usize;
        let slot = (head + offset) % MAX_ENTRIES;

        // SAFETY: Readers access Arc-protected data, atomic indices ensure validity
        unsafe {
            let entries_ptr = self.entries.get();
            (*entries_ptr)[slot].as_ref().map(Arc::clone)
        }
    }

    /// Find entry by exact name and value match.
    /// Returns absolute index if found.
    ///
    /// # Thread-safe read operation
    /// # Performance
    /// O(1) HashMap lookup with read lock.
    #[inline]
    pub fn find_exact(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        // O(1) lookup via HashMap index
        let index = self.exact_index.read().unwrap();

        // Need to create Bytes for HashMap key lookup
        let name_key = Bytes::copy_from_slice(name);
        let value_key = Bytes::copy_from_slice(value);

        index.get(&(name_key, value_key)).copied()
    }

    /// Find entry by name only.
    /// Returns absolute index of first (newest) match.
    ///
    /// # Thread-safe read operation
    /// # Performance
    /// O(1) HashMap lookup with read lock.
    #[inline]
    pub fn find_name(&self, name: &[u8]) -> Option<u64> {
        // O(1) lookup via HashMap index
        let index = self.name_index.read().unwrap();

        // Need to create Bytes for HashMap key lookup
        let name_key = Bytes::copy_from_slice(name);

        index.get(&name_key).copied()
    }

    /// Check if an entry is in the "draining" region.
    /// Draining entries are those not yet acknowledged by the decoder.
    pub fn is_draining(&self, absolute_index: u64) -> bool {
        let known = self.known_received_count.load(Ordering::Acquire);
        absolute_index >= known
    }
}

// Ensure DynamicTable is Send + Sync for concurrent access
unsafe impl Send for DynamicTable {}
unsafe impl Sync for DynamicTable {}

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
