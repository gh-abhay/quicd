//! Dynamic table implementation.
//!
//! The dynamic table is a circular buffer (FIFO) that stores field lines.
//! It supports absolute, relative, and post-base indexing per RFC 9204 Section 3.2.

use crate::error::{Error, Result};
use crate::field_line::FieldLine;
use std::collections::VecDeque;

/// Entry in the dynamic table.
#[derive(Clone)]
struct Entry {
    field: FieldLine,
    absolute_index: u64,
}

/// The dynamic table.
pub struct DynamicTable {
    entries: VecDeque<Entry>,
    capacity: usize,
    current_size: usize,
    insert_count: u64,
    max_capacity: usize,
}

impl DynamicTable {
    /// Creates a new dynamic table with the given capacity.
    pub fn new(capacity: usize, max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
            current_size: 0,
            insert_count: 0,
            max_capacity,
        }
    }

    /// Returns the current insert count.
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Returns the current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Sets a new capacity, evicting entries if necessary.
    pub fn set_capacity(&mut self, new_capacity: usize) -> Result<()> {
        if new_capacity > self.max_capacity {
            return Err(Error::DynamicTableError(format!(
                "capacity {} exceeds maximum {}",
                new_capacity, self.max_capacity
            )));
        }

        self.capacity = new_capacity;

        // Evict entries if current size exceeds new capacity
        while self.current_size > self.capacity && !self.entries.is_empty() {
            if let Some(entry) = self.entries.pop_front() {
                self.current_size -= entry.field.size();
            }
        }

        Ok(())
    }

    /// Inserts a field line into the dynamic table.
    pub fn insert(&mut self, field: FieldLine) -> Result<u64> {
        let size = field.size();

        if size > self.capacity {
            return Err(Error::DynamicTableError(format!(
                "entry size {} exceeds table capacity {}",
                size, self.capacity
            )));
        }

        // Evict entries to make room
        while self.current_size + size > self.capacity && !self.entries.is_empty() {
            if let Some(entry) = self.entries.pop_front() {
                self.current_size -= entry.field.size();
            }
        }

        let absolute_index = self.insert_count;
        self.entries.push_back(Entry {
            field,
            absolute_index,
        });
        self.current_size += size;
        self.insert_count += 1;

        Ok(absolute_index)
    }

    /// Gets an entry by absolute index.
    pub fn get_absolute(&self, index: u64) -> Option<&FieldLine> {
        self.entries
            .iter()
            .find(|e| e.absolute_index == index)
            .map(|e| &e.field)
    }

    /// Gets an entry by relative index (relative to insert_count).
    pub fn get_relative(&self, index: u64, base: u64) -> Option<&FieldLine> {
        if index >= base {
            return None;
        }
        let absolute_index = base - index - 1;
        self.get_absolute(absolute_index)
    }

    /// Gets an entry by post-base index.
    pub fn get_post_base(&self, index: u64, base: u64) -> Option<&FieldLine> {
        let absolute_index = base + index;
        self.get_absolute(absolute_index)
    }

    /// Drains entries up to the given insert count.
    pub fn drain_to(&mut self, insert_count: u64) {
        while let Some(entry) = self.entries.front() {
            if entry.absolute_index >= insert_count {
                break;
            }
            let entry = self.entries.pop_front().unwrap();
            self.current_size -= entry.field.size();
        }
    }
}

