//! QPACK Encoder implementation per RFC 9204.
//!
//! Lock-free, zero-copy encoder with:
//! - Dynamic table management
//! - Encoder stream instruction generation
//! - Blocked stream tracking
//! - Required Insert Count calculation

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;
use hashbrown::HashMap;

use crate::error::{QpackError, Result};
use crate::wire::header_block::{EncodedPrefix, FieldLineGeneric};
use crate::wire::instructions::{DecoderInstruction, EncoderInstruction};
use crate::tables::static_table;
use crate::tables::DynamicTable;

/// QPACK Encoder state.
pub struct Encoder {
    /// Dynamic table (owned by encoder, shared via Arc for read-only access).
    table: DynamicTable,

    /// Encoder stream instruction queue.
    encoder_stream_buffer: VecDeque<Bytes>,

    /// Blocked streams awaiting acknowledgement.
    /// Maps stream_id -> (required_insert_count, referenced_indices)
    /// RFC 9204 Section 2.1.4: We track RIC to update Known Received Count on ack
    /// Uses SmallVec to avoid heap allocation for common case (≤8 references)
    blocked_streams: HashMap<u64, (u64, SmallVec<[u64; 8]>)>,

    /// Maximum blocked streams allowed.
    max_blocked_streams: usize,

    /// Maximum dynamic table capacity.
    max_table_capacity: usize,

    /// Header name frequency counter for proactive insertion (RFC 7.1.1).
    /// Maps name hash -> occurrence count. Used to decide when to insert name-only entries.
    name_frequency: HashMap<u64, u32>,
}

impl Encoder {
    /// Create a new encoder with default capacity set to max.
    /// The capacity can be adjusted later with set_capacity().
    pub fn new(max_table_capacity: usize, max_blocked_streams: usize) -> Self {
        let mut table = DynamicTable::new(max_table_capacity);
        // Initialize capacity to max (can be reduced later)
        let _ = table.set_capacity(max_table_capacity);

        Self {
            table,
            encoder_stream_buffer: VecDeque::with_capacity(32),
            blocked_streams: HashMap::with_capacity(max_blocked_streams),
            max_blocked_streams,
            max_table_capacity,
            name_frequency: HashMap::with_capacity(64),
        }
    }

    /// Get immutable reference to dynamic table (for testing/inspection).
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Get mutable reference to dynamic table (for testing).
    pub fn table_mut(&mut self) -> &mut DynamicTable {
        &mut self.table
    }

    /// Set dynamic table capacity.
    pub fn set_capacity(&mut self, capacity: usize) -> Result<()> {
        self.table.set_capacity(capacity)?;

        // Send Set Capacity instruction
        let inst = EncoderInstruction::SetCapacity {
            capacity: capacity as u64,
        };
        self.encoder_stream_buffer.push_back(inst.encode());

        self.max_table_capacity = capacity;
        Ok(())
    }

    /// Check if an entry should be duplicated (RFC 9204 Section 4.3.1.4).
    fn should_duplicate(&self, absolute_index: u64) -> bool {
        let insert_count = self.table.insert_count();
        let table_len = self.table.len() as u64;
        
        // Only duplicate if table has meaningful size and entry is in oldest 25%
        table_len > 4 && absolute_index < insert_count - (table_len * 3 / 4)
    }

    /// Duplicate an existing entry.
    fn duplicate_entry(&mut self, absolute_index: u64) -> Result<u64> {
        // RFC 9204 Section 4.3.1.4: Duplicate instruction uses relative index
        let relative_index = self.table.insert_count() - absolute_index - 1;
        
        let inst = EncoderInstruction::Duplicate { index: relative_index };
        self.encoder_stream_buffer.push_back(inst.encode());
        
        let (name, value) = {
            let entry = self.table.get(absolute_index).ok_or(QpackError::InvalidDynamicIndex(absolute_index))?;
            (entry.name.clone(), entry.value.clone())
        };
        
        self.table.insert(name, value)
    }

    /// Encode headers into a header block for a given stream.
    ///
    /// # Arguments
    /// * `stream_id` - HTTP/3 stream ID
    /// * `headers` - List of (name, value) pairs
    ///
    /// # Returns
    /// Encoded header block bytes
    pub fn encode(&mut self, stream_id: u64, headers: &[(&[u8], &[u8])]) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        self.encode_into(stream_id, headers, &mut buf)?;
        Ok(buf.freeze())
    }

    /// Encode headers into a provided buffer.
    ///
    /// # Arguments
    /// * `stream_id` - HTTP/3 stream ID
    /// * `headers` - List of (name, value) pairs
    /// * `buf` - Buffer to write encoded header block to
    pub fn encode_into(&mut self, stream_id: u64, headers: &[(&[u8], &[u8])], buf: &mut BytesMut) -> Result<()> {
        // Pre-allocate field lines vector
        let mut field_lines: Vec<FieldLineGeneric<&[u8]>> = Vec::with_capacity(headers.len());
        
        // Use SmallVec to avoid heap allocation for common case (≤8 dynamic references)
        // Stack-allocated for typical requests, heap fallback for complex cases
        let mut dynamic_references = SmallVec::<[u64; 8]>::new();
        
        let mut max_absolute_index = 0u64;
        let mut min_absolute_index = u64::MAX;
        let mut references_dynamic = false;

        for (name, value) in headers {
            // RFC 9204 Section 7.1.3: Check if this is a sensitive header that should never be indexed
            // Uses comprehensive list + pattern matching for custom auth headers
            let never_indexed = should_never_index(name);

            // Try static table exact match
            if let Some(static_idx) = static_table::find_exact(name, value) {
                field_lines.push(FieldLineGeneric::IndexedStatic {
                    index: static_idx as u64,
                });
                continue;
            }

            // Try dynamic table exact match
            if let Some(abs_idx) = self.table.find_exact(name, value) {
                let mut final_idx = abs_idx;
                
                // Check if we should duplicate this entry (if it's old)
                if self.should_duplicate(abs_idx) {
                     if let Ok(new_idx) = self.duplicate_entry(abs_idx) {
                         final_idx = new_idx;
                     }
                }

                // RFC 9204 Section 2.1.4: Can reference if acknowledged OR if we can block
                let is_acknowledged = final_idx < self.table.known_received_count();
                let can_block = self.can_block_stream();
                
                if is_acknowledged || can_block {
                    field_lines.push(FieldLineGeneric::IndexedDynamic {
                        absolute_index: final_idx,
                    });
                    max_absolute_index = max_absolute_index.max(final_idx);
                    min_absolute_index = min_absolute_index.min(final_idx);
                    dynamic_references.push(final_idx);
                    references_dynamic = true;
                    continue;
                }
            }

            // Try static table name match
            if let Some(static_idx) = static_table::find_name(name) {
                field_lines.push(FieldLineGeneric::LiteralStaticName {
                    name_index: static_idx as u64,
                    value: value,
                    never_indexed,
                });
                continue;
            }

            // Try dynamic table name match (only if not sensitive)
            if !never_indexed {
                if let Some(abs_idx) = self.table.find_name(name) {
                    // RFC 9204 Section 2.1.4: Can reference if acknowledged OR if we can block
                    let is_acknowledged = abs_idx < self.table.known_received_count();
                    let can_block = self.can_block_stream();
                    
                    if is_acknowledged || can_block {
                        field_lines.push(FieldLineGeneric::LiteralDynamicName {
                            name_index: abs_idx,
                            value: value,
                            never_indexed,
                        });
                        max_absolute_index = max_absolute_index.max(abs_idx);
                        min_absolute_index = min_absolute_index.min(abs_idx);
                        dynamic_references.push(abs_idx);
                        references_dynamic = true;
                        continue;
                    }
                }
            }

            // Consider inserting into dynamic table (skip if sensitive)
            let mut inserted = false;
            if !never_indexed && self.should_insert(name, value) {
                if let Ok(abs_idx) = self.insert_entry(name, value) {
                    field_lines.push(FieldLineGeneric::IndexedDynamic {
                        absolute_index: abs_idx,
                    });
                    max_absolute_index = max_absolute_index.max(abs_idx);
                    min_absolute_index = min_absolute_index.min(abs_idx);
                    dynamic_references.push(abs_idx);
                    references_dynamic = true;
                    inserted = true;
                }
            } 
            
            if !inserted {
                // Literal without name reference
                field_lines.push(FieldLineGeneric::LiteralName {
                    name: name,
                    value: value,
                    never_indexed,
                });
            }
        }

        // Calculate Required Insert Count and optimal Base
        let required_insert_count = if references_dynamic {
            max_absolute_index + 1
        } else {
            0
        };

        // Dynamic Base optimization: choose Base to minimize encoding size
        // Strategy: if all references are recent (close to insert_count), use Base = insert_count
        // to enable post-base indexing with smaller indices.
        let base = if references_dynamic {
            self.choose_optimal_base(required_insert_count, &dynamic_references)
        } else {
            0
        };

        // Convert absolute indices to post-base where beneficial
        if references_dynamic {
            for field_line in &mut field_lines {
                match field_line {
                    FieldLineGeneric::IndexedDynamic { absolute_index } => {
                        if *absolute_index >= base {
                            // Use post-base indexing
                            let post_base_index = *absolute_index - base;
                            *field_line = FieldLineGeneric::IndexedDynamicPost {
                                index: post_base_index,
                            };
                        }
                    }
                    FieldLineGeneric::LiteralDynamicName {
                        name_index,
                        value,
                        never_indexed,
                    } => {
                        if *name_index >= base {
                            // Use post-base name reference
                            let post_base_index = *name_index - base;
                            *field_line = FieldLineGeneric::LiteralPostBaseName {
                                name_index: post_base_index,
                                value: *value,
                                never_indexed: *never_indexed,
                            };
                        }
                    }
                    _ => {}
                }
            }
        }

        // Track blocked stream if necessary
        if references_dynamic {
            if self.blocked_streams.len() >= self.max_blocked_streams {
                return Err(QpackError::BlockedStreamLimitExceeded);
            }
            // Increment reference counts for all referenced entries (RFC 9204 Section 2.1.1)
            for &idx in &dynamic_references {
                self.table.increment_ref_count(idx);
            }
            self.blocked_streams
                .insert(stream_id, (required_insert_count, dynamic_references));
        }

        // Encode header block
        // Pre-allocate buffer with estimated size: prefix (4 bytes) + field lines (avg 10 bytes each)
        let estimated_size = 4 + (field_lines.len() * 10);
        buf.reserve(estimated_size);

        // Encode prefix with calculated delta base
        let max_entries = self.max_table_capacity as u64 / 32;
        let (sign, delta_base) = if base >= required_insert_count {
            (false, base - required_insert_count)
        } else {
            (true, required_insert_count - base - 1)
        };
        let prefix = EncodedPrefix {
            required_insert_count,
            sign,
            delta_base,
        };
        prefix.encode_into(max_entries, buf);

        // Encode field lines
        for field_line in field_lines {
            field_line.encode_into(base, buf);
        }

        Ok(())
    }

    /// Encode small header sets using pre-allocated buffers.
    /// Optimized for headers with ≤ 16 entries and ≤ 8 dynamic references.
    /// Falls back to heap allocation for larger sets.
    pub fn encode_small(&mut self, stream_id: u64, headers: &[(&[u8], &[u8])]) -> Result<Bytes> {
        const MAX_STACK_HEADERS: usize = 16;
        const MAX_STACK_REFS: usize = 8;

        if headers.len() > MAX_STACK_HEADERS {
            // Fall back to heap allocation for large header sets
            return self.encode(stream_id, headers);
        }

        // Use pre-allocated Vecs with small capacities
        let mut field_lines: Vec<FieldLineGeneric<&[u8]>> = Vec::with_capacity(MAX_STACK_HEADERS);
        let mut dynamic_references = SmallVec::<[u64; 8]>::new();
        
        let mut max_absolute_index = 0u64;
        let mut min_absolute_index = u64::MAX;
        let mut references_dynamic = false;

        for (name, value) in headers {
            // RFC 920 4 Section 7.1.3: Check if this is a sensitive header that should never be indexed
            let never_indexed = should_never_index(name);

            // Try static table exact match
            if let Some(static_idx) = static_table::find_exact(name, value) {
                field_lines.push(FieldLineGeneric::IndexedStatic {
                    index: static_idx as u64,
                });
                continue;
            }

            // Try dynamic table exact match
            if let Some(abs_idx) = self.table.find_exact(name, value) {
                if !self.table.is_draining(abs_idx) || self.can_block_stream() {
                    field_lines.push(FieldLineGeneric::IndexedDynamic {
                        absolute_index: abs_idx,
                    });
                    max_absolute_index = max_absolute_index.max(abs_idx);
                    min_absolute_index = min_absolute_index.min(abs_idx);
                    if dynamic_references.len() < MAX_STACK_REFS {
                        dynamic_references.push(abs_idx);
                    }
                    references_dynamic = true;
                    continue;
                }
            }

            // Try static table name match
            if let Some(static_idx) = static_table::find_name(name) {
                field_lines.push(FieldLineGeneric::LiteralStaticName {
                    name_index: static_idx as u64,
                    value: value,
                    never_indexed,
                });
                continue;
            }

            // Try dynamic table name match (only if not sensitive)
            if !never_indexed {
                if let Some(abs_idx) = self.table.find_name(name) {
                    if !self.table.is_draining(abs_idx) || self.can_block_stream() {
                        field_lines.push(FieldLineGeneric::LiteralDynamicName {
                            name_index: abs_idx,
                            value: value,
                            never_indexed,
                        });
                        max_absolute_index = max_absolute_index.max(abs_idx);
                        min_absolute_index = min_absolute_index.min(abs_idx);
                        if dynamic_references.len() < MAX_STACK_REFS {
                            dynamic_references.push(abs_idx);
                        }
                        references_dynamic = true;
                        continue;
                    }
                }
            }

            // Consider inserting into dynamic table (skip if sensitive)
            let mut inserted = false;
            if !never_indexed && self.should_insert(name, value) {
                if let Ok(abs_idx) = self.insert_entry(name, value) {
                    field_lines.push(FieldLineGeneric::IndexedDynamic {
                        absolute_index: abs_idx,
                    });
                    max_absolute_index = max_absolute_index.max(abs_idx);
                    min_absolute_index = min_absolute_index.min(abs_idx);
                    if dynamic_references.len() < MAX_STACK_REFS {
                        dynamic_references.push(abs_idx);
                    }
                    references_dynamic = true;
                    inserted = true;
                }
            } 
            
            if !inserted {
                // Literal without name reference
                field_lines.push(FieldLineGeneric::LiteralName {
                    name: name,
                    value: value,
                    never_indexed,
                });
            }
        }

        // RFC 9204 Section 4.5.1.1: Required Insert Count is max(all referenced indices) + 1
        // This is INDEPENDENT of Base choice
        let required_insert_count = if references_dynamic {
            max_absolute_index + 1
        } else {
            0
        };

        // RFC 9204 Section 4.5.1.2: Base is chosen to minimize encoding size
        // Base determines whether we use pre-base or post-base indexing
        let base = if references_dynamic {
            self.choose_optimal_base(required_insert_count, &dynamic_references)
        } else {
            0
        };

        // Convert absolute indices to post-base where beneficial
        if references_dynamic {
            for field_line in field_lines.iter_mut() {
                match field_line {
                    FieldLineGeneric::IndexedDynamic { absolute_index } => {
                        if *absolute_index >= base {
                            let post_base_index = *absolute_index - base;
                            *field_line = FieldLineGeneric::IndexedDynamicPost {
                                index: post_base_index,
                            };
                        }
                    }
                    FieldLineGeneric::LiteralDynamicName {
                        name_index,
                        value,
                        never_indexed,
                    } => {
                        if *name_index >= base {
                            let post_base_index = *name_index - base;
                            *field_line = FieldLineGeneric::LiteralPostBaseName {
                                name_index: post_base_index,
                                value: *value,
                                never_indexed: *never_indexed,
                            };
                        }
                    }
                    _ => {}
                }
            }
        }

        // Track blocked stream if necessary
        if references_dynamic {
            if self.blocked_streams.len() >= self.max_blocked_streams {
                return Err(QpackError::BlockedStreamLimitExceeded);
            }
            // Increment reference counts
            for &idx in &dynamic_references {
                self.table.increment_ref_count(idx);
            }
            self.blocked_streams
                .insert(stream_id, (required_insert_count, dynamic_references));
        }

        // Encode header block
        let estimated_size = 4 + (field_lines.len() * 10);
        let mut buf = BytesMut::with_capacity(estimated_size);

        // Encode prefix
        let max_entries = self.max_table_capacity as u64 / 32;
        let (sign, delta_base) = if base >= required_insert_count {
            (false, base - required_insert_count)
        } else {
            (true, required_insert_count - base - 1)
        };
        let prefix = EncodedPrefix {
            required_insert_count,
            sign,
            delta_base,
        };
        prefix.encode_into(max_entries, &mut buf);

        // Encode field lines
        for field_line in field_lines {
            field_line.encode_into(base, &mut buf);
        }

        Ok(buf.freeze())
    }

    /// Process decoder instruction from decoder stream.
    pub fn process_decoder_instruction(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            let (inst, consumed) = DecoderInstruction::decode(&data[offset..])?;
            offset += consumed;

            match inst {
                DecoderInstruction::SectionAck { stream_id } => {
                    // RFC 9204 Section 2.1.4: "If the Required Insert Count of the acknowledged
                    // field section is greater than the current Known Received Count, the Known
                    // Received Count is updated to that Required Insert Count value."
                    if let Some((required_insert_count, referenced_indices)) = self.blocked_streams.remove(&stream_id) {
                        // Decrement reference counts for all referenced entries
                        // RFC 9204 Section 2.1.1: Entries become evictable once acknowledged
                        for &idx in &referenced_indices {
                            self.table.decrement_ref_count(idx);
                        }
                        
                        // Update Known Received Count based on Required Insert Count
                        self.table.update_known_received_count_max(required_insert_count);
                    }
                    // Note: If stream not in blocked_streams, it means RIC was 0 (no dynamic refs)
                    // or we already processed this ack. No action needed per RFC 9204.
                }

                DecoderInstruction::StreamCancel { stream_id } => {
                    if let Some((_ric, referenced_indices)) = self.blocked_streams.remove(&stream_id) {
                        // Decrement reference counts for all referenced entries
                        for &idx in &referenced_indices {
                            self.table.decrement_ref_count(idx);
                        }
                    }
                }

                DecoderInstruction::InsertCountIncrement { increment } => {
                    self.table.update_known_received_count(increment);
                }
            }
        }

        Ok(())
    }

    /// Get next encoder stream instruction (if any).
    pub fn poll_encoder_stream(&mut self) -> Option<Bytes> {
        self.encoder_stream_buffer.pop_front()
    }

    /// Get a batch of encoder stream instructions for more efficient transmission.
    ///
    /// Returns up to `max_instructions` batched together. This reduces syscalls
    /// and improves throughput when multiple instructions are pending.
    ///
    /// # Arguments
    /// * `max_instructions` - Maximum number of instructions to batch (default: 8)
    ///
    /// # Returns
    /// A single `Bytes` containing multiple concatenated instructions, or `None` if empty.
    pub fn poll_encoder_stream_batch(&mut self, max_instructions: usize) -> Option<Bytes> {
        if self.encoder_stream_buffer.is_empty() {
            return None;
        }

        let batch_size = std::cmp::min(max_instructions, self.encoder_stream_buffer.len());
        if batch_size == 0 {
            return None;
        }

        // Calculate total size needed
        let mut total_size = 0;
        for inst in self.encoder_stream_buffer.iter().take(batch_size) {
            total_size += inst.len();
        }

        // Pre-allocate buffer
        let mut batched = bytes::BytesMut::with_capacity(total_size);

        // Concatenate instructions
        for _ in 0..batch_size {
            if let Some(inst) = self.encoder_stream_buffer.pop_front() {
                batched.extend_from_slice(&inst);
            }
        }

        Some(batched.freeze())
    }

    /// Drain all encoder stream instructions.
    pub fn drain_encoder_stream(&mut self) -> Vec<Bytes> {
        self.encoder_stream_buffer.drain(..).collect()
    }

    /// Check if encoder can write an instruction without risking flow control deadlock.
    ///
    /// RFC 9204 Section 2.1.3: "An encoder SHOULD NOT write an instruction unless
    /// sufficient stream and connection flow-control credit is available for the
    /// entire instruction."
    ///
    /// This method allows the application layer to check available flow control
    /// before polling encoder stream instructions.
    ///
    /// # Arguments
    /// * `instruction_size` - Size of the instruction to write (in bytes)
    /// * `available_stream_credit` - Available flow control credit on encoder stream
    /// * `available_conn_credit` - Available flow control credit on connection
    ///
    /// # Returns
    /// `true` if both stream and connection have sufficient credit
    ///
    /// # Example
    /// ```ignore
    /// let inst_size = encoder.peek_next_instruction_size().unwrap();
    /// if encoder.can_write_instruction(inst_size, stream_credit, conn_credit) {
    ///     let instruction = encoder.poll_encoder_stream();
    ///     // Write instruction to encoder stream
    /// }
    /// ```
    pub fn can_write_instruction(
        &self,
        instruction_size: usize,
        available_stream_credit: usize,
        available_conn_credit: usize,
    ) -> bool {
        instruction_size <= available_stream_credit && instruction_size <= available_conn_credit
    }

    /// Peek at the size of the next encoder stream instruction without removing it.
    ///
    /// Useful in conjunction with `can_write_instruction()` to check flow control
    /// before writing instructions.
    ///
    /// # Returns
    /// Size of next instruction in bytes, or None if buffer is empty
    pub fn peek_next_instruction_size(&self) -> Option<usize> {
        self.encoder_stream_buffer.front().map(|inst| inst.len())
    }

    /// Check if we can block another stream.
    fn can_block_stream(&self) -> bool {
        self.blocked_streams.len() < self.max_blocked_streams
    }

    /// Choose optimal Base to minimize encoding size per RFC 9204 Section 4.5.1.2.
    fn choose_optimal_base(&self, required_insert_count: u64, references: &[u64]) -> u64 {
        if references.is_empty() {
            return 0;
        }

        let min_ref = *references.iter().min().unwrap();
        let max_ref = *references.iter().max().unwrap();
        
        // Candidate 1: Base = RIC (Pre-base only, Delta=0)
        let base_ric = required_insert_count;
        
        // Candidate 2: Base = (min + max) / 2 (Mixed Pre/Post-base)
        let base_mid = (min_ref + max_ref) / 2;

        // Candidate 3: Base = min_ref (All post-base)
        let base_min = min_ref;

        // Candidate 4: Base = max_ref + 1 (All pre-base)
        let base_max = max_ref + 1;
        
        let mut best_base = base_ric;
        let mut min_cost = self.calculate_total_cost(base_ric, required_insert_count, references);
        
        for candidate in [base_mid, base_min, base_max] {
            let cost = self.calculate_total_cost(candidate, required_insert_count, references);
            if cost < min_cost {
                min_cost = cost;
                best_base = candidate;
            }
        }
        
        best_base
    }

    /// Calculate total encoding cost for a given base.
    fn calculate_total_cost(&self, base: u64, ric: u64, references: &[u64]) -> u64 {
        let mut cost = 0;
        
        // Delta Base cost
        let delta = if base >= ric {
            base - ric
        } else {
            ric - base - 1
        };
        cost += encode_int_cost(delta, 7);
        
        for &idx in references {
            if idx >= base {
                // Post-base: 0001xxxx (4-bit prefix)
                let p_idx = idx - base;
                cost += encode_int_cost(p_idx, 4);
            } else {
                // Pre-base: 1xxxxxxx (dynamic) -> 10xxxxxx (6-bit prefix) if relative
                // Wait, Indexed Dynamic is 1Txxxxxx. T=1 static, T=0 dynamic.
                // So 6-bit prefix.
                let p_idx = base - idx - 1;
                cost += encode_int_cost(p_idx, 6);
            }
        }
        cost
    }

    /// Decide whether to insert entry into dynamic table.
    /// 
    /// RFC 7.1.1: Implements proactive name insertion heuristic.
    /// If a custom header name appears frequently, insert name-only entry first.
    fn should_insert(&mut self, name: &[u8], value: &[u8]) -> bool {
        // Don't insert if table capacity is zero
        if self.table.capacity() == 0 {
            return false;
        }

        let entry_size = name.len() + value.len() + 32;

        // Don't insert if entry is too large
        if entry_size > self.table.capacity() {
            return false;
        }

        // Don't insert if already in table
        if self.table.find_exact(name, value).is_some() {
            return false;
        }

        // RFC 7.1.1 Proactive Name Insertion (P0 fix):
        // Track name frequency and insert name-only entries for common custom headers
        if name.len() > 8 && static_table::find_name(name).is_none() {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            name.hash(&mut hasher);
            let name_hash = hasher.finish();
            
            let count = self.name_frequency.entry(name_hash).or_insert(0);
            *count += 1;
            
            // If we've seen this name 3+ times and haven't inserted name-only entry yet
            if *count == 3 && self.table.find_name(name).is_none() {
                // Insert name-only entry to enable indexed name references
                let _ = self.insert_name_only_entry(name);
            }
        }

        // Simple heuristic: insert if we have space or can evict to make space
        true
    }

    /// Insert name-only entry into dynamic table (RFC 7.1.1).
    /// Enables subsequent headers with same name to use indexed name reference.
    fn insert_name_only_entry(&mut self, name: &[u8]) -> Result<u64> {
        let name_bytes = Bytes::copy_from_slice(name);
        let value_bytes = Bytes::new(); // Empty value

        // Check if static table has this name
        if let Some(static_idx) = static_table::find_name(name) {
            // Use Insert With Name Reference (static)
            let inst = EncoderInstruction::InsertWithNameRef {
                is_static: true,
                name_index: static_idx as u64,
                value: value_bytes.clone(),
            };
            self.encoder_stream_buffer.push_back(inst.encode());
        } else {
            // Use Insert Without Name Reference (literal)
            let inst = EncoderInstruction::InsertLiteral {
                name: name_bytes.clone(),
                value: value_bytes.clone(),
            };
            self.encoder_stream_buffer.push_back(inst.encode());
        }

        self.table.insert(name_bytes, value_bytes)
    }

    /// Insert entry into dynamic table and emit instruction.
    fn insert_entry(&mut self, name: &[u8], value: &[u8]) -> Result<u64> {
        let name_bytes = Bytes::copy_from_slice(name);
        let value_bytes = Bytes::copy_from_slice(value);

        // Check if name exists in static table
        if let Some(static_idx) = static_table::find_name(name) {
            // Insert with static name reference
            let inst = EncoderInstruction::InsertWithNameRef {
                is_static: true,
                name_index: static_idx as u64,
                value: value_bytes.clone(),
            };
            self.encoder_stream_buffer.push_back(inst.encode());
        } else if let Some(dyn_idx) = self.table.find_name(name) {
            // Insert with dynamic name reference - RFC 9204 Section 4.3.2 requires relative index
            let relative_index = self.table.insert_count() - dyn_idx - 1;
            let inst = EncoderInstruction::InsertWithNameRef {
                is_static: false,
                name_index: relative_index,
                value: value_bytes.clone(),
            };
            self.encoder_stream_buffer.push_back(inst.encode());
        } else {
            // Insert with literal name
            let inst = EncoderInstruction::InsertLiteral {
                name: name_bytes.clone(),
                value: value_bytes.clone(),
            };
            self.encoder_stream_buffer.push_back(inst.encode());
        }

        // Insert into table
        self.table.insert(name_bytes, value_bytes)
    }
}

/// Calculate cost of encoding an integer with prefix.
fn encode_int_cost(value: u64, prefix_bits: u8) -> u64 {
    let max_prefix = (1u64 << prefix_bits) - 1;
    if value < max_prefix {
        1
    } else {
        // 1 byte for prefix + varint bytes
        let mut v = value - max_prefix;
        let mut bytes = 1;
        while v >= 128 {
            v >>= 7;
            bytes += 1;
        }
        bytes + 1
    }
}

/// Check if a header is sensitive and should never be indexed.
///
/// Per RFC 9204 Section 7.1.3, RFC 9110 Section 12.5.3, and security best practices:
///
/// RFC 9204 Section 7.1.3: "An encoder might also choose not to index values for fields
/// that are considered to be highly valuable or sensitive to recovery, such as the Cookie
/// or Authorization header fields."
///
/// Comprehensive list includes:
/// - Authentication/Authorization: Credentials and tokens
/// - Session Management: Cookies and session identifiers
/// - Security Headers: API keys, CSRF tokens, signatures
/// - Privacy: User tracking data
/// - Application-specific: Custom auth headers
#[inline]
fn is_sensitive_header(name: &[u8]) -> bool {
    matches!(
        name,
        // RFC 9110 Authentication
        b"authorization" |
        b"proxy-authorization" |
        b"www-authenticate" |
        b"proxy-authenticate" |
        
        // RFC 6265 Cookies (Session Management)
        b"cookie" |
        b"set-cookie" |
        b"cookie2" |              // Deprecated but still used
        b"set-cookie2" |          // Deprecated but still used
        
        // API Keys and Tokens (Common patterns)
        b"x-api-key" |
        b"api-key" |
        b"x-auth-token" |
        b"x-access-token" |
        b"x-refresh-token" |
        b"x-session-token" |
        b"x-csrf-token" |
        b"x-xsrf-token" |
        
        // OAuth and JWT
        b"x-jwt" |
        b"x-jwt-assertion" |
        b"x-oauth-token" |
        b"bearer" |
        
        // Security Signatures
        b"signature" |
        b"x-signature" |
        b"x-amz-signature" |      // AWS
        b"x-goog-signature" |     // Google Cloud
        b"x-hub-signature" |      // GitHub webhooks
        
        // Authentication Headers (Various schemes)
        b"x-user-token" |
        b"x-device-token" |
        b"x-client-id" |
        b"x-client-secret" |
        b"x-api-secret" |
        b"x-auth-key" |
        b"x-auth-user" |
        b"x-auth-password" |
        
        // Session IDs
        b"x-session-id" |
        b"session-id" |
        b"jsessionid" |           // Java
        b"phpsessid" |            // PHP
        b"aspsessionid" |         // ASP
        
        // Privacy/Tracking
        b"x-user-id" |
        b"x-tracking-id" |
        b"x-correlation-id" | // May contain user context
        
        // WebSocket Security (P0 fix - was missing)
        b"sec-websocket-key" |
        b"sec-websocket-accept" |
        
        // AWS and Cloud Provider Security Tokens (P0 fix - was missing)
        b"x-amz-security-token" |
        b"x-goog-iam-authority-selector" |
        b"x-goog-iam-authorization-token"

        // Custom Application Headers (wildcards handled by prefix)
        // Note: Consider making this configurable for application-specific headers
    )
}

/// Check if a header name contains sensitive patterns (case-insensitive).
///
/// This catches custom authentication headers that follow common naming patterns.
/// Zero-allocation implementation using direct byte comparison.
#[inline]
fn contains_sensitive_pattern(name: &[u8]) -> bool {
    // Early return for short names
    if name.len() < 4 {
        return false;
    }

    // Helper function for case-insensitive byte comparison
    #[inline]
    fn bytes_equal_ci(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b.iter()).all(|(x, y)| x.eq_ignore_ascii_case(y))
    }

    // Helper function to check if name ends with pattern (case-insensitive)
    #[inline]
    fn ends_with_ci(name: &[u8], pattern: &[u8]) -> bool {
        if name.len() < pattern.len() {
            return false;
        }
        let start = name.len() - pattern.len();
        bytes_equal_ci(&name[start..], pattern)
    }

    // Helper function to check if name starts with pattern (case-insensitive)
    #[inline]
    fn starts_with_ci(name: &[u8], pattern: &[u8]) -> bool {
        if name.len() < pattern.len() {
            return false;
        }
        bytes_equal_ci(&name[..pattern.len()], pattern)
    }

    // Helper function to check if name contains pattern anywhere (case-insensitive)
    #[inline]
    fn contains_ci(name: &[u8], pattern: &[u8]) -> bool {
        if name.len() < pattern.len() {
            return false;
        }
        for i in 0..=(name.len() - pattern.len()) {
            if bytes_equal_ci(&name[i..i + pattern.len()], pattern) {
                return true;
            }
        }
        false
    }

    // Check suffix patterns (most common case - headers like "x-api-key", "x-auth-token")
    let suffix_patterns: &[&[u8]] = &[
        b"-token",      // x-auth-token, x-api-token, etc.
        b"-key",        // x-api-key, api-key, etc.
        b"-secret",     // x-secret, api-secret, etc.
        b"-password",   // x-password, user-password, etc.
        b"-credential", // x-credential, auth-credential, etc.
        b"-auth",       // x-auth, custom-auth, etc.
        b"-session",    // x-session, user-session, etc.
        b"-jwt",        // x-jwt, custom-jwt, etc.
        b"-oauth",      // x-oauth, custom-oauth, etc.
        b"-bearer",     // x-bearer, etc.
        b"-signature",  // x-signature, etc.
        b"-csrf",       // x-csrf, etc.
        b"-xsrf",       // x-xsrf, etc.
    ];

    for pattern in suffix_patterns.iter() {
        if ends_with_ci(name, pattern) {
            return true;
        }
    }

    // Check prefix patterns (headers like "token", "auth", "bearer")
    let prefix_patterns: &[&[u8]] = &[b"token", b"auth", b"bearer", b"cookie", b"session"];

    for pattern in prefix_patterns.iter() {
        if starts_with_ci(name, pattern) {
            return true;
        }
    }

    // Check for embedded patterns (less common but still possible)
    let embedded_patterns: &[&[u8]] = &[b"password", b"secret", b"credential"];

    for pattern in embedded_patterns.iter() {
        if contains_ci(name, pattern) {
            return true;
        }
    }

    false
}

/// Determine if a header should never be indexed (comprehensive check).
///
/// This combines explicit sensitive header names with pattern matching for
/// custom authentication headers.
#[inline]
pub fn should_never_index(name: &[u8]) -> bool {
    is_sensitive_header(name) || contains_sensitive_pattern(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_static_only() {
        let mut encoder = Encoder::new(4096, 100);

        let headers = vec![
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ];

        let encoded = encoder.encode(0, &headers).unwrap();
        assert!(!encoded.is_empty());

        // Should not generate encoder stream instructions for static-only
        assert!(encoder.poll_encoder_stream().is_none());
    }

    #[test]
    fn test_encode_with_insertion() {
        let mut encoder = Encoder::new(4096, 100);
        encoder.set_capacity(4096).unwrap();

        let headers = vec![(b"custom-header".as_slice(), b"custom-value".as_slice())];

        let encoded = encoder.encode(0, &headers).unwrap();
        assert!(!encoded.is_empty());

        // Should generate encoder stream instruction
        let inst = encoder.poll_encoder_stream();
        assert!(inst.is_some());
    }

    #[test]
    fn test_decoder_instruction_ack() {
        let mut encoder = Encoder::new(4096, 100);

        // Simulate encoding with dynamic reference
        encoder.blocked_streams.insert(4, (10, SmallVec::from_vec(vec![5, 7, 9])));

        // Process Section Ack
        let ack = DecoderInstruction::SectionAck { stream_id: 4 };
        encoder.process_decoder_instruction(&ack.encode()).unwrap();

        // Stream should be unblocked
        assert!(!encoder.blocked_streams.contains_key(&4));
    }
}
