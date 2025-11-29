//! QPACK Encoder implementation per RFC 9204.
//! 
//! Lock-free, zero-copy encoder with:
//! - Dynamic table management
//! - Encoder stream instruction generation
//! - Blocked stream tracking
//! - Required Insert Count calculation

use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};

use crate::error::{QpackError, Result};
use crate::header_block::{EncodedPrefix, FieldLine};
use crate::instructions::{DecoderInstruction, EncoderInstruction};
use crate::static_table;
use crate::table::DynamicTable;

/// QPACK Encoder state.
pub struct Encoder {
    /// Dynamic table (owned by encoder, shared via Arc for read-only access).
    table: DynamicTable,
    
    /// Encoder stream instruction queue.
    encoder_stream_buffer: VecDeque<Bytes>,
    
    /// Blocked streams awaiting acknowledgement.
    /// Maps stream_id -> required_insert_count
    blocked_streams: HashMap<u64, u64>,
    
    /// Maximum blocked streams allowed.
    max_blocked_streams: usize,
    
    /// Maximum dynamic table capacity.
    max_table_capacity: usize,
}

impl Encoder {
    /// Create a new encoder.
    pub fn new(max_table_capacity: usize, max_blocked_streams: usize) -> Self {
        let mut table = DynamicTable::new(max_table_capacity);
        // Initialize capacity
        let _ = table.set_capacity(max_table_capacity);
        
        Self {
            table,
            encoder_stream_buffer: VecDeque::with_capacity(32),
            blocked_streams: HashMap::with_capacity(max_blocked_streams),
            max_blocked_streams,
            max_table_capacity,
        }
    }
    
    /// Get immutable reference to dynamic table (for testing/inspection).
    pub fn table(&self) -> &DynamicTable {
        &self.table
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
    
    /// Encode headers into a header block for a given stream.
    /// 
    /// # Arguments
    /// * `stream_id` - HTTP/3 stream ID
    /// * `headers` - List of (name, value) pairs
    /// 
    /// # Returns
    /// Encoded header block bytes
    pub fn encode(&mut self, stream_id: u64, headers: &[(&[u8], &[u8])]) -> Result<Bytes> {
        let mut field_lines = Vec::with_capacity(headers.len());
        let mut max_absolute_index = 0u64;
        let mut references_dynamic = false;
        
        for (name, value) in headers {
            // RFC 9204 Section 7.1.3: Check if this is a sensitive header that should never be indexed
            // Uses comprehensive list + pattern matching for custom auth headers
            let never_indexed = should_never_index(name);
            
            // Try static table exact match
            if let Some(static_idx) = static_table::find_exact(name, value) {
                field_lines.push(FieldLine::IndexedStatic {
                    index: static_idx as u64,
                });
                continue;
            }
            
            // Try dynamic table exact match
            if let Some(abs_idx) = self.table.find_exact(name, value) {
                if !self.table.is_draining(abs_idx) || self.can_block_stream() {
                    field_lines.push(FieldLine::IndexedDynamic {
                        absolute_index: abs_idx,
                    });
                    max_absolute_index = max_absolute_index.max(abs_idx);
                    references_dynamic = true;
                    continue;
                }
            }
            
            // Try static table name match
            if let Some(static_idx) = static_table::find_name(name) {
                field_lines.push(FieldLine::LiteralStaticName {
                    name_index: static_idx as u64,
                    value: Bytes::copy_from_slice(value),
                    never_indexed,
                });
                continue;
            }
            
            // Try dynamic table name match (only if not sensitive)
            if !never_indexed {
                if let Some(abs_idx) = self.table.find_name(name) {
                    if !self.table.is_draining(abs_idx) || self.can_block_stream() {
                        field_lines.push(FieldLine::LiteralDynamicName {
                            name_index: abs_idx,
                            value: Bytes::copy_from_slice(value),
                            never_indexed,
                        });
                        max_absolute_index = max_absolute_index.max(abs_idx);
                        references_dynamic = true;
                        continue;
                    }
                }
            }
            
            // Consider inserting into dynamic table (skip if sensitive)
            if !never_indexed && self.should_insert(name, value) {
                let abs_idx = self.insert_entry(name, value)?;
                field_lines.push(FieldLine::IndexedDynamic {
                    absolute_index: abs_idx,
                });
                max_absolute_index = max_absolute_index.max(abs_idx);
                references_dynamic = true;
            } else {
                // Literal without name reference
                field_lines.push(FieldLine::LiteralName {
                    name: Bytes::copy_from_slice(name),
                    value: Bytes::copy_from_slice(value),
                    never_indexed,
                });
            }
        }
        
        // Calculate Required Insert Count and Base
        let required_insert_count = if references_dynamic {
            max_absolute_index + 1
        } else {
            0
        };
        
        // Use Required Insert Count as Base (Delta Base = 0)
        let base = if references_dynamic {
            required_insert_count
        } else {
            0
        };
        
        // Track blocked stream if necessary
        if references_dynamic {
            if self.blocked_streams.len() >= self.max_blocked_streams {
                return Err(QpackError::BlockedStreamLimitExceeded);
            }
            self.blocked_streams.insert(stream_id, required_insert_count);
        }
        
        // Encode header block
        let mut buf = BytesMut::new();
        
        // Encode prefix: Delta Base = 0 means Base = Required Insert Count (positive delta)
        let max_entries = self.max_table_capacity as u64 / 32;
        let prefix = EncodedPrefix {
            required_insert_count,
            sign: false,
            delta_base: 0,
        };
        buf.extend_from_slice(&prefix.encode(max_entries));
        
        // Encode field lines
        for field_line in field_lines {
            buf.extend_from_slice(&field_line.encode(base));
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
                    if let Some(ric) = self.blocked_streams.remove(&stream_id) {
                        // Update known received count
                        let current = self.table.known_received_count();
                        if ric > current {
                            self.table.update_known_received_count(ric - current);
                        }
                    }
                }
                
                DecoderInstruction::StreamCancel { stream_id } => {
                    self.blocked_streams.remove(&stream_id);
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
    
    /// Check if we can block another stream.
    fn can_block_stream(&self) -> bool {
        self.blocked_streams.len() < self.max_blocked_streams
    }
    
    /// Decide whether to insert entry into dynamic table.
    fn should_insert(&self, name: &[u8], value: &[u8]) -> bool {
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
        
        // Simple heuristic: insert if we have space or can evict to make space
        true
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
            // Insert with dynamic name reference
            let inst = EncoderInstruction::InsertWithNameRef {
                is_static: false,
                name_index: dyn_idx,
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
        b"x-correlation-id"       // May contain user context
        
        // Custom Application Headers (wildcards handled by prefix)
        // Note: Consider making this configurable for application-specific headers
    )
}

/// Check if a header name contains sensitive patterns (case-insensitive).
/// 
/// This catches custom authentication headers that follow common naming patterns.
/// To avoid false positives, we require patterns to be at word boundaries or with
/// common prefixes like "x-".
#[inline]
fn contains_sensitive_pattern(name: &[u8]) -> bool {
    // Convert to lowercase for comparison
    let name_lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
    
    // Patterns that indicate authentication/security headers
    // We check for these patterns with hyphens (common in custom headers)
    let sensitive_patterns: &[&[u8]] = &[
        b"-token",           // x-auth-token, x-api-token, etc.
        b"-key",             // x-api-key, api-key, etc.
        b"-secret",          // x-secret, api-secret, etc.
        b"-password",        // x-password, user-password, etc.
        b"-credential",      // x-credential, auth-credential, etc.
        b"-auth",            // x-auth, custom-auth, etc.
        b"-session",         // x-session, user-session, etc.
        b"-jwt",             // x-jwt, custom-jwt, etc.
        b"-oauth",           // x-oauth, custom-oauth, etc.
        b"-bearer",          // x-bearer, etc.
        b"-signature",       // x-signature, etc.
        b"-csrf",            // x-csrf, etc.
        b"-xsrf",            // x-xsrf, etc.
    ];
    
    // Check if name contains any sensitive pattern
    for pattern in sensitive_patterns.iter() {
        if name_lower.windows(pattern.len()).any(|window| window == *pattern) {
            return true;
        }
    }
    
    // Also check for patterns at the start (without hyphen)
    let start_patterns: &[&[u8]] = &[
        b"token",
        b"auth",
        b"bearer",
        b"cookie",
        b"session",
    ];
    
    for pattern in start_patterns.iter() {
        if name_lower.starts_with(pattern) {
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
        
        let headers = vec![
            (b"custom-header".as_slice(), b"custom-value".as_slice()),
        ];
        
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
        encoder.blocked_streams.insert(4, 10);
        
        // Process Section Ack
        let ack = DecoderInstruction::SectionAck { stream_id: 4 };
        encoder.process_decoder_instruction(&ack.encode()).unwrap();
        
        // Stream should be unblocked
        assert!(!encoder.blocked_streams.contains_key(&4));
    }
}
