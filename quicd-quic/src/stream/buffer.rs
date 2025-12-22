//! # Stream Data Buffers (Zero-Copy Reassembly)
//!
//! Manages out-of-order stream data reassembly.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::StreamOffset;
use bytes::Bytes;
extern crate alloc;
use alloc::collections::BTreeMap;

/// Stream Data Chunk (zero-copy)
#[derive(Debug, Clone)]
pub struct StreamData {
    /// Offset in stream
    pub offset: StreamOffset,

    /// Data (reference-counted, zero-copy)
    pub data: Bytes,
}

/// Receive Buffer (Out-of-Order Reassembly)
///
/// Stores received stream data chunks and provides ordered reads.
/// Uses BTreeMap for efficient range queries.
pub struct ReceiveBuffer {
    /// Ordered map of offset -> data chunks
    chunks: BTreeMap<StreamOffset, Bytes>,

    /// Next offset to read (continuous up to this point)
    read_offset: StreamOffset,

    /// Maximum offset received (for flow control)
    max_offset: StreamOffset,

    /// Final size (if FIN received)
    final_size: Option<StreamOffset>,

    /// Total bytes buffered
    buffered_bytes: usize,

    /// Maximum buffer size (flow control limit)
    max_buffer_size: usize,
}

impl ReceiveBuffer {
    /// Create new receive buffer
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            chunks: BTreeMap::new(),
            read_offset: 0,
            max_offset: 0,
            final_size: None,
            buffered_bytes: 0,
            max_buffer_size,
        }
    }

    /// Insert received data chunk
    ///
    /// Handles overlapping/duplicate data.
    pub fn insert(&mut self, offset: StreamOffset, data: Bytes, fin: bool) -> Result<()> {
        // Check flow control limit
        let end_offset = offset + data.len() as u64;
        if end_offset > self.read_offset + self.max_buffer_size as u64 {
            return Err(Error::Transport(TransportError::FlowControlError));
        }

        // Check final size consistency
        if let Some(final_size) = self.final_size {
            if (fin && end_offset != final_size) || end_offset > final_size {
                return Err(Error::Transport(TransportError::FinalSizeError));
            }
        } else if fin {
            self.final_size = Some(end_offset);
        }

        // Store chunk
        if !data.is_empty() {
            self.buffered_bytes += data.len();
            self.chunks.insert(offset, data);
        }

        if end_offset > self.max_offset {
            self.max_offset = end_offset;
        }

        Ok(())
    }

    /// Read contiguous data up to max_len
    ///
    /// Returns None if no data available at read_offset.
    pub fn read(&mut self, max_len: usize) -> Option<Bytes> {
        // Find chunk starting at read_offset
        let chunk = self.chunks.remove(&self.read_offset)?;

        let len = chunk.len().min(max_len);
        self.read_offset += len as u64;
        self.buffered_bytes -= len;

        if len < chunk.len() {
            // Partial read - re-insert remainder
            let remainder = chunk.slice(len..);
            self.chunks.insert(self.read_offset, remainder);
        }

        Some(chunk.slice(..len))
    }

    /// Check if all data received (FIN and all bytes read)
    pub fn is_complete(&self) -> bool {
        self.final_size == Some(self.read_offset)
    }

    /// Get read offset (next byte to read)
    pub fn read_offset(&self) -> StreamOffset {
        self.read_offset
    }

    /// Get bytes buffered
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }
}

/// Send Buffer (Retransmission Tracking)
///
/// Tracks sent stream data for retransmission.
pub struct SendBuffer {
    /// Data to send (ordered chunks)
    pending: BTreeMap<StreamOffset, Bytes>,

    /// Next offset to send
    send_offset: StreamOffset,

    /// Offset up to which data is ACKed
    acked_offset: StreamOffset,

    /// Whether FIN has been sent
    fin_sent: bool,

    /// Whether FIN has been ACKed
    fin_acked: bool,
}

impl SendBuffer {
    /// Create new send buffer
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            send_offset: 0,
            acked_offset: 0,
            fin_sent: false,
            fin_acked: false,
        }
    }

    /// Queue data to send
    pub fn write(&mut self, data: Bytes, fin: bool) {
        let offset = self.send_offset;
        self.send_offset += data.len() as u64;

        if !data.is_empty() {
            self.pending.insert(offset, data);
        }

        if fin {
            self.fin_sent = true;
        }
    }

    /// Get next data to send (up to max_len)
    pub fn peek(&self, max_len: usize) -> Option<(StreamOffset, Bytes, bool)> {
        let (&offset, data) = self.pending.iter().next()?;

        let len = data.len().min(max_len);
        let chunk = data.slice(..len);
        let fin = self.fin_sent && self.send_offset == offset + data.len() as u64;

        Some((offset, chunk, fin))
    }

    /// Mark data as ACKed
    pub fn ack(&mut self, offset: StreamOffset, length: usize) {
        let end = offset + length as u64;
        if end > self.acked_offset {
            self.acked_offset = end;
        }

        // Remove ACKed chunks
        self.pending.retain(|&off, data| {
            let chunk_end = off + data.len() as u64;
            chunk_end > self.acked_offset
        });

        if self.fin_sent && self.acked_offset == self.send_offset {
            self.fin_acked = true;
        }
    }

    /// Check if all data is ACKed
    pub fn is_complete(&self) -> bool {
        self.fin_acked
    }
}

impl Default for SendBuffer {
    fn default() -> Self {
        Self::new()
    }
}
