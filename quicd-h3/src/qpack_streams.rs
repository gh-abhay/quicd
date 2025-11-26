//! QPACK encoder and decoder stream management per RFC 9204.
//!
//! This module manages the dedicated unidirectional streams used for
//! QPACK dynamic table updates and feedback.

use crate::error::H3Error;
use crate::qpack::QpackInstruction;

/// Manager for QPACK encoder and decoder streams.
///
/// Per RFC 9204 Section 4.2, each endpoint opens:
/// - One encoder stream (type 0x02) for sending dynamic table instructions
/// - One decoder stream (type 0x03) for sending acknowledgments and cancellations
pub struct QpackStreamManager {
    /// Encoder stream ID (if set)
    encoder_stream_id: Option<u64>,
    /// Decoder stream ID (if set)
    decoder_stream_id: Option<u64>,
    /// Track streams that are blocked waiting for dynamic table updates
    blocked_streams: std::collections::HashSet<u64>,
}

impl QpackStreamManager {
    /// Create a new QPACK stream manager.
    pub fn new() -> Self {
        Self {
            encoder_stream_id: None,
            decoder_stream_id: None,
            blocked_streams: std::collections::HashSet::new(),
        }
    }
    
    /// Check if encoder stream has been set.
    pub fn has_encoder_stream(&self) -> bool {
        self.encoder_stream_id.is_some()
    }
    
    /// Check if decoder stream has been set.
    pub fn has_decoder_stream(&self) -> bool {
        self.decoder_stream_id.is_some()
    }
    
    /// Set the encoder stream ID.
    pub fn set_encoder_stream(&mut self, stream_id: u64) {
        self.encoder_stream_id = Some(stream_id);
    }
    
    /// Set the decoder stream ID.
    pub fn set_decoder_stream(&mut self, stream_id: u64) {
        self.decoder_stream_id = Some(stream_id);
    }

    /// Process an instruction from the peer's encoder stream.
    /// Returns the instruction for the caller to process with the codec.
    pub fn process_encoder_instruction(
        &mut self,
        instruction: QpackInstruction,
    ) -> Result<QpackInstruction, H3Error> {
        // Validate instruction type
        match instruction {
            QpackInstruction::InsertWithNameReference { .. }
            | QpackInstruction::InsertWithLiteralName { .. }
            | QpackInstruction::SetDynamicTableCapacity { .. }
            | QpackInstruction::Duplicate { .. } => {
                // Valid encoder stream instructions
                Ok(instruction)
            }
            _ => {
                Err(H3Error::Qpack(format!(
                    "unexpected instruction on encoder stream: {:?}",
                    instruction
                )))
            }
        }
    }

    /// Process an instruction from the peer's decoder stream.
    /// Returns the instruction for the caller to process with the codec.
    pub fn process_decoder_instruction(
        &mut self,
        instruction: QpackInstruction,
    ) -> Result<QpackInstruction, H3Error> {
        match instruction {
            QpackInstruction::SectionAcknowledgment { stream_id } => {
                // Section was successfully decoded
                self.blocked_streams.remove(&stream_id);
                Ok(instruction)
            }
            QpackInstruction::StreamCancellation { stream_id } => {
                // Stream was cancelled, release references
                self.blocked_streams.remove(&stream_id);
                Ok(instruction)
            }
            QpackInstruction::InsertCountIncrement { .. } => {
                // Update known received count
                Ok(instruction)
            }
            _ => {
                Err(H3Error::Qpack(format!(
                    "unexpected instruction on decoder stream: {:?}",
                    instruction
                )))
            }
        }
    }

    /// Mark a stream as blocked waiting for dynamic table updates.
    pub fn mark_blocked(&mut self, stream_id: u64) {
        self.blocked_streams.insert(stream_id);
    }

    /// Check if a stream is blocked waiting for dynamic table updates.
    pub fn is_blocked(&self, stream_id: u64) -> bool {
        self.blocked_streams.contains(&stream_id)
    }

    /// Cancel a stream (remove from blocked set).
    pub fn cancel_stream(&mut self, stream_id: u64) {
        self.blocked_streams.remove(&stream_id);
    }
}

impl Default for QpackStreamManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_tracking() {
        let mut manager = QpackStreamManager::new();
        
        assert!(!manager.has_encoder_stream());
        assert!(!manager.has_decoder_stream());
        
        manager.set_encoder_stream(2);
        manager.set_decoder_stream(3);
        
        assert!(manager.has_encoder_stream());
        assert!(manager.has_decoder_stream());
    }

    #[test]
    fn test_blocked_streams() {
        let mut manager = QpackStreamManager::new();
        
        manager.mark_blocked(4);
        assert!(manager.is_blocked(4));
        
        manager.cancel_stream(4);
        assert!(!manager.is_blocked(4));
    }

    #[test]
    fn test_encoder_instruction_validation() {
        let mut manager = QpackStreamManager::new();
        
        let valid = QpackInstruction::SetDynamicTableCapacity { capacity: 4096 };
        assert!(manager.process_encoder_instruction(valid).is_ok());
        
        let invalid = QpackInstruction::SectionAcknowledgment { stream_id: 4 };
        assert!(manager.process_encoder_instruction(invalid).is_err());
    }

    #[test]
    fn test_decoder_instruction_processing() {
        let mut manager = QpackStreamManager::new();
        
        manager.mark_blocked(4);
        let ack = QpackInstruction::SectionAcknowledgment { stream_id: 4 };
        assert!(manager.process_decoder_instruction(ack).is_ok());
        assert!(!manager.is_blocked(4));
    }
}
