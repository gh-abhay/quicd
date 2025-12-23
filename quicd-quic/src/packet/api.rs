//! High-level Packet API
//!
//! Provides convenience wrappers around the lower-level packet parsing traits.

extern crate alloc;

use crate::error::{Error, Result, TransportError};
use crate::packet::header::{DefaultHeaderParser, HeaderForm};
use crate::packet::number::{DefaultPacketNumberDecoder, DefaultPacketNumberEncoder, PacketNumberLen};
use crate::packet::parser::PacketParser;
use crate::packet::types::{PacketHeader, LongPacketType, ParsedPacket, Token, VERSION_1, VERSION_NEGOTIATION};
use crate::types::{ConnectionId, PacketNumber, Instant};
use bytes::{Bytes, BytesMut, BufMut};

/// Parse context for packet parsing
///
/// Provides configuration needed to parse packets, especially for Short header packets
/// which don't encode the DCID length.
#[derive(Debug, Clone, Default)]
pub struct ParseContext {
    /// Expected DCID length for Short header packets (0-20 bytes)
    pub dcid_len: Option<usize>,
    
    /// Largest acknowledged packet number (for PN decoding)
    pub largest_ack: PacketNumber,
}

impl ParseContext {
    /// Create context with specific DCID length
    pub fn with_dcid_len(dcid_len: usize) -> Self {
        Self {
            dcid_len: Some(dcid_len),
            largest_ack: 0,
        }
    }
    
    /// Create context with largest acknowledged packet number
    pub fn with_largest_ack(largest_ack: PacketNumber) -> Self {
        Self {
            dcid_len: None,
            largest_ack,
        }
    }
}

/// High-level QUIC packet representation
///
/// Wraps the parsed packet header and payload, providing convenient methods
/// for common operations.
#[derive(Debug)]
pub struct Packet {
    /// Parsed packet header
    pub header: PacketHeaderWrapper,
    
    /// Encrypted payload
    pub payload: Bytes,
    
    /// Header length in bytes
    pub header_len: usize,
    
    /// Whether header protection has been removed
    pub hp_removed: bool,
}

/// Wrapper around PacketHeader for easier API
#[derive(Debug, Clone)]
pub struct PacketHeaderWrapper {
    pub ty: PacketTypeWrapper,
    pub dcid: ConnectionId,
    pub scid: Option<ConnectionId>,
    pub version: u32,
    pub packet_number: Option<PacketNumber>,
}

/// Simplified packet type for API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketTypeWrapper {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short,
    VersionNegotiation,
}

impl Packet {
    /// Parse a QUIC packet from bytes with optional context
    pub fn parse_with_context(bytes: Bytes, ctx: ParseContext) -> Result<Self> {
        let parser = DefaultHeaderParser;
        
        // Parse the first byte to check header form
        if bytes.is_empty() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }
        
        let first_byte = bytes[0];
        let is_long = (first_byte & 0x80) != 0;
        
        // For now, do a simple parse - we'll enhance this with proper context handling
        let header_len = if is_long {
            // Long header: at least 1 + 4 (version) + 1 (dcid_len) bytes
            if bytes.len() < 6 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            let dcid_len = bytes[5] as usize;
            if bytes.len() < 6 + dcid_len + 1 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            let scid_len = bytes[6 + dcid_len] as usize;
            7 + dcid_len + scid_len // Minimum header length
        } else {
            // Short header: 1 byte + DCID + PN
            let dcid_len = ctx.dcid_len.unwrap_or(0);
            1 + dcid_len + 1 // At least 1 byte for PN
        };
        
        // Extract header info manually for now
        let version = if is_long {
            u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])
        } else {
            VERSION_1
        };
        
        let ty = if is_long {
            let type_bits = (first_byte >> 4) & 0x03;
            match type_bits {
                0x00 => PacketTypeWrapper::Initial,
                0x01 => PacketTypeWrapper::ZeroRtt,
                0x02 => PacketTypeWrapper::Handshake,
                0x03 => PacketTypeWrapper::Retry,
                _ => return Err(Error::Transport(TransportError::FrameEncodingError)),
            }
        } else {
            PacketTypeWrapper::Short
        };
        
        let dcid = if is_long {
            let dcid_len = bytes[5] as usize;
            if bytes.len() < 6 + dcid_len {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            ConnectionId::from_slice(&bytes[6..6 + dcid_len])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?
        } else {
            let dcid_len = ctx.dcid_len.unwrap_or(0);
            if bytes.len() < 1 + dcid_len {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            ConnectionId::from_slice(&bytes[1..1 + dcid_len])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?
        };
        
        let scid = if is_long {
            let dcid_len = bytes[5] as usize;
            let scid_len = bytes[6 + dcid_len] as usize;
            if bytes.len() < 7 + dcid_len + scid_len {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            Some(ConnectionId::from_slice(&bytes[7 + dcid_len..7 + dcid_len + scid_len])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?)
        } else {
            None
        };
        
        let payload = bytes.slice(header_len.min(bytes.len())..);
        
        Ok(Self {
            header: PacketHeaderWrapper {
                ty,
                dcid,
                scid,
                version,
                packet_number: None, // Not yet decoded
            },
            payload,
            header_len,
            hp_removed: false,
        })
    }
    
    /// Parse a QUIC packet from bytes (no context)
    pub fn parse(bytes: Bytes) -> Result<Self> {
        Self::parse_with_context(bytes, ParseContext::default())
    }
    
    /// Remove header protection from the packet
    ///
    /// **Critical**: Must be called before decrypting payload.
    /// Modifies the packet in-place to reveal the actual packet number.
    ///
    /// # Arguments
    ///
    /// * `hp_key` - Header protection key (16 bytes)
    /// * `buf` - Original packet buffer (needed for sampling)
    pub fn remove_header_protection(&mut self, hp_key: &[u8], buf: &[u8]) -> Result<()> {
        // RFC 9001 Section 5.4: Header protection algorithm
        // 1. Extract 16-byte sample from payload
        // 2. Compute mask using HP algorithm
        // 3. XOR first byte and packet number bytes
        
        // For simplicity, mark as removed
        // Real implementation would apply XOR masks
        self.hp_removed = true;
        
        // TODO: Implement actual header protection removal algorithm
        // This requires:
        // 1. Determining sample offset (4 bytes after PN for Long, after PN for Short)
        // 2. Extracting 16-byte sample
        // 3. Computing ChaCha20 or AES-ECB mask
        // 4. Applying XOR masks to header
        
        Ok(())
    }
    
    /// Create a Version Negotiation packet
    ///
    /// RFC 9000 Section 17.2.1: Version Negotiation packet format
    pub fn create_version_negotiation(
        dcid: ConnectionId,
        scid: ConnectionId,
        supported_versions: Vec<u32>,
    ) -> Self {
        Self {
            header: PacketHeaderWrapper {
                ty: PacketTypeWrapper::VersionNegotiation,
                dcid: dcid.clone(),
                scid: Some(scid.clone()),
                version: VERSION_NEGOTIATION,
                packet_number: None,
            },
            payload: Bytes::new(), // Will be filled during serialization
            header_len: 0,
            hp_removed: false,
        }
    }
    
    /// Serialize the packet to bytes
    pub fn serialize(&self) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(1200);
        
        match self.header.ty {
            PacketTypeWrapper::VersionNegotiation => {
                // RFC 9000 Section 17.2.1: Version Negotiation packet
                // First byte: Long header (0x80) + unused bits (0x40 for fixed bit not required in VN)
                buf.put_u8(0x80 | 0x40);
                
                // Version (4 bytes) = 0x00000000
                buf.put_u32(VERSION_NEGOTIATION);
                
                // DCID Length + DCID
                let dcid_bytes = self.header.dcid.as_bytes();
                buf.put_u8(dcid_bytes.len() as u8);
                buf.put_slice(dcid_bytes);
                
                // SCID Length + SCID
                if let Some(ref scid) = self.header.scid {
                    let scid_bytes = scid.as_bytes();
                    buf.put_u8(scid_bytes.len() as u8);
                    buf.put_slice(scid_bytes);
                } else {
                    buf.put_u8(0); // Zero-length SCID
                }
                
                // Supported Versions (placeholder - would come from config)
                buf.put_u32(VERSION_1);
                
                Ok(buf.freeze())
            }
            _ => {
                // TODO: Implement serialization for other packet types
                Err(Error::Transport(TransportError::InternalError))
            }
        }
    }
}

