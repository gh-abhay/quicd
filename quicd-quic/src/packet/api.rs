//! High-level Packet API
//!
//! Provides convenience wrappers around the lower-level packet parsing traits.

extern crate alloc;

use crate::error::{Error, Result, TransportError};
use crate::packet::header::DefaultHeaderParser;
use crate::packet::types::{PacketType, VERSION_1, VERSION_NEGOTIATION};
use crate::types::{ConnectionId, PacketNumber};
use bytes::{BufMut, Bytes, BytesMut};

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
    pub ty: PacketType,
    pub dcid: ConnectionId,
    pub scid: Option<ConnectionId>,
    pub version: u32,
    pub packet_number: Option<PacketNumber>,
    pub packet_number_len: Option<usize>, // Store actual packet number length after HP removal
    /// Key phase bit for 1-RTT packets (RFC 9001 Section 6)
    pub key_phase: bool,
}

impl Packet {
    /// Parse a QUIC packet from bytes with optional context
    pub fn parse_with_context(bytes: Bytes, ctx: ParseContext) -> Result<Self> {
        let _parser = DefaultHeaderParser;

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
                0x00 => PacketType::Initial,
                0x01 => PacketType::ZeroRtt,
                0x02 => PacketType::Handshake,
                0x03 => PacketType::Retry,
                _ => return Err(Error::Transport(TransportError::FrameEncodingError)),
            }
        } else {
            PacketType::OneRtt
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
            Some(
                ConnectionId::from_slice(&bytes[7 + dcid_len..7 + dcid_len + scid_len])
                    .ok_or(Error::Transport(TransportError::FrameEncodingError))?,
            )
        } else {
            None
        };

        let payload = bytes.slice(header_len.min(bytes.len())..);

        // Extract key_phase for short headers (RFC 9001 Section 6)
        // For short headers, key_phase is bit 2 (0x04) of first byte
        // Note: This is before header protection removal, so actual value may differ
        // It will be updated after header protection is removed
        let key_phase = if !is_long {
            (first_byte & 0x04) != 0
        } else {
            false
        };

        Ok(Self {
            header: PacketHeaderWrapper {
                ty,
                dcid,
                scid,
                version,
                packet_number: None,     // Not yet decoded
                packet_number_len: None, // Not yet decoded
                key_phase,
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
    /// * `hp` - Header protection provider
    /// * `hp_key` - Header protection key
    /// * `buf` - Original packet buffer (needed for sampling)
    /// * `dcid_len_override` - Optional DCID length override for Short headers
    ///                         (used when the parsed DCID length might be incorrect)
    pub fn remove_header_protection(
        &mut self,
        hp: &dyn crate::crypto::HeaderProtectionProvider,
        hp_key: &[u8],
        buf: &mut [u8],
        dcid_len_override: Option<usize>,
    ) -> Result<()> {
        // RFC 9001 Section 5.4: Header protection removal
        // 1. Determine packet number offset
        let is_long = (buf[0] & 0x80) != 0;
        let pn_offset = if is_long {
            // Long header: 1 (first byte) + 4 (version) + 1 (dcid_len) + dcid + 1 (scid_len) + scid
            if buf.len() < 6 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            let dcid_len = buf[5] as usize;
            if buf.len() < 7 + dcid_len {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            let scid_len = buf[6 + dcid_len] as usize;
            let mut offset = 7 + dcid_len + scid_len;

            // For Initial packets, parse Token Length and Token fields
            if self.header.ty == crate::packet::types::PacketType::Initial {
                // Parse Token Length (variable-length integer)
                if buf.len() < offset {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                let (token_len, token_len_bytes) =
                    match crate::types::VarIntCodec::decode(&buf[offset..]) {
                        Some((len, bytes)) => (len as usize, bytes),
                        None => return Err(Error::Transport(TransportError::FrameEncodingError)),
                    };
                offset += token_len_bytes;

                // Skip Token field
                if buf.len() < offset + token_len {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                offset += token_len;
            }

            // Parse Length field (variable-length integer) - present in all long header packets
            if buf.len() < offset {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            let (_length, length_bytes) = match crate::types::VarIntCodec::decode(&buf[offset..]) {
                Some((len, bytes)) => (len, bytes),
                None => return Err(Error::Transport(TransportError::FrameEncodingError)),
            };
            offset += length_bytes;

            // Now offset points to Packet Number
            offset
        } else {
            // Short header: 1 (first byte) + DCID length
            // For 1-RTT packets, the DCID is the server's SCID
            // Use override if provided, otherwise use the parsed DCID length
            let dcid_len = dcid_len_override.unwrap_or_else(|| {
                if self.header.dcid.len() == 0 {
                    return 0;
                }
                self.header.dcid.len()
            });
            if dcid_len == 0 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            1 + dcid_len
        };

        // 2. Extract 16-byte sample starting 4 bytes after PN offset (RFC 9001 Section 5.4.2)
        let sample_offset = pn_offset + 4;
        if buf.len() < sample_offset + 16 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }
        let sample = &buf[sample_offset..sample_offset + 16];

        // 3. Build 5-byte mask using HP algorithm
        let mut mask = [0u8; 5];
        hp.build_mask(hp_key, sample, &mut mask)?;

        // 4. Apply mask to first byte to reveal actual PN length
        // Modify the buffer in-place
        if is_long {
            // Long header: mask 4 least significant bits
            buf[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: mask 5 least significant bits
            buf[0] ^= mask[0] & 0x1f;
        }

        // Extract actual PN length from unmasked first byte (now in buf[0])
        let actual_pn_length = ((buf[0] & 0x03) + 1) as usize;

        // 5. Extract and unmask packet number (modify buffer in-place)
        if buf.len() < pn_offset + actual_pn_length {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let mut pn_bytes = [0u8; 4];
        for i in 0..actual_pn_length {
            // Unmask the packet number bytes in the buffer
            buf[pn_offset + i] ^= mask[1 + i];
            pn_bytes[i] = buf[pn_offset + i];
        }

        // Convert to u64 (left-padded with zeros)
        let mut pn_value = 0u64;
        for i in 0..actual_pn_length {
            pn_value = (pn_value << 8) | (pn_bytes[i] as u64);
        }

        // Store unmasked packet number and length in header
        self.header.packet_number = Some(pn_value);
        self.header.packet_number_len = Some(actual_pn_length);
        
        // Update key_phase for short headers after HP removal (RFC 9001 Section 5.4.1)
        // The key phase bit (bit 2, 0x04) is now unmasked
        if !is_long {
            self.header.key_phase = (buf[0] & 0x04) != 0;
        }
        
        self.hp_removed = true;

        Ok(())
    }

    /// Create a Version Negotiation packet
    ///
    /// RFC 9000 Section 17.2.1: Version Negotiation packet format
    pub fn create_version_negotiation(
        dcid: ConnectionId,
        scid: ConnectionId,
        _supported_versions: Vec<u32>,
    ) -> Self {
        Self {
            header: PacketHeaderWrapper {
                ty: PacketType::VersionNegotiation,
                dcid: dcid.clone(),
                scid: Some(scid.clone()),
                version: VERSION_NEGOTIATION,
                packet_number: None,
                packet_number_len: None,
                key_phase: false,
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
            PacketType::VersionNegotiation => {
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
