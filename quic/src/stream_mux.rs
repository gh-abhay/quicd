//! QUIC Stream Multiplexing
//!
//! Implements protocol detection and routing for multiplexed streams over QUIC.
//! Supports both ALPN-based (single protocol per connection) and stream-type
//! based (multiple protocols per connection) multiplexing.
//!
//! # Standards Compliance
//! - RFC 9000: QUIC Transport Protocol
//! - RFC 9114: HTTP/3
//! - IETF ALPN registry
//!
//! # Architecture
//! ```text
//! QUIC Connection (ALPN negotiated)
//!   ↓
//! Stream Multiplexer (protocol detection)
//!   ↓
//! Protocol Registry (ALPN/stream-type → service)
//!   ↓
//! Service Handler (process request)
//! ```

use std::collections::HashMap;

/// ALPN protocol identifiers (IETF standardized)
pub mod alpn {
    /// HTTP/3 (RFC 9114)
    pub const HTTP3: &[u8] = b"h3";
    
    /// HTTP/3 draft 29
    pub const HTTP3_29: &[u8] = b"h3-29";
    
    /// DNS over QUIC (RFC 9250)
    pub const DOQ: &[u8] = b"doq";
    
    /// Media over QUIC (draft)
    pub const MOQ: &[u8] = b"moq-00";
    
    /// WebTransport
    pub const WEBTRANSPORT: &[u8] = b"webtransport";
    
    /// Superd multiplexed services (custom)
    pub const SUPERD_MUX: &[u8] = b"x-superd-mux";
    
    /// Echo service (custom, single protocol)
    pub const SUPERD_ECHO: &[u8] = b"x-superd-echo";
}

/// Stream-type protocol IDs (for multiplexed connections)
///
/// These are sent as the first bytes of a stream when ALPN is set to
/// a multiplexing protocol (e.g., `x-superd-mux`).
///
/// Format: QUIC variable-length integer (1-8 bytes)
pub mod stream_type {
    /// HTTP/3 request stream (RFC 9114)
    pub const HTTP3_REQUEST: u64 = 0x00;
    
    /// HTTP/3 push stream (RFC 9114)
    pub const HTTP3_PUSH: u64 = 0x01;
    
    /// HTTP/3 QPACK encoder stream (RFC 9114)
    pub const HTTP3_QPACK_ENCODER: u64 = 0x02;
    
    /// HTTP/3 QPACK decoder stream (RFC 9114)
    pub const HTTP3_QPACK_DECODER: u64 = 0x03;
    
    // 0x04 - 0x3F: Reserved for IETF standards
    
    // 0x40 - 0xBF: Reserved for extensions
    
    // 0xC0 - 0xFF: Private/Experimental use
    
    /// Echo service (custom)
    pub const ECHO: u64 = 0xC0;
    
    /// Custom service 1
    pub const CUSTOM_1: u64 = 0xC1;
    
    /// Custom service 2
    pub const CUSTOM_2: u64 = 0xC2;
}

/// Protocol detection result
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// HTTP/3 (ALPN or stream-type based)
    Http3,
    
    /// Echo service
    Echo,
    
    /// WebTransport
    WebTransport,
    
    /// Custom protocol by ID
    Custom(u64),
    
    /// Unknown protocol
    Unknown,
}

/// Protocol routing information
#[derive(Debug, Clone)]
pub struct ProtocolRoute {
    /// Protocol identifier
    pub protocol: Protocol,
    
    /// Service name to route to
    pub service_name: &'static str,
    
    /// Offset in stream data where actual payload starts
    /// (after protocol-type header, if present)
    pub data_offset: usize,
}

/// Protocol detector and router
pub struct StreamMultiplexer {
    /// ALPN to protocol mapping
    alpn_map: HashMap<Vec<u8>, Protocol>,
    
    /// Stream-type ID to protocol mapping
    stream_type_map: HashMap<u64, Protocol>,
    
    /// Protocol to service name mapping
    protocol_service_map: HashMap<Protocol, &'static str>,
}

impl StreamMultiplexer {
    /// Create a new stream multiplexer with default protocol mappings
    pub fn new() -> Self {
        let mut mux = Self {
            alpn_map: HashMap::new(),
            stream_type_map: HashMap::new(),
            protocol_service_map: HashMap::new(),
        };
        
        // Register standard ALPN protocols
        mux.alpn_map.insert(alpn::HTTP3.to_vec(), Protocol::Http3);
        mux.alpn_map.insert(alpn::HTTP3_29.to_vec(), Protocol::Http3);
        mux.alpn_map.insert(alpn::SUPERD_ECHO.to_vec(), Protocol::Echo);
        mux.alpn_map.insert(alpn::WEBTRANSPORT.to_vec(), Protocol::WebTransport);
        
        // Register stream-type protocols (for multiplexed connections)
        mux.stream_type_map.insert(stream_type::HTTP3_REQUEST, Protocol::Http3);
        mux.stream_type_map.insert(stream_type::ECHO, Protocol::Echo);
        
        // Map protocols to service names
        mux.protocol_service_map.insert(Protocol::Http3, "http3");
        mux.protocol_service_map.insert(Protocol::Echo, "echo");
        
        mux
    }
    
    /// Register a custom ALPN protocol
    pub fn register_alpn(&mut self, alpn: &[u8], protocol: Protocol, service_name: &'static str) {
        self.alpn_map.insert(alpn.to_vec(), protocol.clone());
        self.protocol_service_map.insert(protocol, service_name);
    }
    
    /// Register a custom stream-type protocol
    pub fn register_stream_type(&mut self, type_id: u64, protocol: Protocol, service_name: &'static str) {
        self.stream_type_map.insert(type_id, protocol.clone());
        self.protocol_service_map.insert(protocol, service_name);
    }
    
    /// Detect protocol from ALPN and optionally stream-type header
    ///
    /// # Arguments
    /// - `alpn`: Negotiated ALPN from QUIC connection
    /// - `stream_data`: First bytes of stream (may contain protocol-type header)
    ///
    /// # Returns
    /// Protocol routing information including service name and data offset
    pub fn detect_protocol(&self, alpn: &[u8], stream_data: &[u8]) -> ProtocolRoute {
        // Check if ALPN indicates multiplexed connection
        if alpn == alpn::SUPERD_MUX {
            // Multiplexed: read stream-type header
            if let Some((type_id, offset)) = decode_varint(stream_data) {
                let protocol = self.stream_type_map
                    .get(&type_id)
                    .cloned()
                    .unwrap_or(Protocol::Unknown);
                
                let service_name = self.protocol_service_map
                    .get(&protocol)
                    .copied()
                    .unwrap_or("echo"); // Default fallback
                
                return ProtocolRoute {
                    protocol,
                    service_name,
                    data_offset: offset,
                };
            }
        }
        
        // ALPN-based protocol detection (single protocol per connection)
        let protocol = self.alpn_map
            .get(alpn)
            .cloned()
            .unwrap_or(Protocol::Echo); // Default to echo for unknown
        
        let service_name = self.protocol_service_map
            .get(&protocol)
            .copied()
            .unwrap_or("echo");
        
        ProtocolRoute {
            protocol,
            service_name,
            data_offset: 0, // No header, data starts at offset 0
        }
    }
    
    /// Get service name for a protocol
    pub fn service_for_protocol(&self, protocol: &Protocol) -> Option<&'static str> {
        self.protocol_service_map.get(protocol).copied()
    }
}

impl Default for StreamMultiplexer {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode QUIC variable-length integer
///
/// Returns (value, bytes_consumed) or None if insufficient data
///
/// QUIC varint encoding (RFC 9000 Section 16):
/// - First 2 bits indicate length:
///   - 0b00: 1 byte (6-bit value)
///   - 0b01: 2 bytes (14-bit value)
///   - 0b10: 4 bytes (30-bit value)
///   - 0b11: 8 bytes (62-bit value)
pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    
    let first_byte = data[0];
    let prefix = first_byte >> 6;
    
    match prefix {
        0b00 => {
            // 1 byte
            Some((u64::from(first_byte & 0x3F), 1))
        }
        0b01 => {
            // 2 bytes
            if data.len() < 2 {
                return None;
            }
            let value = u16::from_be_bytes([first_byte & 0x3F, data[1]]);
            Some((u64::from(value), 2))
        }
        0b10 => {
            // 4 bytes
            if data.len() < 4 {
                return None;
            }
            let mut bytes = [0u8; 4];
            bytes[0] = first_byte & 0x3F;
            bytes[1..4].copy_from_slice(&data[1..4]);
            let value = u32::from_be_bytes(bytes);
            Some((u64::from(value), 4))
        }
        0b11 => {
            // 8 bytes
            if data.len() < 8 {
                return None;
            }
            let mut bytes = [0u8; 8];
            bytes[0] = first_byte & 0x3F;
            bytes[1..8].copy_from_slice(&data[1..8]);
            let value = u64::from_be_bytes(bytes);
            Some((value, 8))
        }
        _ => unreachable!(),
    }
}

/// Encode QUIC variable-length integer
///
/// Returns the encoded bytes
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < (1 << 6) {
        // 1 byte
        vec![(value as u8)]
    } else if value < (1 << 14) {
        // 2 bytes
        let bytes = (value as u16).to_be_bytes();
        vec![bytes[0] | 0x40, bytes[1]]
    } else if value < (1 << 30) {
        // 4 bytes
        let bytes = (value as u32).to_be_bytes();
        vec![bytes[0] | 0x80, bytes[1], bytes[2], bytes[3]]
    } else {
        // 8 bytes
        let bytes = value.to_be_bytes();
        vec![
            bytes[0] | 0xC0,
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_varint_encoding() {
        // 1 byte
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(37), vec![0x25]);
        assert_eq!(encode_varint(63), vec![0x3F]);
        
        // 2 bytes
        assert_eq!(encode_varint(64), vec![0x40, 0x40]);
        assert_eq!(encode_varint(16383), vec![0x7F, 0xFF]);
        
        // 4 bytes
        assert_eq!(encode_varint(16384), vec![0x80, 0x00, 0x40, 0x00]);
        
        // 8 bytes
        assert_eq!(encode_varint(1 << 30), vec![0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
    }
    
    #[test]
    fn test_varint_decoding() {
        // 1 byte
        assert_eq!(decode_varint(&[0x25]), Some((37, 1)));
        assert_eq!(decode_varint(&[0x3F]), Some((63, 1)));
        
        // 2 bytes
        assert_eq!(decode_varint(&[0x40, 0x40]), Some((64, 2)));
        assert_eq!(decode_varint(&[0x7F, 0xFF]), Some((16383, 2)));
        
        // 4 bytes
        assert_eq!(decode_varint(&[0x80, 0x00, 0x40, 0x00]), Some((16384, 4)));
        
        // Insufficient data
        assert_eq!(decode_varint(&[0x40]), None);
        assert_eq!(decode_varint(&[]), None);
    }
    
    #[test]
    fn test_alpn_detection() {
        let mux = StreamMultiplexer::new();
        
        // HTTP/3 via ALPN
        let route = mux.detect_protocol(alpn::HTTP3, b"GET / HTTP/3");
        assert_eq!(route.protocol, Protocol::Http3);
        assert_eq!(route.service_name, "http3");
        assert_eq!(route.data_offset, 0);
        
        // Echo via ALPN
        let route = mux.detect_protocol(alpn::SUPERD_ECHO, b"hello world");
        assert_eq!(route.protocol, Protocol::Echo);
        assert_eq!(route.service_name, "echo");
        assert_eq!(route.data_offset, 0);
    }
    
    #[test]
    fn test_stream_type_detection() {
        let mux = StreamMultiplexer::new();
        
        // Multiplexed connection with stream-type header
        // Type 0xC0 (ECHO) + "hello world"
        let data = {
            let mut d = encode_varint(stream_type::ECHO);
            d.extend_from_slice(b"hello world");
            d
        };
        
        let route = mux.detect_protocol(alpn::SUPERD_MUX, &data);
        assert_eq!(route.protocol, Protocol::Echo);
        assert_eq!(route.service_name, "echo");
        assert!(route.data_offset > 0); // Header was consumed
    }
    
    #[test]
    fn test_custom_protocol_registration() {
        let mut mux = StreamMultiplexer::new();
        
        let custom_alpn = b"x-my-protocol";
        let custom_protocol = Protocol::Custom(999);
        
        mux.register_alpn(custom_alpn, custom_protocol.clone(), "my_service");
        
        let route = mux.detect_protocol(custom_alpn, b"data");
        assert_eq!(route.protocol, custom_protocol);
        assert_eq!(route.service_name, "my_service");
    }
}
