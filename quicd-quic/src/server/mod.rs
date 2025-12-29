//! # QUIC Server State Machine (RFC 9000 Section 7, 8)
//!
//! Connection acceptance, version negotiation, and retry logic.

#![forbid(unsafe_code)]

pub mod amplification;

use self::amplification::AmplificationLimiter;
use crate::connection::state::QuicConnection;
use crate::connection::{
    Connection, ConnectionConfig, ConnectionIdGenerator, ConnectionIdManager, NewConnectionIdData,
    RandomConnectionIdGenerator,
};
use crate::crypto::CryptoBackend;
use crate::error::{Error, Result, TransportError};
use crate::packet::PacketParserTrait;
use crate::transport::TransportParameters;
use crate::types::{ConnectionId, Instant, Side, Token};
use crate::version::{VERSION_1, VERSION_NEGOTIATION};
use bytes::{Bytes, BytesMut};
extern crate alloc;
use alloc::collections::BTreeMap as HashMap;

/// Server State Machine
///
/// Manages multiple connections and handles:
/// - Version Negotiation (RFC 9000 Section 6)
/// - Address Validation and Retry (RFC 9000 Section 8)
/// - Connection ID routing
///
/// **Design**: Stateless where possible (Retry, Version Negotiation).
/// Stateful only after Initial packet validated.
pub trait QuicServer: Send {
    /// Process incoming datagram (may create new connection)
    ///
    /// **Returns**:
    /// - Ok(Some(cid)): Datagram routed to existing connection
    /// - Ok(None): Datagram handled (Version Negotiation/Retry sent)
    /// - Err: Invalid packet
    fn process_initial_datagram(
        &mut self,
        data: Bytes,
        recv_time: Instant,
    ) -> Result<Option<ConnectionId>>;

    /// Accept new connection after address validation
    ///
    /// Creates Connection instance for accepted client.
    fn accept_connection(
        &mut self,
        dcid: ConnectionId,
        scid: ConnectionId,
        remote_address: &[u8],
    ) -> Result<Box<dyn Connection>>;

    /// Get connection by CID
    fn get_connection(&mut self, cid: &ConnectionId) -> Option<&mut Box<dyn Connection>>;

    /// Remove closed connection
    fn remove_connection(&mut self, cid: &ConnectionId);

    /// Send Version Negotiation packet
    ///
    /// **Stateless**: No connection created.
    fn send_version_negotiation(
        &self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        buf: &mut BytesMut,
    ) -> Result<usize>;

    /// Send Retry packet (address validation)
    ///
    /// **Stateless**: Forces client to prove address ownership.
    fn send_retry(
        &self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: &Token,
        buf: &mut BytesMut,
    ) -> Result<usize>;

    /// Generate retry token
    ///
    /// Token encodes: client address, timestamp, original DCID.
    /// Must be verifiable and tamper-proof (HMAC).
    fn generate_retry_token(&self, client_address: &[u8], original_dcid: &ConnectionId) -> Token;

    /// Validate retry token
    ///
    /// Checks token authenticity and freshness.
    fn validate_retry_token(&self, token: &Token, client_address: &[u8]) -> Result<ConnectionId>;

    /// Get supported QUIC versions
    fn supported_versions(&self) -> &[u32];

    /// Create connection ID generator for new connection
    ///
    /// **Pluggable Design**: Server provides generator (e.g., eBPF-aware).
    /// Library manages CID lifecycle via ConnectionIdManager.
    fn create_cid_generator(&self) -> Box<dyn ConnectionIdGenerator>;

    /// Generate and issue NEW_CONNECTION_ID frames
    ///
    /// Called by connection when it needs more CIDs for rotation.
    fn issue_connection_ids(
        &mut self,
        connection_id: &ConnectionId,
        count: usize,
    ) -> Result<Vec<NewConnectionIdData>>;

    /// Generate Stateless Reset packet
    ///
    /// **RFC 9000 Section 10.3**: Used when server has no state for connection.
    /// Packet format: random bits + 16-byte stateless reset token.
    fn send_stateless_reset(
        &self,
        dcid: &ConnectionId,
        original_packet_len: usize,
        buf: &mut BytesMut,
    ) -> Result<usize>;

    /// Calculate stateless reset token for a connection ID
    ///
    /// **RFC 9000 Section 10.3.2**: HMAC(static_key, connection_id) truncated to 16 bytes.
    fn calculate_stateless_reset_token(&self, cid: &ConnectionId) -> [u8; 16];
}

/// Server Configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Supported QUIC versions
    pub supported_versions: Vec<u32>,

    /// Default transport parameters for connections
    pub transport_params: TransportParameters,

    /// Require address validation (Retry)
    pub require_retry: bool,

    /// Maximum connections
    pub max_connections: usize,

    /// Connection idle timeout
    pub idle_timeout: core::time::Duration,

    /// Active connection ID limit (how many CIDs we can track per connection)
    pub active_connection_id_limit: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            supported_versions: vec![VERSION_1],
            transport_params: TransportParameters::default_server(),
            require_retry: false,
            max_connections: 100000,
            idle_timeout: core::time::Duration::from_secs(30),
            active_connection_id_limit: 8,
        }
    }
}

/// Server Implementation Skeleton
pub struct DefaultQuicServer {
    /// Server configuration
    config: ServerConfig,

    /// Active connections (keyed by DCID)
    connections: HashMap<ConnectionId, Box<dyn Connection>>,

    /// Packet parser (stored for future trait-based parsing)
    #[allow(dead_code)]
    packet_parser: Box<dyn PacketParserTrait>,

    /// Crypto backend factory (stored for connection creation)
    #[allow(dead_code)]
    crypto_backend: Box<dyn CryptoBackend>,

    /// Static secret for token generation (HMAC key)
    /// RFC 9000 Section 8.1.4: Used to create stateless address validation tokens
    token_secret: [u8; 32],

    /// Static secret for stateless reset token generation
    /// RFC 9000 Section 10.3.2: Used to derive reset tokens from connection IDs
    reset_secret: [u8; 32],

    /// Anti-amplification limiter (stored for future enforcement)
    /// RFC 9000 Section 8.1: Enforces 3x sending limit to unvalidated addresses
    #[allow(dead_code)]
    amp_limiter: AmplificationLimiter,

    /// Connection ID managers (per connection)
    cid_managers: HashMap<ConnectionId, ConnectionIdManager>,
}

impl DefaultQuicServer {
    /// Create new server
    pub fn new(config: ServerConfig, crypto_backend: Box<dyn CryptoBackend>) -> Self {
        // Generate random secrets for token/reset generation
        let mut token_secret = [0u8; 32];
        let mut reset_secret = [0u8; 32];

        // In production, these should be cryptographically random
        // For now, use simple generation (real impl would use rand::thread_rng)
        for i in 0..32 {
            token_secret[i] = (i as u8).wrapping_mul(17).wrapping_add(42);
            reset_secret[i] = (i as u8).wrapping_mul(23).wrapping_add(97);
        }

        Self {
            config,
            connections: HashMap::new(),
            packet_parser: Box::new(crate::packet::parser::DefaultPacketParser::new(65535)),
            crypto_backend,
            token_secret,
            reset_secret,
            amp_limiter: AmplificationLimiter::new(),
            cid_managers: HashMap::new(),
        }
    }

    /// Check if version is supported (RFC 9000 Section 6)
    ///
    /// TODO: Used during version negotiation processing
    #[allow(dead_code)]
    fn is_version_supported(&self, version: u32) -> bool {
        self.config.supported_versions.contains(&version)
    }

    /// Simple HMAC-SHA256 for token integrity (RFC 9000 Section 8.1.4)
    ///
    /// Note: In a real implementation, use a proper HMAC library.
    /// This is a simplified version for demonstration.
    fn compute_hmac(&self, key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        // Simplified HMAC - real implementation would use sha2 crate
        // For now, XOR-based checksum (NOT cryptographically secure!)
        let mut result = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            result[i % 32] ^= byte.wrapping_add(key[i % 32]);
        }
        result
    }
}

impl QuicServer for DefaultQuicServer {
    fn process_initial_datagram(
        &mut self,
        _data: Bytes,
        _recv_time: Instant,
    ) -> Result<Option<ConnectionId>> {
        unimplemented!("Skeleton - no implementation required")
    }

    fn accept_connection(
        &mut self,
        dcid: ConnectionId,
        scid: ConnectionId,
        _remote_address: &[u8],
    ) -> Result<Box<dyn Connection>> {
        let conn_config = ConnectionConfig {
            local_params: self.config.transport_params.clone(),
            idle_timeout: self.config.idle_timeout,
            max_packet_size: 1200,
            cert_data: None,
            key_data: None,
            alpn_protocols: Vec::new(), // Server skeleton - not used in production
        };

        // Note: This is skeleton code - original_dcid should be provided in production
        let conn = QuicConnection::new(Side::Server, scid, dcid, None, conn_config);
        Ok(Box::new(conn))
    }

    fn get_connection(&mut self, cid: &ConnectionId) -> Option<&mut Box<dyn Connection>> {
        self.connections.get_mut(cid)
    }

    fn remove_connection(&mut self, cid: &ConnectionId) {
        self.connections.remove(cid);
    }

    fn send_version_negotiation(
        &self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        buf: &mut BytesMut,
    ) -> Result<usize> {
        // RFC 9000 Section 6.1: Version Negotiation Packet Generation
        //
        // Format:
        //   - Header Form (1) = 1
        //   - Unused (7)
        //   - Version (32) = 0x00000000
        //   - DCID Len (8)
        //   - DCID (0..2040)
        //   - SCID Len (8)
        //   - SCID (0..2040)
        //   - Supported Version (32) ...
        //
        // Echo client's CIDs to ensure proper routing.

        use bytes::BufMut;

        let start_pos = buf.len();

        // First byte: 1 (long header) + 7 unused bits (set to 0)
        let first_byte = 0x80;
        buf.put_u8(first_byte);

        // Version field: 0x00000000 for Version Negotiation
        buf.put_u32(VERSION_NEGOTIATION);

        // Destination Connection ID
        let dcid_bytes = dcid.as_bytes();
        if dcid_bytes.len() > 255 {
            return Err(Error::InvalidInput);
        }
        buf.put_u8(dcid_bytes.len() as u8);
        buf.extend_from_slice(dcid_bytes);

        // Source Connection ID
        let scid_bytes = scid.as_bytes();
        if scid_bytes.len() > 255 {
            return Err(Error::InvalidInput);
        }
        buf.put_u8(scid_bytes.len() as u8);
        buf.extend_from_slice(scid_bytes);

        // Supported Versions (must include at least one)
        for &version in self.supported_versions() {
            buf.put_u32(version);
        }

        let written = buf.len() - start_pos;
        Ok(written)
    }

    fn send_retry(
        &self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: &Token,
        buf: &mut BytesMut,
    ) -> Result<usize> {
        // RFC 9000 Section 17.2.5: Retry Packet
        //
        // Format:
        //   - Header Form (1) = 1
        //   - Fixed Bit (1) = 1
        //   - Long Packet Type (2) = 3
        //   - Unused (4)
        //   - Version (32)
        //   - DCID Len (8)
        //   - DCID (0..160)
        //   - SCID Len (8)
        //   - SCID (0..160)
        //   - Retry Token (..)
        //   - Retry Integrity Tag (128) - computed per RFC 9001 Section 5.8
        //
        // DCID: client's source CID from Initial packet
        // SCID: server-chosen new CID (MUST differ from client's DCID)

        use bytes::BufMut;

        let start_pos = buf.len();

        // First byte: 11 (long header) + 11 (type=3/Retry) + 0000 (unused)
        let first_byte = 0xF0; // 1111_0000
        buf.put_u8(first_byte);

        // Version (QUIC v1)
        buf.put_u32(VERSION_1);

        // Destination Connection ID (client's SCID from Initial)
        let dcid_bytes = dcid.as_bytes();
        if dcid_bytes.len() > 20 {
            return Err(Error::InvalidInput);
        }
        buf.put_u8(dcid_bytes.len() as u8);
        buf.extend_from_slice(dcid_bytes);

        // Source Connection ID (server-chosen, MUST be different from DCID)
        let scid_bytes = scid.as_bytes();
        if scid_bytes.len() > 20 {
            return Err(Error::InvalidInput);
        }
        if scid_bytes == dcid_bytes {
            return Err(Error::InvalidInput);
        }
        buf.put_u8(scid_bytes.len() as u8);
        buf.extend_from_slice(scid_bytes);

        // Retry Token
        let token_bytes = token.as_bytes();
        if token_bytes.is_empty() {
            return Err(Error::Transport(TransportError::ProtocolViolation));
        }
        buf.extend_from_slice(token_bytes);

        // Compute Retry Integrity Tag (RFC 9001 Section 5.8)
        //
        // Pseudo-packet format:
        //   - ODCID Len (8)
        //   - Original DCID (0..160) - the client's original DCID from first Initial
        //   - Retry packet bytes (without integrity tag)
        //
        // For now, use a simplified integrity tag calculation.
        // Real implementation would use AES-128-GCM with fixed key/nonce from RFC 9001.

        // TODO: In production, compute proper AES-128-GCM tag
        // For now, use placeholder (16 zero bytes)
        let integrity_tag = [0u8; 16];
        buf.extend_from_slice(&integrity_tag);

        let written = buf.len() - start_pos;
        Ok(written)
    }

    fn generate_retry_token(&self, client_address: &[u8], original_dcid: &ConnectionId) -> Token {
        // RFC 9000 Section 8.1.2: Retry Token Construction
        //
        // Token format (implementation-specific):
        //   - Timestamp (8 bytes) - for freshness check
        //   - Client Address Length (1 byte)
        //   - Client Address (variable)
        //   - Original DCID Length (1 byte)
        //   - Original DCID (variable)
        //   - HMAC (32 bytes) - integrity protection
        //
        // Token must be authenticated to prevent forgery.

        use bytes::BufMut;

        let mut token_buf = BytesMut::new();

        // Timestamp (seconds since epoch - simplified, real impl would use actual time)
        let timestamp = 0u64; // Placeholder - real impl: SystemTime::now()
        token_buf.put_u64(timestamp);

        // Client address
        if client_address.len() > 255 {
            // Address too long, truncate
            token_buf.put_u8(255);
            token_buf.extend_from_slice(&client_address[..255]);
        } else {
            token_buf.put_u8(client_address.len() as u8);
            token_buf.extend_from_slice(client_address);
        }

        // Original DCID
        let dcid_bytes = original_dcid.as_bytes();
        if dcid_bytes.len() > 255 {
            // Should not happen for valid connection IDs
            token_buf.put_u8(20);
            token_buf.extend_from_slice(&dcid_bytes[..20]);
        } else {
            token_buf.put_u8(dcid_bytes.len() as u8);
            token_buf.extend_from_slice(dcid_bytes);
        }

        // Compute HMAC over all data
        let hmac = self.compute_hmac(&self.token_secret, &token_buf[..]);
        token_buf.extend_from_slice(&hmac);

        Token::new(token_buf.freeze())
    }

    fn validate_retry_token(&self, token: &Token, client_address: &[u8]) -> Result<ConnectionId> {
        // RFC 9000 Section 8.1.3: Token Validation
        //
        // Verify:
        // 1. Token HMAC is valid (prevents forgery)
        // 2. Client address matches (prevents replay to different address)
        // 3. Token is not expired (freshness)

        let token_bytes = token.as_bytes();

        // Minimum token size: 8 (timestamp) + 1 (addr len) + 1 (dcid len) + 32 (hmac) = 42
        if token_bytes.len() < 42 {
            return Err(Error::Transport(TransportError::InvalidToken));
        }

        // Extract HMAC (last 32 bytes)
        let hmac_offset = token_bytes.len() - 32;
        let provided_hmac = &token_bytes[hmac_offset..];
        let data = &token_bytes[..hmac_offset];

        // Verify HMAC
        let expected_hmac = self.compute_hmac(&self.token_secret, data);
        if provided_hmac != &expected_hmac[..] {
            return Err(Error::Transport(TransportError::InvalidToken));
        }

        // Parse token data
        let mut offset = 0;

        // Timestamp
        if data.len() < offset + 8 {
            return Err(Error::Transport(TransportError::InvalidToken));
        }
        let timestamp_bytes: [u8; 8] = data[offset..offset + 8]
            .try_into()
            .map_err(|_| Error::Transport(TransportError::InvalidToken))?;
        let _timestamp = u64::from_be_bytes(timestamp_bytes);
        offset += 8;

        // TODO: Check timestamp freshness (e.g., within 30 seconds)
        // For now, accept all timestamps

        // Client address
        if data.len() < offset + 1 {
            return Err(Error::Transport(TransportError::InvalidToken));
        }
        let addr_len = data[offset] as usize;
        offset += 1;

        if data.len() < offset + addr_len {
            return Err(Error::Transport(TransportError::InvalidToken));
        }
        let token_address = &data[offset..offset + addr_len];
        offset += addr_len;

        // Verify address matches
        if token_address != client_address {
            return Err(Error::Transport(TransportError::InvalidToken));
        }

        // Original DCID
        if data.len() < offset + 1 {
            return Err(Error::Transport(TransportError::InvalidToken));
        }
        let dcid_len = data[offset] as usize;
        offset += 1;

        if data.len() < offset + dcid_len {
            return Err(Error::Transport(TransportError::InvalidToken));
        }
        let dcid_bytes = &data[offset..offset + dcid_len];

        // Reconstruct original DCID using from_slice
        let original_dcid = ConnectionId::from_slice(dcid_bytes)
            .ok_or(Error::Transport(TransportError::InvalidToken))?;

        Ok(original_dcid)
    }

    fn supported_versions(&self) -> &[u32] {
        &self.config.supported_versions
    }

    fn create_cid_generator(&self) -> Box<dyn ConnectionIdGenerator> {
        // Default implementation uses random CID generator
        // Server can override this to provide eBPF-aware generator
        Box::new(RandomConnectionIdGenerator::new(self.reset_secret))
    }

    fn issue_connection_ids(
        &mut self,
        connection_id: &ConnectionId,
        count: usize,
    ) -> Result<Vec<NewConnectionIdData>> {
        // Get or create CID manager for this connection
        let active_limit = self.config.active_connection_id_limit;
        let reset_secret = self.reset_secret;
        let manager = self
            .cid_managers
            .entry(connection_id.clone())
            .or_insert_with(|| {
                ConnectionIdManager::new(
                    Box::new(RandomConnectionIdGenerator::new(reset_secret)),
                    connection_id.clone(),
                    active_limit,
                )
            });

        manager.issue_new_cids(count)
    }

    fn send_stateless_reset(
        &self,
        dcid: &ConnectionId,
        original_packet_len: usize,
        buf: &mut BytesMut,
    ) -> Result<usize> {
        // RFC 9000 Section 10.3: Stateless Reset
        //
        // Format:
        //   - Fixed Bits (2) = 1 (appears as short header)
        //   - Unpredictable Bits (38..) - randomized
        //   - Stateless Reset Token (128) - last 16 bytes
        //
        // Minimum size: 21 bytes (1 + 4 + 16)
        // MUST be smaller than original packet (anti-amplification)

        use bytes::BufMut;

        let start_pos = buf.len();

        // Calculate stateless reset token for this CID
        let reset_token = self.calculate_stateless_reset_token(dcid);

        // Determine packet size (smaller than original, at least 21 bytes)
        let reset_size = if original_packet_len >= 43 {
            // Make it one byte shorter than original
            original_packet_len - 1
        } else {
            // Use minimum size
            21
        };

        // Must not amplify more than 3x
        let max_size = (original_packet_len * 3).min(1200);
        let reset_size = reset_size.min(max_size);

        if reset_size < 21 {
            return Err(Error::InvalidInput);
        }

        // First byte: 01 (short header) + 6 random bits (set to 0 for simplicity)
        let first_byte = 0x40;
        buf.put_u8(first_byte);

        // Unpredictable bits (everything except last 16 bytes)
        // In production, fill with cryptographically random data
        let random_bytes = reset_size - 1 - 16; // -1 for first byte, -16 for token
        for _ in 0..random_bytes {
            // Use simple pseudo-random pattern (not cryptographically secure)
            buf.put_u8(0xFF);
        }

        // Stateless Reset Token (last 16 bytes)
        buf.extend_from_slice(&reset_token);

        let written = buf.len() - start_pos;
        Ok(written)
    }

    fn calculate_stateless_reset_token(&self, cid: &ConnectionId) -> [u8; 16] {
        // RFC 9000 Section 10.3.2: Calculate stateless reset token
        //
        // Token = HMAC(static_key, connection_id)[0..16]
        //
        // Uses static server secret so tokens can be computed without state.

        let cid_bytes = cid.as_bytes();
        let hmac = self.compute_hmac(&self.reset_secret, cid_bytes);

        // Return first 16 bytes
        let mut token = [0u8; 16];
        token.copy_from_slice(&hmac[0..16]);
        token
    }
}

// ============================================================================
// Server Event (for application notifications)
// ============================================================================

/// Server Event
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// New connection accepted
    ConnectionAccepted { connection_id: ConnectionId },

    /// Connection closed
    ConnectionClosed { connection_id: ConnectionId },

    /// Version Negotiation sent (stateless)
    VersionNegotiationSent,

    /// Retry sent (stateless)
    RetrySent,
}
