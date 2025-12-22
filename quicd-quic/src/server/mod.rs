//! # QUIC Server State Machine (RFC 9000 Section 7, 8)
//!
//! Connection acceptance, version negotiation, and retry logic.

#![forbid(unsafe_code)]

use crate::connection::{Connection, ConnectionConfig};
use crate::connection::state::QuicConnection;
use crate::crypto::CryptoBackend;
use crate::error::{Error, Result, TransportError};
use crate::packet::{Header, PacketParser, PacketType};
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            supported_versions: vec![VERSION_1],
            transport_params: TransportParameters::default_server(),
            require_retry: false,
            max_connections: 100000,
            idle_timeout: core::time::Duration::from_secs(30),
        }
    }
}

/// Server Implementation Skeleton
pub struct DefaultQuicServer {
    /// Server configuration
    config: ServerConfig,

    /// Active connections (keyed by DCID)
    connections: HashMap<ConnectionId, Box<dyn Connection>>,

    /// Packet parser
    packet_parser: Box<dyn PacketParser>,

    /// Crypto backend factory
    crypto_backend: Box<dyn CryptoBackend>,
}

impl DefaultQuicServer {
    /// Create new server
    pub fn new(config: ServerConfig, crypto_backend: Box<dyn CryptoBackend>) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            packet_parser: Box::new(crate::packet::header::DefaultPacketParser),
            crypto_backend,
        }
    }

    /// Check if version is supported
    fn is_version_supported(&self, version: u32) -> bool {
        self.config.supported_versions.contains(&version)
    }
}

impl QuicServer for DefaultQuicServer {
    fn process_initial_datagram(
        &mut self,
        data: Bytes,
        recv_time: Instant,
    ) -> Result<Option<ConnectionId>> {
        unimplemented!("Skeleton - no implementation required")
    }

    fn accept_connection(
        &mut self,
        dcid: ConnectionId,
        scid: ConnectionId,
        remote_address: &[u8],
    ) -> Result<Box<dyn Connection>> {
        let conn_config = ConnectionConfig {
            local_params: self.config.transport_params.clone(),
            idle_timeout: self.config.idle_timeout,
            max_packet_size: 1200,
        };

        let conn = QuicConnection::new(Side::Server, scid, dcid, conn_config);
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
        unimplemented!("Skeleton")
    }

    fn send_retry(
        &self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: &Token,
        buf: &mut BytesMut,
    ) -> Result<usize> {
        unimplemented!("Skeleton")
    }

    fn generate_retry_token(&self, client_address: &[u8], original_dcid: &ConnectionId) -> Token {
        unimplemented!("Skeleton")
    }

    fn validate_retry_token(&self, token: &Token, client_address: &[u8]) -> Result<ConnectionId> {
        unimplemented!("Skeleton")
    }

    fn supported_versions(&self) -> &[u32] {
        &self.config.supported_versions
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
