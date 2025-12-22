//! # QUIC Connection Facade (Complete Interface)
//!
//! This module provides the complete public interface for using the QUIC library.
//! It brings together all trait hierarchies into a cohesive API.

extern crate alloc;

use crate::types::*;
use crate::error::*;
use crate::packet::*;
use crate::frames::*;
use crate::crypto::*;
use crate::stream::*;
use crate::flow_control::*;
use crate::recovery::*;
use crate::transport::*;
use crate::connection::*;
use bytes::{Bytes, BytesMut};

/// QUIC Endpoint Trait
///
/// Represents a QUIC endpoint (client or server) that manages multiple connections.
/// This is the top-level abstraction for the entire QUIC stack.
pub trait QuicEndpoint: Send + Sync {
    /// Process an incoming datagram
    ///
    /// Demultiplexes to the appropriate connection based on Connection ID.
    /// For servers, may create new connections.
    ///
    /// # Arguments
    ///
    /// - `datagram`: Raw UDP payload
    /// - `recv_time`: Reception timestamp
    ///
    /// Returns the connection handle and events generated.
    fn process_datagram(
        &mut self,
        datagram: &[u8],
        recv_time: Instant,
    ) -> Result<(ConnectionHandle, alloc::vec::Vec<ConnectionEvent>)>;
    
    /// Create a new outbound connection (client only)
    ///
    /// Initiates a connection to a remote endpoint.
    fn connect(
        &mut self,
        server_name: &str,
        alpn_protocols: &[&[u8]],
    ) -> Result<ConnectionHandle>;
    
    /// Poll all connections for outgoing datagrams
    ///
    /// Returns datagrams ready to send.
    fn poll_all(&mut self, now: Instant) -> alloc::vec::Vec<(ConnectionHandle, Bytes)>;
    
    /// Get the next timeout across all connections
    fn next_timeout(&self) -> Option<(ConnectionHandle, Instant)>;
    
    /// Handle timeout for a specific connection
    fn on_timeout(&mut self, handle: ConnectionHandle, now: Instant) -> Result<()>;
}

/// Connection Handle
///
/// Opaque identifier for a specific connection.
/// Used to reference connections in the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionHandle(pub u64);

/// QUIC Server Trait
///
/// Server-specific functionality for accepting connections.
pub trait QuicServer: QuicEndpoint {
    /// Accept a new incoming connection
    ///
    /// Called when Initial packet is received from unknown source.
    fn accept_connection(
        &mut self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        remote_addr: &[u8],
    ) -> Result<ConnectionHandle>;
    
    /// Reject a connection with Retry
    ///
    /// Sends a Retry packet for address validation.
    fn send_retry(
        &mut self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        remote_addr: &[u8],
    ) -> Result<Bytes>;
    
    /// Get pending connections (handshake in progress)
    fn pending_connections(&self) -> alloc::vec::Vec<ConnectionHandle>;
}

/// QUIC Client Trait
///
/// Client-specific functionality.
pub trait QuicClient: QuicEndpoint {
    /// Check if 0-RTT is available
    ///
    /// Returns true if early data can be sent based on previous session.
    fn can_send_0rtt(&self, handle: ConnectionHandle) -> bool;
    
    /// Send 0-RTT data
    ///
    /// Send early data before handshake completes.
    fn send_0rtt_data(
        &mut self,
        handle: ConnectionHandle,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<()>;
}

/// Connection Context Interface
///
/// Provides access to all connection subsystems.
/// This is the primary interface for interacting with an established connection.
pub trait ConnectionContext {
    /// Get connection state
    fn state(&self) -> ConnectionState;
    
    /// Get connection statistics
    fn stats(&self) -> ConnectionStats;
    
    /// Get peer transport parameters
    fn peer_transport_parameters(&self) -> &TransportParameters;
    
    /// Get local transport parameters
    fn local_transport_parameters(&self) -> &TransportParameters;
    
    /// Access stream operations
    fn streams(&mut self) -> &mut dyn StreamOperations;
    
    /// Access datagram operations (if supported)
    fn datagrams(&mut self) -> Option<&mut dyn DatagramOperations>;
    
    /// Close the connection
    fn close(&mut self, error_code: VarInt, reason: &[u8]) -> Result<()>;
}

/// Server Configuration
///
/// Configuration for a QUIC server endpoint.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Transport parameters to advertise
    pub transport_params: TransportParameters,
    
    /// Supported ALPN protocols
    pub alpn_protocols: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    
    /// TLS certificate chain (DER-encoded)
    pub certificate_chain: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    
    /// TLS private key (DER-encoded)
    pub private_key: alloc::vec::Vec<u8>,
    
    /// Crypto backend
    pub crypto_backend: alloc::boxed::Box<dyn CryptoBackend>,
    
    /// Enable address validation (Retry packets)
    pub enable_retry: bool,
    
    /// Connection ID length
    pub connection_id_length: usize,
    
    /// Maximum concurrent connections
    pub max_concurrent_connections: usize,
}

/// Client Configuration
///
/// Configuration for a QUIC client endpoint.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Transport parameters to advertise
    pub transport_params: TransportParameters,
    
    /// Supported ALPN protocols
    pub alpn_protocols: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    
    /// Crypto backend
    pub crypto_backend: alloc::boxed::Box<dyn CryptoBackend>,
    
    /// Enable 0-RTT
    pub enable_0rtt: bool,
    
    /// Connection ID length
    pub connection_id_length: usize,
    
    /// Session ticket cache (for resumption)
    pub session_cache: Option<alloc::boxed::Box<dyn SessionCache>>,
}

/// Session Cache Trait
///
/// Stores TLS session tickets for resumption and 0-RTT.
pub trait SessionCache: Send + Sync {
    /// Store a session ticket
    fn put(&mut self, server_name: &str, ticket: Bytes) -> Result<()>;
    
    /// Retrieve a session ticket
    fn get(&self, server_name: &str) -> Option<Bytes>;
    
    /// Clear all cached tickets
    fn clear(&mut self);
}

/// Endpoint Builder
///
/// Fluent interface for creating QUIC endpoints.
pub struct EndpointBuilder {
    side: Side,
    server_config: Option<ServerConfig>,
    client_config: Option<ClientConfig>,
}

impl EndpointBuilder {
    /// Create a new endpoint builder
    pub fn new() -> Self {
        Self {
            side: Side::Client,
            server_config: None,
            client_config: None,
        }
    }
    
    /// Configure as server
    pub fn server(mut self, config: ServerConfig) -> Self {
        self.side = Side::Server;
        self.server_config = Some(config);
        self
    }
    
    /// Configure as client
    pub fn client(mut self, config: ClientConfig) -> Self {
        self.side = Side::Client;
        self.client_config = Some(config);
        self
    }
    
    /// Build the endpoint
    pub fn build(self) -> Result<alloc::boxed::Box<dyn QuicEndpoint>> {
        // Implementation would create the endpoint instance
        unimplemented!("Endpoint implementation goes here")
    }
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete QUIC Stack Interface
///
/// This trait represents the complete integration of all QUIC components.
/// It demonstrates how all the individual traits work together.
pub trait QuicStack {
    // Packet Layer
    type PacketParser: PacketParser;
    type PacketSerializer: PacketSerializer;
    
    // Frame Layer
    type FrameParser: FrameParser;
    type FrameSerializer: FrameSerializer;
    
    // Crypto Layer
    type CryptoBackend: CryptoBackend;
    type AeadProvider: AeadProvider;
    type HeaderProtection: HeaderProtectionProvider;
    
    // Stream Layer
    type StreamController: StreamController;
    type StreamMap: StreamMap;
    
    // Flow Control
    type FlowController: FlowController;
    type FlowControlManager: FlowControlManager;
    
    // Recovery Layer
    type CongestionController: CongestionController;
    type LossDetector: LossDetector;
    type RttEstimator: RttEstimator;
    
    // Connection Layer
    type Connection: QuicConnection;
    
    /// Create a new stack instance with default implementations
    fn new_default() -> Self;
    
    /// Get packet parser
    fn packet_parser(&self) -> &Self::PacketParser;
    
    /// Get frame parser
    fn frame_parser(&self) -> &Self::FrameParser;
    
    /// Get crypto backend
    fn crypto_backend(&self) -> &Self::CryptoBackend;
}

/// Event Loop Integration
///
/// Helper trait for integrating QUIC with async/event-driven frameworks.
pub trait EventLoopIntegration {
    /// Register interest in read events
    fn register_read(&mut self) -> Result<()>;
    
    /// Register interest in write events
    fn register_write(&mut self) -> Result<()>;
    
    /// Register a timer
    fn register_timer(&mut self, deadline: Instant) -> Result<TimerHandle>;
    
    /// Cancel a timer
    fn cancel_timer(&mut self, handle: TimerHandle) -> Result<()>;
}

/// Timer Handle
///
/// Opaque identifier for a registered timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerHandle(pub u64);
