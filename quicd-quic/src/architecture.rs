//! # Architecture Documentation
//!
//! This module provides comprehensive documentation of the quicd-quic architecture,
//! trait hierarchies, and integration patterns.

// ============================================================================
// TRAIT HIERARCHY OVERVIEW
// ============================================================================

//! ## Trait Hierarchy and Integration
//!
//! The quicd-quic library is organized into layers with clear trait interfaces:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Application Layer                         │
//! │  (Uses QuicConnection, StreamOperations, DatagramOperations) │
//! └─────────────────────────────────────────────────────────────┘
//!                             │
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  Connection State Machine                    │
//! │              (QuicConnection trait)                          │
//! │                                                              │
//! │  • process_datagram(&[u8]) -> Result<Vec<Event>>            │
//! │  • poll_send(&mut BytesMut) -> Option<usize>                │
//! │  • next_timeout() -> Option<Instant>                        │
//! └─────────────────────────────────────────────────────────────┘
//!          │              │              │              │
//!          ▼              ▼              ▼              ▼
//! ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
//! │   Packet     │ │   Stream     │ │     Flow     │ │   Recovery   │
//! │   Parser     │ │  Controller  │ │  Controller  │ │   (Loss +    │
//! │              │ │              │ │              │ │  Congestion) │
//! └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
//!          │              │              │              │
//!          ▼              ▼              ▼              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Crypto Backend                             │
//! │  (AEAD, HeaderProtection, TLS Session)                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```

// ============================================================================
// ZERO-COPY DESIGN PATTERNS
// ============================================================================

//! ## Zero-Copy Design Patterns
//!
//! ### 1. Lifetime-Bound Parsing
//!
//! All parsing traits use lifetime parameters to borrow from input buffers:
//!
//! ```rust,ignore
//! pub trait PacketParser {
//!     fn parse_packet<'a>(&self, buf: &'a [u8]) 
//!         -> Result<(ParsedPacket<'a>, usize)>;
//! }
//!
//! pub struct ParsedPacket<'a> {
//!     pub header: PacketHeader,
//!     pub payload: &'a [u8],  // Zero-copy reference
//! }
//!
//! pub struct StreamFrame<'a> {
//!     pub stream_id: StreamId,
//!     pub offset: StreamOffset,
//!     pub data: &'a [u8],     // Zero-copy reference
//! }
//! ```
//!
//! ### 2. Buffer Injection Pattern
//!
//! Output methods accept caller-provided buffers:
//!
//! ```rust,ignore
//! pub trait PacketSerializer {
//!     fn serialize_packet(
//!         &mut self,
//!         buf: &mut BytesMut,  // Caller provides buffer
//!         header: &PacketHeader,
//!         frames: &[Frame],
//!     ) -> Result<usize>;      // Returns bytes written
//! }
//! ```
//!
//! ### 3. Reference-Counted Data Transfer
//!
//! Stream data uses `bytes::Bytes` for zero-copy transfer:
//!
//! ```rust,ignore
//! pub trait StreamSendBuffer {
//!     fn write(&mut self, data: Bytes) -> Result<StreamOffset>;
//!     fn get_data_to_send(&mut self) -> Option<(StreamOffset, Bytes)>;
//! }
//! ```

// ============================================================================
// PLUGGABLE SUBSYSTEMS
// ============================================================================

//! ## Pluggable Subsystems via Traits
//!
//! ### Cryptography Backend
//!
//! The `CryptoBackend` trait allows swapping TLS implementations:
//!
//! ```rust,ignore
//! pub trait CryptoBackend: Send + Sync {
//!     fn create_aead(&self, algorithm: AeadAlgorithm, key: &[u8], iv: &[u8])
//!         -> Result<Box<dyn AeadProvider>>;
//!     
//!     fn create_header_protection(&self, algorithm: AeadAlgorithm, key: &[u8])
//!         -> Result<Box<dyn HeaderProtectionProvider>>;
//!     
//!     fn create_tls_session(&self, side: Side, ...) 
//!         -> Result<Box<dyn TlsSession>>;
//! }
//!
//! // Implementations:
//! // - RustlsCryptoBackend (using rustls)
//! // - BoringSSLCryptoBackend (using BoringSSL via FFI)
//! // - MockCryptoBackend (for testing)
//! ```
//!
//! ### Congestion Control
//!
//! The `CongestionController` trait allows pluggable algorithms:
//!
//! ```rust,ignore
//! pub trait CongestionController: Send + Sync {
//!     fn on_packet_sent(&mut self, pn: PacketNumber, bytes: usize, ...);
//!     fn on_packet_acked(&mut self, pn: PacketNumber, bytes: usize, ...);
//!     fn on_packets_lost(&mut self, lost: &[(PacketNumber, usize)], ...);
//!     fn congestion_window(&self) -> u64;
//! }
//!
//! // Implementations:
//! // - NewRenoCongestionController (RFC 9002 Appendix B)
//! // - CubicCongestionController
//! // - BbrCongestionController
//! ```

// ============================================================================
// EVENT-DRIVEN ARCHITECTURE
// ============================================================================

//! ## Event-Driven Architecture
//!
//! The connection state machine is purely event-driven:
//!
//! ```rust,ignore
//! // Input Events:
//! connection.process_datagram(datagram, recv_time)?;
//! connection.on_timeout(now)?;
//!
//! // Output Events:
//! while let Some(event) = connection.poll_event() {
//!     match event {
//!         ConnectionEvent::StreamData { stream_id, data, fin } => { ... }
//!         ConnectionEvent::StreamOpened { stream_id } => { ... }
//!         ConnectionEvent::HandshakeComplete { alpn, ... } => { ... }
//!         ConnectionEvent::ConnectionClosing { ... } => { ... }
//!     }
//! }
//!
//! // Output Datagrams:
//! while let Some(bytes_written) = connection.poll_send(&mut buf, now) {
//!     udp_socket.send(&buf[..bytes_written])?;
//!     buf.clear();
//! }
//! ```

// ============================================================================
// RFC COMPLIANCE MAPPING
// ============================================================================

//! ## RFC Compliance Mapping
//!
//! Each module maps to specific RFC sections:
//!
//! ### RFC 8999 - Version-Independent Properties
//! - `version.rs`: Version negotiation and invariants
//! - `packet/types.rs`: Packet header format (version-independent)
//!
//! ### RFC 9000 - QUIC Transport
//! - `types.rs`: Core types (Section 16-17)
//! - `packet/`: Packet formats (Section 17)
//! - `frames/`: All frame types (Section 19)
//! - `stream/`: Stream states (Section 2-3)
//! - `flow_control/`: Flow control (Section 4)
//! - `connection/`: Connection lifecycle (Section 5, 10)
//! - `transport/`: Transport parameters (Section 18)
//! - `error.rs`: Error codes (Section 20)
//!
//! ### RFC 9001 - TLS for QUIC
//! - `crypto/backend.rs`: Crypto abstraction (Section 4-5)
//! - `packet/protection.rs`: Header protection (Section 5.4)
//!
//! ### RFC 9002 - Loss Detection and Congestion Control
//! - `recovery/loss.rs`: Loss detection (Section 6)
//! - `recovery/congestion.rs`: Congestion control (Section 7)
//! - `recovery/rtt.rs`: RTT estimation (Section 5)

// ============================================================================
// INTEGRATION EXAMPLES
// ============================================================================

//! ## Integration Examples
//!
//! ### Minimal Client
//!
//! ```rust,ignore
//! use quicd_quic::*;
//!
//! // Create crypto backend
//! let crypto = RustlsCryptoBackend::new()?;
//!
//! // Configure connection
//! let config = ConnectionConfig {
//!     local_transport_params: TransportParameters::default(),
//!     alpn_protocols: vec![b"h3".to_vec()],
//!     server_name: Some(\"example.com\".to_string()),
//!     side: Side::Client,
//!     ..Default::default()
//! };
//!
//! // Create connection
//! let mut connection = ConnectionBuilder::new()
//!     .side(Side::Client)
//!     .transport_params(config.local_transport_params)
//!     .alpn_protocol(b\"h3\")
//!     .server_name(\"example.com\")
//!     .crypto_backend(Box::new(crypto))
//!     .build()?;
//!
//! // Event loop
//! loop {
//!     // Process received datagrams
//!     if let Some(dgram) = udp_socket.recv()? {
//!         let events = connection.process_datagram(&dgram, Instant::now())?;
//!         for event in events {
//!             handle_event(event);
//!         }
//!     }
//!
//!     // Send outgoing datagrams
//!     let mut buf = BytesMut::with_capacity(1500);
//!     while let Some(len) = connection.poll_send(&mut buf, Instant::now()) {
//!         udp_socket.send(&buf[..len])?;
//!         buf.clear();
//!     }
//!
//!     // Handle timeouts
//!     if let Some(deadline) = connection.next_timeout() {
//!         if Instant::now() >= deadline {
//!             connection.on_timeout(Instant::now())?;
//!         }
//!     }
//! }
//! ```
//!
//! ### Server with Custom Congestion Control
//!
//! ```rust,ignore
//! use quicd_quic::*;
//!
//! // Custom congestion controller
//! struct CustomCongestionController { ... }
//!
//! impl CongestionController for CustomCongestionController {
//!     fn on_packet_sent(&mut self, ...) { ... }
//!     fn on_packet_acked(&mut self, ...) { ... }
//!     fn on_packets_lost(&mut self, ...) { ... }
//!     fn congestion_window(&self) -> u64 { ... }
//! }
//!
//! // Create server
//! let server = EndpointBuilder::new()
//!     .server(ServerConfig {
//!         transport_params: TransportParameters::default(),
//!         alpn_protocols: vec![b\"h3\".to_vec()],
//!         certificate_chain: load_certs(),
//!         private_key: load_key(),
//!         crypto_backend: Box::new(RustlsCryptoBackend::new()?),
//!         ..Default::default()
//!     })
//!     .build()?;
//!
//! // Accept connections with custom CC
//! loop {
//!     let (handle, events) = server.process_datagram(&dgram, Instant::now())?;
//!     
//!     // Inject custom congestion controller
//!     server.set_congestion_controller(
//!         handle, 
//!         Box::new(CustomCongestionController::new())
//!     )?;
//! }
//! ```

// ============================================================================
// TESTING STRATEGIES
// ============================================================================

//! ## Testing Strategies
//!
//! ### Unit Testing with Mock Backends
//!
//! ```rust,ignore
//! struct MockCryptoBackend;
//!
//! impl CryptoBackend for MockCryptoBackend {
//!     fn create_aead(&self, ...) -> Result<Box<dyn AeadProvider>> {
//!         Ok(Box::new(MockAeadProvider))
//!     }
//!     // ... other methods
//! }
//!
//! #[test]
//! fn test_connection_handshake() {
//!     let crypto = Box::new(MockCryptoBackend);
//!     let conn = ConnectionBuilder::new()
//!         .crypto_backend(crypto)
//!         .build()
//!         .unwrap();
//!     
//!     // Test with predictable crypto
//! }
//! ```
//!
//! ### Property-Based Testing
//!
//! ```rust,ignore
//! use proptest::prelude::*;
//!
//! proptest! {
//!     #[test]
//!     fn parse_arbitrary_packets(data in prop::collection::vec(any::<u8>(), 0..1500)) {
//!         let parser = DefaultPacketParser::new(1500);
//!         
//!         // Should never panic on invalid input
//!         let _ = parser.parse_packet(&data);
//!     }
//! }
//! ```

// ============================================================================
// PERFORMANCE CONSIDERATIONS
// ============================================================================

//! ## Performance Considerations
//!
//! ### 1. Zero Allocations in Hot Path
//!
//! - Packet parsing: borrows from input buffer (no alloc)
//! - Frame iteration: stack-allocated iterator (no alloc)
//! - Header protection removal: in-place mutation (no alloc)
//!
//! ### 2. Buffer Pool Integration
//!
//! Integrate with external buffer pools:
//!
//! ```rust,ignore
//! // Caller manages buffer pool
//! let mut buf = buffer_pool.acquire();
//! if let Some(len) = connection.poll_send(&mut buf, now) {
//!     udp_socket.send(&buf[..len])?;
//! }
//! buffer_pool.release(buf);
//! ```
//!
//! ### 3. LIFO Buffer Reuse
//!
//! Stack-based buffer allocation for cache locality:
//!
//! ```rust,ignore
//! // Most recently used buffer is reused first
//! let buf1 = pool.alloc(); // Cold cache
//! pool.free(buf1);
//! let buf2 = pool.alloc(); // Reuses buf1 (hot cache)
//! ```

// ============================================================================
// NO_STD COMPATIBILITY
// ============================================================================

//! ## no_std Compatibility
//!
//! The core library is `#![no_std]` compatible:
//!
//! ```rust,ignore
//! #![no_std]
//! extern crate alloc;
//!
//! use alloc::boxed::Box;
//! use alloc::vec::Vec;
//! use quicd_quic::*;
//!
//! // Use with custom allocator
//! ```
//!
//! Time abstraction for no_std:
//!
//! ```rust,ignore
//! use quicd_quic::Instant;
//!
//! // On bare metal, provide monotonic nanoseconds
//! let now = Instant::from_nanos(hardware_timer_nanos());
//! ```
