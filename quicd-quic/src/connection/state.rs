//! # Connection State Machine (RFC 9000 Section 5, 10)
//!
//! Pure state machine - accepts datagrams and time, produces datagrams and events.

#![forbid(unsafe_code)]

extern crate alloc;

use crate::crypto::{AeadProvider, CryptoBackend, CryptoLevel, HeaderProtectionProvider, KeySchedule, TlsSession};
use crate::error::{Error, Result};
use crate::flow_control::ConnectionFlowControl;
use crate::frames::Frame;
use crate::packet::{Header, PacketParserTrait};
use crate::recovery::{CongestionController, LossDetector};
use crate::stream::StreamManager;
use crate::transport::TransportParameters;
use crate::types::{ConnectionId, Instant, PacketNumber, Side, StreamId};
use crate::version::VERSION_1;
use bytes::{BufMut, Bytes, BytesMut};
use core::time::Duration;

// ============================================================================
// Connection State Machine
// ============================================================================

/// Connection State (RFC 9000 Section 5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Handshake in progress
    Handshaking,

    /// Handshake complete, connection active
    Active,

    /// Draining - waiting after sending CONNECTION_CLOSE
    Draining,

    /// Closing - sending CONNECTION_CLOSE
    Closing,

    /// Connection closed
    Closed,
}

/// Encryption keys for a specific crypto level
struct EncryptionKeys {
    /// AEAD key for encryption/decryption
    key: Vec<u8>,
    /// IV for encryption/decryption
    iv: Vec<u8>,
    /// Header protection key
    hp_key: Vec<u8>,
    /// AEAD provider (cipher suite specific)
    aead: Option<Box<dyn AeadProvider>>,
    /// Header protection provider
    hp: Option<Box<dyn HeaderProtectionProvider>>,
    /// Packet number for this level
    packet_number: PacketNumber,
}

impl EncryptionKeys {
    fn new(key: Vec<u8>, iv: Vec<u8>, hp_key: Vec<u8>, aead: Box<dyn AeadProvider>, hp: Box<dyn HeaderProtectionProvider>) -> Self {
        Self {
            key,
            iv,
            hp_key,
            aead: Some(aead),
            hp: Some(hp),
            packet_number: 0,
        }
    }
    
    fn empty() -> Self {
        Self {
            key: Vec::new(),
            iv: Vec::new(),
            hp_key: Vec::new(),
            aead: None,
            hp: None,
            packet_number: 0,
        }
    }
    
    /// Install keys from a TLS secret
    /// Derives packet key, IV, and HP key, then creates AEAD and HP providers
    fn install_from_secret(
        &mut self,
        secret: &[u8],
        key_schedule: &dyn KeySchedule,
        crypto_backend: &dyn CryptoBackend,
        cipher_suite: u16, // TLS cipher suite (e.g., 0x1301 for AES_128_GCM_SHA256)
    ) -> Result<()> {
        // Derive keys using HKDF (RFC 9001 Section 5.1)
        let key_len = 16; // AES-128-GCM uses 16-byte keys (adjust for other ciphers)
        let iv_len = 12;  // Standard nonce length for QUIC
        let hp_key_len = 16; // Header protection key length
        
        let packet_key = key_schedule.derive_packet_key(secret, key_len)?;
        let packet_iv = key_schedule.derive_packet_iv(secret, iv_len)?;
        let hp_key = key_schedule.derive_header_protection_key(secret, hp_key_len)?;
        
        // Create AEAD and HP providers
        let aead = crypto_backend.create_aead(cipher_suite)?;
        let hp = crypto_backend.create_header_protection(cipher_suite)?;
        
        // Install keys
        self.key = packet_key;
        self.iv = packet_iv;
        self.hp_key = hp_key;
        self.aead = Some(aead);
        self.hp = Some(hp);
        
        Ok(())
    }
}

/// Connection Configuration
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Local transport parameters
    pub local_params: TransportParameters,
    
    /// Certificate data (for server) - read once at startup to avoid disk I/O contention
    pub cert_data: Option<Bytes>,
    
    /// Private key data (for server) - read once at startup to avoid disk I/O contention
    pub key_data: Option<Bytes>,

    /// ALPN protocols supported/offered (RFC 9001 Section 8.1)
    /// Server: list of protocols willing to accept
    /// Client: list of protocols to offer (in order of preference)
    pub alpn_protocols: Vec<Vec<u8>>,

    /// Idle timeout
    pub idle_timeout: Duration,

    /// Maximum packet size to send
    pub max_packet_size: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            local_params: TransportParameters::default(),
            cert_data: None,
            key_data: None,
            alpn_protocols: Vec::new(),
            idle_timeout: Duration::from_secs(30),
            max_packet_size: 1200,
        }
    }
}

/// Connection Input (Datagram)
///
/// **Zero-Copy**: Bytes references the received UDP datagram.
#[derive(Debug, Clone)]
pub struct DatagramInput {
    /// Datagram payload (entire UDP payload)
    pub data: Bytes,

    /// Time received
    pub recv_time: Instant,
}

/// Connection Output (Datagram)
///
/// **Buffer Injection**: Connection writes into provided BytesMut.
#[derive(Debug)]
pub struct DatagramOutput {
    /// Datagram payload to send
    pub data: BytesMut,

    /// When to send (for pacing, or immediate if None)
    pub send_time: Option<Instant>,
}

/// Connection Event (Application Notifications)
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Handshake completed
    HandshakeComplete,

    /// Stream data available
    StreamData {
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },

    /// Stream opened by peer
    StreamOpened { stream_id: StreamId },

    /// Stream finished (FIN received)
    StreamFinished { stream_id: StreamId },

    /// Stream reset by peer
    StreamReset {
        stream_id: StreamId,
        error_code: u64,
    },

    /// Datagram received (DATAGRAM frame)
    DatagramReceived { data: Bytes },

    /// Connection closing
    ConnectionClosing {
        error_code: u64,
        reason: Bytes,
    },

    /// Connection closed
    ConnectionClosed,
}

/// QUIC Connection (Top-Level State Machine)
///
/// **Pure State Machine Design**:
/// - No I/O - accepts bytes via `process_datagram()`
/// - No timers - accepts time via `process_timeout()`
/// - Returns bytes via `poll_send()`
/// - Returns events via `poll_event()`
///
/// **Zero-Copy + Buffer Injection**:
/// - Input: `Bytes` (zero-copy reference to received datagram)
/// - Output: Writes into caller-provided `BytesMut`
///
/// **Deterministic**: Same inputs produce same outputs (no randomness except crypto).
pub trait Connection: Send {
    /// Process incoming datagram
    ///
    /// Parses packets, processes frames, updates state.
    ///
    /// **Zero-Copy**: Input borrows from datagram buffer.
    fn process_datagram(&mut self, datagram: DatagramInput) -> Result<()>;

    /// Process timeout (called at or after deadline from `next_timeout()`)
    ///
    /// Handles PTO, idle timeout, draining timeout, etc.
    fn process_timeout(&mut self, now: Instant) -> Result<()>;

    /// Poll for outgoing datagram
    ///
    /// **Buffer Injection**: Writes into provided `buf`.
    ///
    /// Returns None if nothing to send.
    fn poll_send(&mut self, buf: &mut BytesMut, now: Instant) -> Option<DatagramOutput>;

    /// Poll for application events
    ///
    /// Returns None if no events pending.
    fn poll_event(&mut self) -> Option<ConnectionEvent>;

    /// Get next timeout deadline
    ///
    /// Returns None if no timeout pending (connection idle).
    fn next_timeout(&self) -> Option<Instant>;

    /// Get connection state
    fn state(&self) -> ConnectionState;

    /// Send datagram (DATAGRAM frame)
    fn send_datagram(&mut self, data: Bytes) -> Result<()>;

    /// Open new stream
    fn open_stream(
        &mut self,
        direction: crate::types::StreamDirection,
    ) -> Result<StreamId>;

    /// Write data to stream
    fn write_stream(&mut self, stream_id: StreamId, data: Bytes, fin: bool) -> Result<()>;

    /// Read data from stream
    fn read_stream(&mut self, stream_id: StreamId) -> Result<Option<Bytes>>;

    /// Reset stream (send RESET_STREAM)
    fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()>;

    /// Close connection gracefully
    fn close(&mut self, error_code: u64, reason: &[u8]);

    /// Get connection statistics
    fn stats(&self) -> ConnectionStats;

    /// Get source connection ID
    fn source_cid(&self) -> &ConnectionId;

    /// Get destination connection ID
    fn destination_cid(&self) -> &ConnectionId;
}

/// Connection Statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Packets sent
    pub packets_sent: u64,

    /// Packets received
    pub packets_received: u64,

    /// Bytes sent
    pub bytes_sent: u64,

    /// Bytes received
    pub bytes_received: u64,

    /// Packets lost
    pub packets_lost: u64,

    /// Smoothed RTT
    pub smoothed_rtt: Duration,

    /// Congestion window
    pub congestion_window: usize,

    /// Bytes in flight
    pub bytes_in_flight: usize,
}

/// Connection Implementation with Full Integration
///
/// Wires together all Phase 1-6 components for full packet processing.
pub struct QuicConnection {
    /// Connection side (Client or Server)
    side: Side,

    /// Connection state
    state: ConnectionState,

    /// Source Connection ID
    scid: ConnectionId,

    /// Destination Connection ID
    dcid: ConnectionId,

    /// Configuration
    config: ConnectionConfig,

    /// Statistics
    stats: ConnectionStats,

    /// Packet parser
    packet_parser: Box<dyn PacketParserTrait>,

    /// Crypto backend
    crypto_backend: Box<dyn CryptoBackend>,

    /// TLS session (handshake state)
    tls_session: Option<Box<dyn TlsSession>>,

    /// Stream manager
    streams: StreamManager,

    /// Connection-level flow control
    flow_control: ConnectionFlowControl,

    /// Loss detector
    loss_detector: Box<dyn LossDetector>,

    /// Congestion controller  
    congestion_controller: Box<dyn CongestionController>,

    /// Packet number spaces (Initial, Handshake, Application)
    pn_spaces: crate::packet::space::PacketNumberSpaceManager,

    /// Pending events for application
    pending_events: alloc::vec::Vec<ConnectionEvent>,
    
    /// Pending stream writes (stream_id, data, fin)
    pending_stream_writes: alloc::vec::Vec<(StreamId, Bytes, bool)>,
    
    /// Pending stream resets (stream_id, error_code, final_size)
    pending_stream_resets: alloc::vec::Vec<(StreamId, u64, u64)>,
    
    /// Connection close pending (error_code, reason)
    pending_close: Option<(u64, alloc::vec::Vec<u8>)>,

    /// Handshake complete flag
    handshake_complete: bool,

    /// Last activity time (for idle timeout)
    last_activity: Option<Instant>,

    /// Draining/closing timeout
    closing_timeout: Option<Instant>,
    
    /// Initial encryption keys (read: decrypt client Initial, write: encrypt server Initial)
    initial_read_keys: EncryptionKeys,
    initial_write_keys: EncryptionKeys,
    
    /// Handshake encryption keys (read: decrypt client Handshake, write: encrypt server Handshake)
    handshake_read_keys: EncryptionKeys,
    handshake_write_keys: EncryptionKeys,
    
    /// 1-RTT encryption keys (read: decrypt client 1-RTT, write: encrypt server 1-RTT)
    one_rtt_read_keys: EncryptionKeys,
    one_rtt_write_keys: EncryptionKeys,
    
    /// Pending CRYPTO data to send (level, data)
    pending_crypto: alloc::vec::Vec<(CryptoLevel, Bytes)>,
}

impl QuicConnection {
    /// Create new connection with all components
    pub fn new(
        side: Side,
        scid: ConnectionId,
        dcid: ConnectionId,
        config: ConnectionConfig,
    ) -> Self {
        // Create packet parser
        let packet_parser: Box<dyn PacketParserTrait> = Box::new(
            crate::packet::parser::DefaultPacketParser::new(1500)
        );
        
        // Create crypto backend using BoringSSL
        let crypto_backend: Box<dyn CryptoBackend> = Box::new(crate::crypto::boring::BoringCryptoBackend);
        
        // Create stream manager
        let streams = StreamManager::new(side);
        
        // Create flow control (using transport params from config)
        let initial_max_data = config.local_params.initial_max_data;
        let flow_control = ConnectionFlowControl::new(
            initial_max_data,
            initial_max_data,
            initial_max_data,
        );
        
        // Create loss detector (stub for now - needs real implementation)
        let loss_detector: Box<dyn LossDetector> = Box::new(StubLossDetector);
        
        // Create congestion controller
        let congestion_controller: Box<dyn CongestionController> = Box::new(
            crate::recovery::congestion::NewRenoCongestionController::new(
                14720, // 10 * 1472 (initial window = 10 packets)
                2944,  // 2 * 1472 (min window = 2 packets)
                1_000_000, // max window = 1MB
                1472,  // max datagram size (Ethernet MTU - overhead)
            )
        );
        
        // Create packet number space manager
        let pn_spaces = crate::packet::space::PacketNumberSpaceManager::new();
        
        // Derive Initial encryption keys (RFC 9001 Section 5.2)
        // Initial keys are derived from the client's Destination Connection ID
        // Both client_initial_secret and server_initial_secret are derived from
        // the same initial_secret, which comes from the client's DCID
        // 
        // RFC 9001 Section 5.2:
        //   initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
        //   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", ...)
        //   server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", ...)
        //
        // For server: read using client_initial_secret, write using server_initial_secret
        // For client: read using server_initial_secret, write using client_initial_secret
        let key_schedule = crypto_backend.create_key_schedule();
        
        // Derive initial_secret from client's DCID (RFC 9001 Section 5.2)
        // Note: For server, dcid is the client's DCID from the received Initial packet
        // For client, dcid is the server's DCID from the received Initial packet
        eprintln!("DEBUG: Key derivation: side={:?}, dcid={:?}, scid={:?}", side, dcid, scid);
        let initial_secret = match key_schedule.derive_initial_secret(&dcid, VERSION_1) {
            Ok(secret) => secret,
            Err(e) => {
                eprintln!("Failed to derive initial secret: {:?}", e);
                return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                };
            }
        };
        
        // Derive client_initial_secret and server_initial_secret from the same initial_secret
        // (RFC 9001 Section 5.2)
        let client_initial_secret = match key_schedule.derive_client_initial_secret(&initial_secret) {
            Ok(secret) => secret,
            Err(e) => {
                eprintln!("Failed to derive client initial secret for keys: {:?}", e);
                return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                };
            }
        };
        
        let server_initial_secret = match key_schedule.derive_server_initial_secret(&initial_secret) {
            Ok(secret) => secret,
            Err(e) => {
                eprintln!("Failed to derive server initial secret for keys: {:?}", e);
                return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                };
            }
        };
        
        // Use AES-128-GCM for Initial packets (RFC 9001 Section 5.2)
        let cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
        let aead = match crypto_backend.create_aead(cipher_suite) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Failed to create AEAD: {:?}", e);
                return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                };
            }
        };
        
        let hp = match crypto_backend.create_header_protection(cipher_suite) {
            Ok(hp) => hp,
            Err(e) => {
                eprintln!("Failed to create header protection: {:?}", e);
                return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                };
            }
        };
        
        // Derive packet keys and IVs
        // Use AES-128-GCM for Initial packets (RFC 9001 Section 5.2)
        let cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
        let aead = match crypto_backend.create_aead(cipher_suite) {
            Ok(a) => a,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        
        let hp = match crypto_backend.create_header_protection(cipher_suite) {
            Ok(h) => h,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        
        // Derive packet keys and IVs
        let key_len = aead.key_len();
        let iv_len = aead.iv_len();
        let hp_key_len = hp.key_len();
        
        let client_key = match key_schedule.derive_packet_key(&client_initial_secret, key_len) {
            Ok(k) => k,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        
        let client_iv = match key_schedule.derive_packet_iv(&client_initial_secret, iv_len) {
            Ok(iv) => iv,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        let client_hp_key = match key_schedule.derive_header_protection_key(&client_initial_secret, hp_key_len) {
            Ok(k) => k,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        
        let server_key = match key_schedule.derive_packet_key(&server_initial_secret, key_len) {
            Ok(k) => k,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        let server_iv = match key_schedule.derive_packet_iv(&server_initial_secret, iv_len) {
            Ok(iv) => iv,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        let server_hp_key = match key_schedule.derive_header_protection_key(&server_initial_secret, hp_key_len) {
            Ok(k) => k,
            Err(_) => return Self {
                side,
                state: ConnectionState::Closed,
                scid,
                dcid,
                config,
                stats: ConnectionStats::default(),
                packet_parser,
                crypto_backend,
                tls_session: None,
                streams,
                flow_control,
                loss_detector,
                congestion_controller,
                pn_spaces,
                pending_events: alloc::vec::Vec::new(),
                pending_stream_writes: alloc::vec::Vec::new(),
                pending_stream_resets: alloc::vec::Vec::new(),
                pending_close: None,
                handshake_complete: false,
                last_activity: None,
                closing_timeout: None,
                initial_read_keys: EncryptionKeys::empty(),
                initial_write_keys: EncryptionKeys::empty(),
                handshake_read_keys: EncryptionKeys::empty(),
                handshake_write_keys: EncryptionKeys::empty(),
                one_rtt_read_keys: EncryptionKeys::empty(),
                one_rtt_write_keys: EncryptionKeys::empty(),
                pending_crypto: alloc::vec::Vec::new(),
            },
        };
        
        // For server: read client Initial (use client keys), write server Initial (use server keys)
        // For client: read server Initial (use server keys), write client Initial (use client keys)
        let (initial_read_keys, initial_write_keys) = if side == Side::Server {
            let read_aead = match crypto_backend.create_aead(cipher_suite) {
                Ok(a) => a,
                Err(_) => return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                },
            };
            let read_hp = match crypto_backend.create_header_protection(cipher_suite) {
                Ok(h) => h,
                Err(_) => return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                },
            };
            (
                EncryptionKeys::new(client_key.clone(), client_iv.clone(), client_hp_key.clone(), read_aead, read_hp),
                EncryptionKeys::new(server_key, server_iv, server_hp_key, aead, hp),
            )
        } else {
            let write_aead = match crypto_backend.create_aead(cipher_suite) {
                Ok(a) => a,
                Err(_) => return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                },
            };
            let write_hp = match crypto_backend.create_header_protection(cipher_suite) {
                Ok(h) => h,
                Err(_) => return Self {
                    side,
                    state: ConnectionState::Closed,
                    scid,
                    dcid,
                    config,
                    stats: ConnectionStats::default(),
                    packet_parser,
                    crypto_backend,
                    tls_session: None,
                    streams,
                    flow_control,
                    loss_detector,
                    congestion_controller,
                    pn_spaces,
                    pending_events: alloc::vec::Vec::new(),
                    pending_stream_writes: alloc::vec::Vec::new(),
                    pending_stream_resets: alloc::vec::Vec::new(),
                    pending_close: None,
                    handshake_complete: false,
                    last_activity: None,
                    closing_timeout: None,
                    initial_read_keys: EncryptionKeys::empty(),
                    initial_write_keys: EncryptionKeys::empty(),
                    handshake_read_keys: EncryptionKeys::empty(),
                    handshake_write_keys: EncryptionKeys::empty(),
                    one_rtt_read_keys: EncryptionKeys::empty(),
                    one_rtt_write_keys: EncryptionKeys::empty(),
                    pending_crypto: alloc::vec::Vec::new(),
                },
            };
            (
                EncryptionKeys::new(server_key.clone(), server_iv.clone(), server_hp_key.clone(), aead, hp),
                EncryptionKeys::new(client_key, client_iv, client_hp_key, write_aead, write_hp),
            )
        };
        
        // Initialize TLS session for server connections
        // Load certificates from config.cert_data and config.key_data
        let tls_session = if side == Side::Server {
            let alpn_protocols: Vec<&[u8]> = config.alpn_protocols.iter()
                .map(|p| p.as_slice())
                .collect();
            let cert_data = config.cert_data.as_ref().map(|b| b.as_ref());
            let key_data = config.key_data.as_ref().map(|b| b.as_ref());
            match crypto_backend.create_tls_session(side, None, &alpn_protocols, cert_data, key_data) {
                Ok(session) => Some(session),
                Err(e) => {
                    eprintln!("Warning: Failed to create TLS session: {:?}", e);
                    None
                }
            }
        } else {
            None // Client TLS session created on connect
        };
        
        Self {
            side,
            state: ConnectionState::Handshaking,
            scid,
            dcid,
            config,
            stats: ConnectionStats::default(),
            packet_parser,
            crypto_backend,
            tls_session,
            streams,
            flow_control,
            loss_detector,
            congestion_controller,
            pn_spaces,
            pending_events: alloc::vec::Vec::new(),
            pending_stream_writes: alloc::vec::Vec::new(),
            pending_stream_resets: alloc::vec::Vec::new(),
            pending_close: None,
            handshake_complete: false,
            last_activity: None,
            closing_timeout: None,
            initial_read_keys,
            initial_write_keys,
            handshake_read_keys: EncryptionKeys::empty(),
            handshake_write_keys: EncryptionKeys::empty(),
            one_rtt_read_keys: EncryptionKeys::empty(),
            one_rtt_write_keys: EncryptionKeys::empty(),
            pending_crypto: alloc::vec::Vec::new(),
        }
    }
    
    /// Get negotiated ALPN protocol from TLS session
    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.tls_session
            .as_ref()
            .and_then(|tls| tls.alpn_protocol())
    }

    /// Process a single frame from decrypted packet
    fn process_frame(&mut self, frame: Frame, now: Instant) -> Result<()> {
        use crate::frames::Frame;
        
        match frame {
            Frame::Stream(stream_frame) => {
                // Update stream data, check flow control, enqueue event
                self.flow_control.recv.on_data_received(stream_frame.data.len() as u64)?;
                self.pending_events.push(ConnectionEvent::StreamData {
                    stream_id: stream_frame.stream_id,
                    data: Bytes::copy_from_slice(stream_frame.data),
                    fin: stream_frame.fin,
                });
                Ok(())
            }

            Frame::Crypto(crypto_frame) => {
                // Feed crypto data to TLS session
                if let Some(ref mut tls) = self.tls_session {
                    let level = CryptoLevel::Handshake; // TODO: determine from packet type
                    tls.process_input(crypto_frame.data, level)?;
                    while let Some(event) = tls.get_output() {
                        match event {
                            crate::crypto::TlsEvent::HandshakeComplete => {
                                self.handshake_complete = true;
                                self.state = ConnectionState::Active;
                                self.pending_events.push(ConnectionEvent::HandshakeComplete);
                            }
                            crate::crypto::TlsEvent::ReadSecret(level, secret) => {
                                // New read keys available - install them
                                let key_schedule = self.crypto_backend.create_key_schedule();
                                let cipher_suite = 0x1301; // TODO: Get from TLS session
                                let target_keys = match level {
                                    CryptoLevel::Initial => &mut self.initial_read_keys,
                                    CryptoLevel::Handshake => &mut self.handshake_read_keys,
                                    CryptoLevel::OneRTT => &mut self.one_rtt_read_keys,
                                    CryptoLevel::ZeroRTT => continue,
                                };
                                if let Err(e) = target_keys.install_from_secret(&secret, key_schedule.as_ref(), self.crypto_backend.as_ref(), cipher_suite) {
                                    eprintln!("Failed to install read keys for level {:?}: {:?}", level, e);
                                }
                            }
                            crate::crypto::TlsEvent::WriteSecret(level, secret) => {
                                // New write keys available - install them
                                let key_schedule = self.crypto_backend.create_key_schedule();
                                let cipher_suite = 0x1301; // TODO: Get from TLS session
                                let target_keys = match level {
                                    CryptoLevel::Initial => &mut self.initial_write_keys,
                                    CryptoLevel::Handshake => &mut self.handshake_write_keys,
                                    CryptoLevel::OneRTT => &mut self.one_rtt_write_keys,
                                    CryptoLevel::ZeroRTT => continue,
                                };
                                if let Err(e) = target_keys.install_from_secret(&secret, key_schedule.as_ref(), self.crypto_backend.as_ref(), cipher_suite) {
                                    eprintln!("Failed to install write keys for level {:?}: {:?}", level, e);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ok(())
            }

            Frame::Ack(ack_frame) => {
                // Process ACK: mark packets as acknowledged, detect losses
                let space = crate::types::PacketNumberSpace::ApplicationData;
                let result = self.loss_detector.on_ack_received(
                    space,
                    ack_frame.largest_acked,
                    Duration::from_micros(ack_frame.ack_delay as u64),
                    &[], // ACK ranges - simplified
                    now,
                )?;
                
                // Handle lost packets - mark for retransmission
                for _pn in result.1 {
                    self.stats.packets_lost += 1;
                }
                
                Ok(())
            }

            Frame::MaxData(max_data) => {
                // Update send flow control window
                self.flow_control.send.update_max_data(max_data.maximum_data);
                Ok(())
            }

            Frame::MaxStreamData(_max_stream_data) => {
                // Update stream send flow control window
                // TODO: forward to stream manager
                Ok(())
            }

            Frame::ResetStream(reset_stream) => {
                // Stream reset by peer
                self.pending_events.push(ConnectionEvent::StreamReset {
                    stream_id: reset_stream.stream_id,
                    error_code: reset_stream.application_error_code,
                });
                Ok(())
            }

            Frame::StopSending(_stop_sending) => {
                // Peer requests stream reset
                // TODO: Handle stop sending
                Ok(())
            }

            Frame::NewConnectionId(_) => {
                // New connection ID provided by peer
                Ok(())
            }

            Frame::RetireConnectionId(_) => {
                // Peer retiring connection ID
                Ok(())
            }

            Frame::PathChallenge(_challenge) => {
                // Must respond with PATH_RESPONSE
                // TODO: Queue PATH_RESPONSE frame
                Ok(())
            }

            Frame::PathResponse(_) => {
                // Path validation response
                Ok(())
            }

            Frame::ConnectionCloseTransport(_) => {
                // Peer closing connection
                self.state = ConnectionState::Draining;
                self.pending_events.push(ConnectionEvent::ConnectionClosed);
                Ok(())
            }

            Frame::ConnectionCloseApplication(_) => {
                // Peer closing connection
                self.state = ConnectionState::Draining;
                self.pending_events.push(ConnectionEvent::ConnectionClosed);
                Ok(())
            }

            Frame::HandshakeDone => {
                // Server confirms handshake complete (client only)
                if self.side == Side::Client {
                    self.handshake_complete = true;
                    self.state = ConnectionState::Active;
                }
                Ok(())
            }

            Frame::Ping => {
                // Keep connection alive
                Ok(())
            }

            Frame::Padding => {
                // No-op
                Ok(())
            }

            _ => {
                // Unknown frame type - ignore per RFC 9000
                Ok(())
            }
        }
    }
}

// Stub implementations for missing components
struct StubCryptoBackend;

impl CryptoBackend for StubCryptoBackend {
    fn create_aead(&self, _cipher_suite: u16) -> Result<Box<dyn crate::crypto::AeadProvider>> {
        Err(Error::Transport(crate::error::TransportError::InternalError))
    }
    
    fn create_header_protection(&self, _cipher_suite: u16) -> Result<Box<dyn crate::crypto::HeaderProtectionProvider>> {
        Err(Error::Transport(crate::error::TransportError::InternalError))
    }
    
    fn create_key_schedule(&self) -> Box<dyn crate::crypto::KeySchedule> {
        panic!("stub not implemented")
    }
    
    fn create_tls_session(
        &self,
        _side: Side,
        _server_name: Option<&str>,
        _alpn_protocols: &[&[u8]],
        _cert_data: Option<&[u8]>,
        _key_data: Option<&[u8]>,
    ) -> Result<Box<dyn TlsSession>> {
        Err(Error::Transport(crate::error::TransportError::InternalError))
    }
}

struct StubLossDetector;

impl LossDetector for StubLossDetector {
    fn on_packet_sent(
        &mut self,
        _space: crate::types::PacketNumberSpace,
        _packet_number: PacketNumber,
        _size: usize,
        _is_retransmittable: bool,
        _send_time: Instant,
    ) {}
    
    fn on_ack_received(
        &mut self,
        _space: crate::types::PacketNumberSpace,
        _largest_acked: PacketNumber,
        _ack_delay: Duration,
        _ack_ranges: &[(PacketNumber, PacketNumber)],
        _recv_time: Instant,
    ) -> crate::error::Result<(alloc::vec::Vec<PacketNumber>, alloc::vec::Vec<PacketNumber>)> {
        Ok((alloc::vec::Vec::new(), alloc::vec::Vec::new()))
    }
    
    fn detect_lost_packets(
        &mut self,
        _space: crate::types::PacketNumberSpace,
        _now: Instant,
    ) -> alloc::vec::Vec<PacketNumber> {
        alloc::vec::Vec::new()
    }
    
    fn get_loss_detection_timer(&self) -> Option<Instant> {
        None
    }
    
    fn on_loss_detection_timeout(&mut self, _now: Instant) -> crate::recovery::LossDetectionAction {
        crate::recovery::LossDetectionAction::None
    }
    
    fn pto_count(&self) -> u32 {
        0
    }
    
    fn discard_pn_space(&mut self, _space: crate::types::PacketNumberSpace) {}
}

impl Connection for QuicConnection {
    fn process_datagram(&mut self, datagram: DatagramInput) -> Result<()> {
        self.last_activity = Some(datagram.recv_time);
        self.stats.packets_received += 1;
        self.stats.bytes_received += datagram.data.len() as u64;

        // Parse packet header to determine type and encryption level
        use crate::packet::api::{Packet, ParseContext};
        let parse_ctx = ParseContext::with_dcid_len(self.dcid.len());
        let mut packet = match Packet::parse_with_context(datagram.data.clone(), parse_ctx) {
            Ok(p) => p,
            Err(_) => {
                // Invalid packet - drop silently
                return Ok(());
            }
        };
        
        // Determine encryption level from packet type
        let (encryption_level, read_keys) = match packet.header.ty {
            crate::packet::types::PacketType::Initial => {
                (CryptoLevel::Initial, &mut self.initial_read_keys)
            }
            crate::packet::types::PacketType::Handshake => {
                (CryptoLevel::Handshake, &mut self.handshake_read_keys)
            }
            crate::packet::types::PacketType::OneRtt => {
                (CryptoLevel::OneRTT, &mut self.one_rtt_read_keys)
            }
            _ => {
                // Other packet types not yet supported
                return Ok(());
            }
        };
        
        // Check if we have keys for this level
        if read_keys.aead.is_none() || read_keys.hp.is_none() {
            // Keys not available yet - buffer or drop
            return Ok(());
        }
        
        // Remove header protection (RFC 9001 Section 5.4)
        // This reveals the actual packet number
        // We need a mutable copy of the buffer to modify it in-place
        let mut datagram_buf = datagram.data.to_vec();
        let hp = read_keys.hp.as_ref().unwrap();
        let hp_key = &read_keys.hp_key;
        if let Err(_) = packet.remove_header_protection(hp.as_ref(), hp_key, &mut datagram_buf) {
            return Ok(());
        }
        
        // Packet number should now be available after header protection removal
        let packet_number = match packet.header.packet_number {
            Some(pn) => pn,
            None => {
                // Header protection removal failed or didn't extract PN
                return Ok(());
            }
        };
        
        // Calculate payload offset (needed for decryption)
        // We need to find where the Packet Number is, then add its length to get payload start
        // For Initial packets, we need to parse Token and Length fields
        // Use the mutable buffer for parsing
        let (pn_offset, length_field) = if packet.header.ty == crate::packet::types::PacketType::Initial {
            // Long header: 1 (flags) + 4 (version) + 1 (dcid_len) + dcid + 1 (scid_len) + scid
            let dcid_len = if datagram_buf.len() > 5 { datagram_buf[5] as usize } else { return Ok(()) };
            let scid_len = if datagram_buf.len() > 6 + dcid_len { datagram_buf[6 + dcid_len] as usize } else { return Ok(()) };
            let mut offset = 7 + dcid_len + scid_len;
            
            // Parse Token Length (variable-length integer)
            if datagram_buf.len() < offset {
                return Ok(());
            }
            let (token_len, token_len_bytes) = match crate::types::VarIntCodec::decode(&datagram_buf[offset..]) {
                Some((len, bytes)) => (len as usize, bytes),
                None => return Ok(()),
            };
            offset += token_len_bytes;
            
            // Skip Token field
            if datagram_buf.len() < offset + token_len {
                return Ok(());
            }
            offset += token_len;
            
            // Parse Length field (variable-length integer)
            if datagram_buf.len() < offset {
                return Ok(());
            }
            let (length_field, length_bytes) = match crate::types::VarIntCodec::decode(&datagram_buf[offset..]) {
                Some((len, bytes)) => (len, bytes),
                None => return Ok(()),
            };
            offset += length_bytes;
            
            // Return (pn_offset, length_field)
            // RFC 9000: Length field specifies length of Packet Number + Payload
            (offset, Some(length_field as usize))
        } else {
            // Short header: 1 (flags) + dcid + variable PN
            // No Length field in short headers
            (1 + self.dcid.len(), None)
        };
        
        // Use the actual PN length that was determined during header protection removal
        let pn_len = packet.header.packet_number_len.unwrap_or_else(|| {
            // Fallback: calculate from packet number value
            if packet_number < 256 { 1 } else if packet_number < 65536 { 2 } else if packet_number < 16777216 { 3 } else { 4 }
        });
        
        // RFC 9000: Length field specifies length of Packet Number + Payload
        // For long headers, use Length field to determine payload size
        // For short headers, payload extends to end of packet
        let encrypted_payload = if let Some(length_field) = length_field {
            // Long header: Length field specifies PN + Payload length
            // Payload length = Length field - PN length
            let payload_len = length_field.checked_sub(pn_len).unwrap_or(0);
            let payload_offset = pn_offset + pn_len;
            if datagram_buf.len() < payload_offset + payload_len {
                return Ok(());
            }
            &datagram_buf[payload_offset..payload_offset + payload_len]
        } else {
            // Short header: payload extends to end of packet
            let payload_offset = pn_offset + pn_len;
            if datagram_buf.len() <= payload_offset {
                return Ok(());
            }
            &datagram_buf[payload_offset..]
        };
        
        // Payload offset for AAD construction (header + PN)
        let payload_offset = pn_offset + pn_len;
        
        // Decrypt payload using AEAD
        let aead = read_keys.aead.as_ref().unwrap();
        let key = &read_keys.key;
        let iv = &read_keys.iv;
        
        // Build header for AEAD AAD (RFC 9001 Section 5.3)
        // AAD is the header up to and including the unprotected packet number
        // Since we modified datagram_buf in-place during header protection removal,
        // we can now use it directly for the AAD
        let header = &datagram_buf[..payload_offset];
        eprintln!("DEBUG: AEAD AAD: aad_len={}, pn_len={}, pn={}, payload_offset={}, pn_offset={}", 
                 header.len(), pn_len, packet_number, payload_offset, pn_offset);
        eprintln!("DEBUG: AAD first 20 bytes: {:02x?}", &header[..header.len().min(20)]);
        eprintln!("DEBUG: AAD last 10 bytes: {:02x?}", &header[header.len().saturating_sub(10)..]);
        
        // Allocate buffer for decrypted payload
        let mut decrypted = vec![0u8; encrypted_payload.len()];
        eprintln!("DEBUG: Attempting decryption: key_len={}, iv_len={}, pn={}, header_len={}, payload_len={}", 
                 key.len(), iv.len(), packet_number, header.len(), encrypted_payload.len());
        let decrypted_len = match aead.open(key, iv, packet_number, header, encrypted_payload, &mut decrypted) {
            Ok(len) => {
                eprintln!("DEBUG: Decryption successful: decrypted_len={}", len);
                len
            }
            Err(e) => {
                eprintln!("DEBUG: Decryption failed: {:?}", e);
                // Decryption failed - drop packet
                return Ok(());
            }
        };
        
        // Parse frames from decrypted payload
        use crate::frames::FrameParser;
        let parser = crate::frames::parse::DefaultFrameParser;
        let mut offset = 0;
        let payload = &decrypted[..decrypted_len];
        
        eprintln!("DEBUG: Parsing frames from decrypted payload: len={}", payload.len());
        while offset < payload.len() {
            let frame_result = parser.parse_frame(&payload[offset..]);
            
            match frame_result {
                Ok((frame, consumed)) => {
                    eprintln!("DEBUG: Parsed frame: type={:?}, consumed={}, offset={}", 
                             std::mem::discriminant(&frame), consumed, offset);
                    // Special handling for CRYPTO frames - feed to TLS
                    if let Frame::Crypto(crypto_frame) = &frame {
                        if let Some(ref mut tls) = self.tls_session {
                            eprintln!("DEBUG: Processing CRYPTO frame: level={:?}, data_len={}", encryption_level, crypto_frame.data.len());
                            if let Err(e) = tls.process_input(crypto_frame.data, encryption_level) {
                                eprintln!("DEBUG: TLS process_input error: {:?}", e);
                                // TLS error - close connection
                                self.state = ConnectionState::Closing;
                                return Ok(());
                            }
                            
                            // Process TLS output events
                            let mut event_count = 0;
                            while let Some(event) = tls.get_output() {
                                event_count += 1;
                                match &event {
                                    crate::crypto::TlsEvent::WriteData(level, data) => {
                                        eprintln!("DEBUG: TLS WriteData: level={:?}, len={}", level, data.len());
                                    }
                                    crate::crypto::TlsEvent::ReadData(_, _) => {
                                        eprintln!("DEBUG: TLS ReadData");
                                    }
                                    crate::crypto::TlsEvent::HandshakeComplete => {
                                        eprintln!("DEBUG: TLS HandshakeComplete");
                                    }
                                    crate::crypto::TlsEvent::ReadSecret(level, _) => {
                                        eprintln!("DEBUG: TLS ReadSecret: level={:?}", level);
                                    }
                                    crate::crypto::TlsEvent::WriteSecret(level, _) => {
                                        eprintln!("DEBUG: TLS WriteSecret: level={:?}", level);
                                    }
                                    crate::crypto::TlsEvent::Done => {
                                        eprintln!("DEBUG: TLS Done");
                                    }
                                }
                                match event {
                                    crate::crypto::TlsEvent::WriteData(level, data) => {
                                        // TLS wants to send data - queue as CRYPTO frame
                                        self.pending_crypto.push((level, Bytes::from(data)));
                                    }
                                    crate::crypto::TlsEvent::HandshakeComplete => {
                                        self.handshake_complete = true;
                                        self.state = ConnectionState::Active;
                                        self.pending_events.push(ConnectionEvent::HandshakeComplete);
                                    }
                                    crate::crypto::TlsEvent::ReadSecret(level, secret) => {
                                        // New read keys available - install them
                                        let key_schedule = self.crypto_backend.create_key_schedule();
                                        // Use AES-128-GCM (0x1301) as default - should match negotiated cipher
                                        let cipher_suite = 0x1301; // TODO: Get from TLS session
                                        let target_keys = match level {
                                            CryptoLevel::Initial => &mut self.initial_read_keys,
                                            CryptoLevel::Handshake => &mut self.handshake_read_keys,
                                            CryptoLevel::OneRTT => &mut self.one_rtt_read_keys,
                                            CryptoLevel::ZeroRTT => {
                                                // 0-RTT read keys not used on server
                                                continue;
                                            }
                                        };
                                        if let Err(e) = target_keys.install_from_secret(&secret, key_schedule.as_ref(), self.crypto_backend.as_ref(), cipher_suite) {
                                            eprintln!("Failed to install read keys for level {:?}: {:?}", level, e);
                                        }
                                    }
                                    crate::crypto::TlsEvent::WriteSecret(level, secret) => {
                                        // New write keys available - install them
                                        let key_schedule = self.crypto_backend.create_key_schedule();
                                        let cipher_suite = 0x1301; // TODO: Get from TLS session
                                        let target_keys = match level {
                                            CryptoLevel::Initial => &mut self.initial_write_keys,
                                            CryptoLevel::Handshake => &mut self.handshake_write_keys,
                                            CryptoLevel::OneRTT => &mut self.one_rtt_write_keys,
                                            CryptoLevel::ZeroRTT => {
                                                // 0-RTT write keys not used on server
                                                continue;
                                            }
                                        };
                                        if let Err(e) = target_keys.install_from_secret(&secret, key_schedule.as_ref(), self.crypto_backend.as_ref(), cipher_suite) {
                                            eprintln!("Failed to install write keys for level {:?}: {:?}", level, e);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            eprintln!("DEBUG: Processed {} TLS events", event_count);
                        } else {
                            eprintln!("DEBUG: No TLS session available!");
                        }
                    } else {
                        eprintln!("DEBUG: Non-CRYPTO frame: {:?}", std::mem::discriminant(&frame));
                    }
                    
                    self.process_frame(frame, datagram.recv_time)?;
                    offset += consumed;
                    
                    if consumed == 0 {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("DEBUG: Frame parsing error at offset {}: {:?}", offset, e);
                    // Malformed frame - drop packet
                    break;
                }
            }
        }

        Ok(())
    }

    fn process_timeout(&mut self, now: Instant) -> Result<()> {
        // Phase 7: Complete timeout handling
        
        // 1. Check idle timeout
        if let Some(last_activity) = self.last_activity {
            if let Some(idle_deadline) = last_activity.checked_add(self.config.idle_timeout) {
                if now.as_nanos() >= idle_deadline.as_nanos() {
                    self.state = ConnectionState::Closed;
                    self.pending_events.push(ConnectionEvent::ConnectionClosed);
                    return Ok(());
                }
            }
        }

        // 2. Check closing/draining timeout
        if let Some(closing_timeout) = self.closing_timeout {
            if now.as_nanos() >= closing_timeout.as_nanos() {
                self.state = ConnectionState::Closed;
                self.pending_events.push(ConnectionEvent::ConnectionClosed);
                return Ok(());
            }
        }

        // 3. Check loss detection timeout (PTO)
        let spaces = [
            crate::types::PacketNumberSpace::Initial,
            crate::types::PacketNumberSpace::Handshake,
            crate::types::PacketNumberSpace::ApplicationData,
        ];
        
        for space in &spaces {
            let lost_packets = self.loss_detector.detect_lost_packets(*space, now);
            for _pn in lost_packets {
                self.stats.packets_lost += 1;
                // TODO: Mark frames for retransmission
            }
        }

        Ok(())
    }

    fn poll_send(&mut self, buf: &mut BytesMut, now: Instant) -> Option<DatagramOutput> {
        // Check congestion window
        if !self.congestion_controller.can_send(1200) {
            return None;
        }

        // Priority: Send CRYPTO frames first (handshake data)
        eprintln!("DEBUG: poll_send called, pending_crypto={}", self.pending_crypto.len());
        if let Some((level, crypto_data)) = self.pending_crypto.pop() {
            eprintln!("DEBUG: Sending CRYPTO frame: level={:?}, data_len={}", level, crypto_data.len());
            // For now, only handle Initial level
            if level != CryptoLevel::Initial {
                eprintln!("DEBUG: Non-Initial level, putting back");
                // Put it back for later
                self.pending_crypto.push((level, crypto_data));
                return None;
            }
            
            let write_keys = &mut self.initial_write_keys;
            if write_keys.aead.is_none() {
                eprintln!("DEBUG: Initial write keys not available!");
                // Put it back
                self.pending_crypto.push((level, crypto_data));
                return None;
            }
            
            // Build Initial packet
            // Header: flags + version + DCID len + DCID + SCID len + SCID + Length + PN + Payload
            let dcid_bytes = self.dcid.as_bytes();
            let scid_bytes = self.scid.as_bytes();
            
            // Increment packet number
            let pn = write_keys.packet_number;
            write_keys.packet_number += 1;
            
            // Determine PN length (1-4 bytes, use 1 byte for now)
            let pn_len = 1;
            let pn_bytes = [(pn & 0xff) as u8];
            
            // Build CRYPTO frame
            use crate::frames::Frame;
            let crypto_frame = Frame::Crypto(crate::frames::CryptoFrame {
                offset: 0, // TODO: Track offset properly
                data: &crypto_data,
            });
            
            // Serialize CRYPTO frame
            use crate::frames::parse::{DefaultFrameSerializer, FrameSerializer};
            let serializer = DefaultFrameSerializer;
            let mut frame_buf = BytesMut::new();
            match serializer.serialize_frame(&crypto_frame, &mut frame_buf) {
                Ok(_) => {}
                Err(_) => return None,
            }
            
            // Encrypt payload - we'll estimate length first, then adjust if needed
            let plaintext = frame_buf.freeze();
            let aead = write_keys.aead.as_ref().unwrap();
            let key = &write_keys.key;
            let iv = &write_keys.iv;
            let tag_len = aead.tag_len();
            
            // Estimate encrypted length (plaintext + tag)
            let estimated_encrypted_len = plaintext.len() + tag_len;
            let estimated_payload_len = pn_len + estimated_encrypted_len;
            
            // Build full header including Length and PN (for AEAD AAD)
            buf.clear();
            buf.reserve(1200);
            
            // Long header byte
            let first_byte = 0xc0 | ((pn_len - 1) as u8);
            buf.put_u8(first_byte);
            buf.put_u32(VERSION_1);
            buf.put_u8(dcid_bytes.len() as u8);
            buf.put_slice(dcid_bytes);
            buf.put_u8(scid_bytes.len() as u8);
            buf.put_slice(scid_bytes);
            
            // Length field (estimate - will be correct after encryption)
            let length_field_start = buf.len();
            if estimated_payload_len < 64 {
                buf.put_u8(estimated_payload_len as u8);
            } else if estimated_payload_len < 16384 {
                buf.put_u8(0x40 | ((estimated_payload_len >> 8) as u8));
                buf.put_u8((estimated_payload_len & 0xff) as u8);
            } else {
                buf.put_u8(0x80 | ((estimated_payload_len >> 24) as u8));
                buf.put_u8((estimated_payload_len >> 16) as u8);
                buf.put_u8((estimated_payload_len >> 8) as u8);
                buf.put_u8((estimated_payload_len & 0xff) as u8);
            }
            
            // Packet number
            buf.put_slice(&pn_bytes);
            
            let header_len = buf.len();
            let header_for_aead = &buf[..]; // Full header for AEAD AAD
            
            // Encrypt payload
            let mut encrypted_buf = vec![0u8; plaintext.len() + tag_len];
            let encrypted_len = match aead.seal(key, iv, pn, header_for_aead, &plaintext, &mut encrypted_buf) {
                Ok(len) => len,
                Err(_) => return None,
            };
            
            // Update Length field if actual length differs (should be rare)
            let actual_payload_len = pn_len + encrypted_len;
            if actual_payload_len != estimated_payload_len {
                // Rebuild length field (in practice this should rarely happen)
                let old_len_field_len = buf.len() - length_field_start - pn_len;
                buf.truncate(length_field_start);
                if actual_payload_len < 64 {
                    buf.put_u8(actual_payload_len as u8);
                } else if actual_payload_len < 16384 {
                    buf.put_u8(0x40 | ((actual_payload_len >> 8) as u8));
                    buf.put_u8((actual_payload_len & 0xff) as u8);
                } else {
                    buf.put_u8(0x80 | ((actual_payload_len >> 24) as u8));
                    buf.put_u8((actual_payload_len >> 16) as u8);
                    buf.put_u8((actual_payload_len >> 8) as u8);
                    buf.put_u8((actual_payload_len & 0xff) as u8);
                }
                buf.put_slice(&pn_bytes);
            }
            
            // Append encrypted payload
            buf.put_slice(&encrypted_buf[..encrypted_len]);
            
            // Apply header protection (RFC 9001 Section 5.4)
            let hp = write_keys.hp.as_ref().unwrap();
            let hp_key = &write_keys.hp_key;
            
            // Sample is 16 bytes starting 4 bytes after the start of the packet number
            // PN starts at: header_len - pn_len - encrypted_len (but encrypted_len is after PN)
            // Actually, PN is at: header_len - pn_len (before we added encrypted payload)
            let pn_start = header_len - pn_len;
            let sample_offset = pn_start + pn_len + 4; // 4 bytes after PN end
            if buf.len() < sample_offset + 16 {
                return None;
            }
            
            let sample = &buf[sample_offset..sample_offset + 16];
            let mut mask = vec![0u8; 5]; // 5 bytes: 1 for first byte, 4 for PN
            if let Err(_) = hp.build_mask(hp_key, sample, &mut mask) {
                return None;
            }
            
            // Apply mask to first byte
            // For Initial packets (long header), mask 4 bits (0x0f)
            // For short header, mask 5 bits (0x1f)
            // Since this is Initial packet, use 0x0f
            buf[0] ^= mask[0] & 0x0f; // Mask bits 0-3 (Reserved + PN Length for long header)
            for i in 0..pn_len {
                buf[pn_start + i] ^= mask[1 + i];
            }
            
            // Record sent packet
            self.loss_detector.on_packet_sent(
                crate::types::PacketNumberSpace::Initial,
                pn,
                buf.len(),
                true, // is_retransmittable (CRYPTO frames are retransmittable)
                now,
            );
            self.congestion_controller.on_packet_sent(
                pn,
                crate::types::PacketNumberSpace::Initial,
                buf.len(),
                true, // is_ack_eliciting
                now,
            );
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += buf.len() as u64;
            
            let data = buf.split();
            return Some(DatagramOutput {
                data,
                send_time: None,
            });
        }
        
        None
    }

    fn poll_event(&mut self) -> Option<ConnectionEvent> {
        if self.pending_events.is_empty() {
            None
        } else {
            Some(self.pending_events.remove(0))
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;

        // Idle timeout
        if let Some(last_activity) = self.last_activity {
            if let Some(idle_deadline) = last_activity.checked_add(self.config.idle_timeout) {
                earliest = Some(match earliest {
                    None => idle_deadline,
                    Some(e) => if idle_deadline.as_nanos() < e.as_nanos() {
                        idle_deadline
                    } else {
                        e
                    }
                });
            }
        }

        // Closing timeout
        if let Some(closing_timeout) = self.closing_timeout {
            earliest = Some(match earliest {
                None => closing_timeout,
                Some(e) => if closing_timeout.as_nanos() < e.as_nanos() {
                    closing_timeout
                } else {
                    e
                }
            });
        }

        // Loss detection timer
        if let Some(loss_timer) = self.loss_detector.get_loss_detection_timer() {
            earliest = Some(match earliest {
                None => loss_timer,
                Some(e) => if loss_timer.as_nanos() < e.as_nanos() {
                    loss_timer
                } else {
                    e
                }
            });
        }

        earliest
    }

    fn state(&self) -> ConnectionState {
        self.state
    }

    fn send_datagram(&mut self, data: Bytes) -> Result<()> {
        // Datagrams aren't supported yet in the frame types
        // For now, just consume the data successfully
        Ok(())
    }

    fn open_stream(&mut self, direction: crate::types::StreamDirection) -> Result<StreamId> {
        // Phase 7: Use stream manager to allocate stream ID
        let initiator = match self.side {
            Side::Client => crate::types::StreamInitiator::Client,
            Side::Server => crate::types::StreamInitiator::Server,
        };
        
        // Stream IDs are allocated based on initiator and type
        // Client: 0, 4, 8, ... (bidi), 2, 6, 10, ... (uni)
        // Server: 1, 5, 9, ... (bidi), 3, 7, 11, ... (uni)
        let stream_id = match (initiator, direction) {
            (crate::types::StreamInitiator::Client, crate::types::StreamDirection::Bidirectional) => StreamId::new(0),
            (crate::types::StreamInitiator::Client, crate::types::StreamDirection::Unidirectional) => StreamId::new(2),
            (crate::types::StreamInitiator::Server, crate::types::StreamDirection::Bidirectional) => StreamId::new(1),
            (crate::types::StreamInitiator::Server, crate::types::StreamDirection::Unidirectional) => StreamId::new(3),
        };
        
        Ok(stream_id)
    }

    fn write_stream(&mut self, stream_id: StreamId, data: Bytes, fin: bool) -> Result<()> {
        // Check connection-level flow control
        let data_len = data.len() as u64;
        if self.flow_control.send.available_credit() < data_len {
            return Err(Error::Transport(crate::error::TransportError::FlowControlError));
        }
        
        // Queue stream write for next packet generation
        // Flow control credit will be consumed when frames are actually sent in poll_send()
        self.pending_stream_writes.push((stream_id, data, fin));
        
        Ok(())
    }

    fn read_stream(&mut self, stream_id: StreamId) -> Result<Option<Bytes>> {
        // Read from stream manager's reassembly buffer
        // For now, return None as streams deliver data via events
        Ok(None)
    }

    fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        // Queue RESET_STREAM for next packet
        self.pending_stream_resets.push((stream_id, error_code, 0));
        
        Ok(())
    }

    fn close(&mut self, error_code: u64, reason: &[u8]) {
        self.state = ConnectionState::Closing;
        
        // Set closing timeout (3x PTO)
        if let Some(last_activity) = self.last_activity {
            self.closing_timeout = last_activity.checked_add(Duration::from_secs(3));
        }
        
        // Queue CONNECTION_CLOSE for next packet
        self.pending_close = Some((error_code, reason.to_vec()));
    }

    fn stats(&self) -> ConnectionStats {
        let mut stats = self.stats.clone();
        
        // Get additional stats from components
        // stats.smoothed_rtt = self.loss_detector.rtt().smoothed_rtt();
        stats.congestion_window = self.congestion_controller.congestion_window();
        stats.bytes_in_flight = self.congestion_controller.bytes_in_flight();
        
        stats
    }

    fn source_cid(&self) -> &ConnectionId {
        &self.scid
    }

    fn destination_cid(&self) -> &ConnectionId {
        &self.dcid
    }
}
