use crate::error::Result;
use crate::types::{ConnectionId, PacketNumber, Side};
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CryptoLevel {
    Initial,
    ZeroRTT,
    Handshake,
    OneRTT,
}

pub trait CryptoBackend: Send + Sync {
    fn create_aead(&self, cipher_suite: u16) -> Result<Box<dyn AeadProvider>>;
    fn create_header_protection(&self, cipher_suite: u16) -> Result<Box<dyn HeaderProtectionProvider>>;
    fn create_key_schedule(&self) -> Box<dyn KeySchedule>;
    fn create_tls_session(
        &self,
        side: Side,
        server_name: Option<&str>,
        alpn_protocols: &[&[u8]],
        cert_data: Option<&[u8]>,
        key_data: Option<&[u8]>,
    ) -> Result<Box<dyn TlsSession>>;
}

pub trait AeadProvider: Send + Sync {
    fn seal(
        &self,
        key: &[u8],
        iv: &[u8],
        packet_number: PacketNumber,
        header: &[u8],
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize>;

    fn open(
        &self,
        key: &[u8],
        iv: &[u8],
        packet_number: PacketNumber,
        header: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize>;

    fn key_len(&self) -> usize;
    fn iv_len(&self) -> usize;
    fn tag_len(&self) -> usize;
}

pub trait HeaderProtectionProvider: Send + Sync {
    fn build_mask(&self, key: &[u8], sample: &[u8], output: &mut [u8]) -> Result<()>;
    fn key_len(&self) -> usize;
    fn sample_len(&self) -> usize;
}

pub trait KeySchedule: Send + Sync {
    // HKDF operations
    // Initial secrets always use SHA-256 regardless of negotiated cipher
    fn derive_initial_secret(&self, dcid: &ConnectionId, version: u32) -> Result<[u8; 32]>;
    fn derive_client_initial_secret(&self, initial_secret: &[u8]) -> Result<[u8; 32]>;
    fn derive_server_initial_secret(&self, initial_secret: &[u8]) -> Result<[u8; 32]>;
    // Handshake and OneRTT keys use hash function matching cipher suite
    fn derive_packet_key(&self, secret: &[u8], len: usize, cipher_suite: u16) -> Result<Vec<u8>>;
    fn derive_packet_iv(&self, secret: &[u8], len: usize, cipher_suite: u16) -> Result<Vec<u8>>;
    fn derive_header_protection_key(&self, secret: &[u8], len: usize, cipher_suite: u16) -> Result<Vec<u8>>;
}

pub enum TlsEvent {
    WriteData(CryptoLevel, Vec<u8>),
    ReadData(CryptoLevel, Vec<u8>),
    HandshakeComplete,
    ReadSecret(CryptoLevel, Vec<u8>, u16), // Added cipher_suite as third parameter
    WriteSecret(CryptoLevel, Vec<u8>, u16), // Added cipher_suite as third parameter
    Done,
}

pub trait TlsSession: Send + Sync {
    fn process_input(&mut self, data: &[u8], level: CryptoLevel) -> Result<()>;
    fn get_output(&mut self) -> Option<TlsEvent>;
    fn is_handshake_complete(&self) -> bool;
    fn alpn_protocol(&self) -> Option<Vec<u8>>;
    fn peer_transport_params(&self) -> Option<Vec<u8>>;
    fn set_transport_params(&mut self, params: &[u8]) -> Result<()>;
}
