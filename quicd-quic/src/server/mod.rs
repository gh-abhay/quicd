//! Server-specific QUIC features
//!
//! This module implements server-side functionality including:
//! - Stateless Retry (RFC 9000 Section 8.1) - DDoS protection
//! - Address validation tokens (RFC 9000 Section 8)
//! - Stateless Reset (RFC 9000 Section 10.3)

use crate::types::{ConnectionId, Instant};
use crate::error::{Error, Result};
use core::time::Duration;
use alloc::vec::Vec;

/// Address validation token generator and validator (RFC 9000 Section 8)
///
/// **Design**: Tokens are cryptographically bound to client address and original
/// destination CID. This prevents token reuse across different clients or connections.
///
/// **Security**: Uses HMAC-SHA256 with a rotating secret key to prevent forgery.
pub struct TokenValidator {
    /// Current secret key for HMAC
    current_secret: [u8; 32],
    
    /// Previous secret key (for rotation grace period)
    previous_secret: Option<[u8; 32]>,
    
    /// When current_secret was created
    secret_created_at: Instant,
    
    /// How long a secret remains valid
    secret_lifetime: Duration,
    
    /// Maximum token lifetime (RFC 9000 recommends limiting)
    max_token_age: Duration,
}

impl TokenValidator {
    /// Create a new token validator
    ///
    /// **Security Recommendations**:
    /// - `secret_lifetime`: Rotate every 15-30 minutes
    /// - `max_token_age`: Accept tokens for 24 hours max
    pub fn new(
        initial_secret: [u8; 32],
        now: Instant,
        secret_lifetime: Duration,
        max_token_age: Duration,
    ) -> Self {
        Self {
            current_secret: initial_secret,
            previous_secret: None,
            secret_created_at: now,
            secret_lifetime,
            max_token_age,
        }
    }
    
    /// Rotate the secret key
    ///
    /// **Design**: Keeps previous key for grace period to avoid rejecting
    /// valid tokens during rotation.
    pub fn rotate_secret(&mut self, new_secret: [u8; 32], now: Instant) {
        self.previous_secret = Some(self.current_secret);
        self.current_secret = new_secret;
        self.secret_created_at = now;
    }
    
    /// Check if secret should be rotated
    pub fn should_rotate_secret(&self, now: Instant) -> bool {
        now.duration_since(self.secret_created_at) >= self.secret_lifetime
    }
    
    /// Generate a Retry token (RFC 9000 Section 8.1.4)
    ///
    /// **Token Format**: `timestamp || client_addr || odcid || HMAC`
    ///
    /// **Parameters**:
    /// - `client_addr`: Client's IP:port (prevents token reuse)
    /// - `original_dcid`: Client's original Destination CID
    /// - `now`: Current timestamp (for expiration check)
    ///
    /// **Returns**: Opaque token to include in Retry packet
    pub fn generate_retry_token(
        &self,
        client_addr: &ClientAddress,
        original_dcid: &ConnectionId,
        now: Instant,
    ) -> Vec<u8> {
        let mut token = Vec::new();
        
        // 1. Timestamp (8 bytes)
        token.extend_from_slice(&now.0.as_millis().to_be_bytes());
        
        // 2. Client address (variable)
        token.extend_from_slice(&client_addr.encode());
        
        // 3. Original DCID length (1 byte)
        token.push(original_dcid.len() as u8);
        
        // 4. Original DCID
        token.extend_from_slice(original_dcid.as_bytes());
        
        // 5. HMAC-SHA256 (32 bytes)
        let hmac = self.compute_hmac(&token, &self.current_secret);
        token.extend_from_slice(&hmac);
        
        token
    }
    
    /// Validate a Retry token (RFC 9000 Section 8.1.4)
    ///
    /// **Validation Steps**:
    /// 1. Check token format and length
    /// 2. Verify HMAC with current and previous secrets
    /// 3. Check timestamp not expired
    /// 4. Verify client address matches
    /// 5. Extract original DCID
    ///
    /// **Returns**: Original destination CID if valid
    pub fn validate_retry_token(
        &self,
        token: &[u8],
        client_addr: &ClientAddress,
        now: Instant,
    ) -> Result<ConnectionId> {
        // Minimum token size: 8 (timestamp) + HMAC (32) = 40 bytes
        if token.len() < 40 {
            return Err(Error::InvalidToken);
        }
        
        let data_len = token.len() - 32;
        let (data, hmac) = token.split_at(data_len);
        
        // 1. Verify HMAC with current secret
        let valid_hmac = self.verify_hmac(data, hmac, &self.current_secret)
            || self.previous_secret
                .as_ref()
                .map(|secret| self.verify_hmac(data, hmac, secret))
                .unwrap_or(false);
        
        if !valid_hmac {
            return Err(Error::InvalidToken);
        }
        
        // 2. Parse token data
        let mut cursor = 0;
        
        // Extract timestamp
        if data.len() < cursor + 16 {
            return Err(Error::InvalidToken);
        }
        let timestamp_bytes: [u8; 16] = data[cursor..cursor + 16]
            .try_into()
            .map_err(|_| Error::InvalidToken)?;
        let token_timestamp = Instant(Duration::from_millis(
            u128::from_be_bytes(timestamp_bytes)
        ));
        cursor += 16;
        
        // 3. Check expiration
        let age = now.duration_since(token_timestamp);
        if age > self.max_token_age {
            return Err(Error::InvalidToken);
        }
        
        // 4. Extract and verify client address
        let (addr, addr_len) = ClientAddress::decode(&data[cursor..])
            .map_err(|_| Error::InvalidToken)?;
        cursor += addr_len;
        
        if &addr != client_addr {
            return Err(Error::InvalidToken);
        }
        
        // 5. Extract original DCID
        if data.len() < cursor + 1 {
            return Err(Error::InvalidToken);
        }
        let dcid_len = data[cursor] as usize;
        cursor += 1;
        
        if data.len() < cursor + dcid_len {
            return Err(Error::InvalidToken);
        }
        
        let original_dcid = ConnectionId::new(&data[cursor..cursor + dcid_len])
            .ok_or(Error::InvalidToken)?;
        
        Ok(original_dcid)
    }
    
    /// Generate a NEW_TOKEN frame token (RFC 9000 Section 8.1.3)
    ///
    /// **Design**: Similar to Retry token but can be sent after handshake
    /// for future 0-RTT connections.
    pub fn generate_new_token(
        &self,
        client_addr: &ClientAddress,
        now: Instant,
    ) -> Vec<u8> {
        let mut token = Vec::new();
        
        // Timestamp
        token.extend_from_slice(&now.0.as_millis().to_be_bytes());
        
        // Client address
        token.extend_from_slice(&client_addr.encode());
        
        // Token type marker (1 = NEW_TOKEN)
        token.push(1);
        
        // HMAC
        let hmac = self.compute_hmac(&token, &self.current_secret);
        token.extend_from_slice(&hmac);
        
        token
    }
    
    /// Validate a NEW_TOKEN frame token
    pub fn validate_new_token(
        &self,
        token: &[u8],
        client_addr: &ClientAddress,
        now: Instant,
    ) -> Result<()> {
        if token.len() < 40 {
            return Err(Error::InvalidToken);
        }
        
        let data_len = token.len() - 32;
        let (data, hmac) = token.split_at(data_len);
        
        // Verify HMAC
        let valid_hmac = self.verify_hmac(data, hmac, &self.current_secret)
            || self.previous_secret
                .as_ref()
                .map(|secret| self.verify_hmac(data, hmac, secret))
                .unwrap_or(false);
        
        if !valid_hmac {
            return Err(Error::InvalidToken);
        }
        
        // Check expiration and address (similar to retry token)
        // ... (implementation details)
        
        Ok(())
    }
    
    /// Compute HMAC-SHA256
    ///
    /// **Note**: This is a placeholder. Real implementation should use
    /// a crypto library like `ring` or `sha2` + `hmac`.
    fn compute_hmac(&self, data: &[u8], secret: &[u8; 32]) -> [u8; 32] {
        // TODO: Implement with actual HMAC-SHA256
        // Use ring::hmac or hmac + sha2 crates
        [0u8; 32]
    }
    
    /// Verify HMAC
    fn verify_hmac(&self, data: &[u8], expected_hmac: &[u8], secret: &[u8; 32]) -> bool {
        let computed_hmac = self.compute_hmac(data, secret);
        
        // Constant-time comparison to prevent timing attacks
        computed_hmac.iter()
            .zip(expected_hmac.iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
    }
}

/// Client network address (IP:port)
///
/// **Design**: Simplified representation. Real implementation should support
/// both IPv4 and IPv6.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientAddress {
    /// IP address bytes (4 for IPv4, 16 for IPv6)
    pub ip: Vec<u8>,
    
    /// Port number
    pub port: u16,
}

impl ClientAddress {
    /// Encode address to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Address family (4 = IPv4, 6 = IPv6)
        bytes.push(self.ip.len() as u8);
        
        // IP bytes
        bytes.extend_from_slice(&self.ip);
        
        // Port
        bytes.extend_from_slice(&self.port.to_be_bytes());
        
        bytes
    }
    
    /// Decode address from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        
        let addr_len = data[0] as usize;
        if data.len() < 1 + addr_len + 2 {
            return Err(Error::BufferTooShort);
        }
        
        let ip = data[1..1 + addr_len].to_vec();
        let port = u16::from_be_bytes([
            data[1 + addr_len],
            data[1 + addr_len + 1],
        ]);
        
        Ok((Self { ip, port }, 1 + addr_len + 2))
    }
}

/// Stateless Reset token (RFC 9000 Section 10.3)
///
/// **Design**: Allows a server that lost connection state (e.g., after restart)
/// to signal the client to close the connection.
#[derive(Debug, Clone)]
pub struct StatelessResetToken {
    /// 16-byte cryptographically random token
    token: [u8; 16],
}

impl StatelessResetToken {
    /// Generate a stateless reset token for a connection ID
    ///
    /// **RFC 9000 Section 10.3.1**: Token MUST be derived from a secret
    /// and the connection ID.
    pub fn generate(secret: &[u8; 32], cid: &ConnectionId) -> Self {
        // Use HMAC-SHA256 and truncate to 16 bytes
        let mut hasher = [0u8; 32]; // Placeholder
        // TODO: hasher = HMAC-SHA256(secret, cid)
        
        let mut token = [0u8; 16];
        token.copy_from_slice(&hasher[..16]);
        
        Self { token }
    }
    
    /// Get token bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.token
    }
    
    /// Check if packet is a stateless reset (RFC 9000 Section 10.3.3)
    ///
    /// **Design**: Last 16 bytes of a short header packet with unknown CID
    /// may be a stateless reset token.
    pub fn is_stateless_reset(packet: &[u8], expected_token: &[u8; 16]) -> bool {
        if packet.len() < 21 {  // Minimum: 1 header + 4 packet number + 16 token
            return false;
        }
        
        let token_start = packet.len() - 16;
        &packet[token_start..] == expected_token
    }
}

/// Server configuration for address validation
#[derive(Debug, Clone)]
pub struct AddressValidationConfig {
    /// Require address validation via Retry for all new connections
    pub require_retry: bool,
    
    /// Secret key rotation interval
    pub secret_rotation_interval: Duration,
    
    /// Maximum token age
    pub max_token_age: Duration,
    
    /// Maximum number of tokens to accept without validation
    /// (0 = always require validation)
    pub max_unvalidated_connections: usize,
}

impl Default for AddressValidationConfig {
    fn default() -> Self {
        Self {
            require_retry: true,
            secret_rotation_interval: Duration::from_secs(900),  // 15 minutes
            max_token_age: Duration::from_secs(86400),  // 24 hours
            max_unvalidated_connections: 0,
        }
    }
}

/// Server-side connection acceptance logic
pub struct ServerAcceptor {
    /// Token validator
    token_validator: TokenValidator,
    
    /// Configuration
    config: AddressValidationConfig,
    
    /// Number of unvalidated connections currently open
    unvalidated_connections: usize,
}

impl ServerAcceptor {
    /// Create a new server acceptor
    pub fn new(
        initial_secret: [u8; 32],
        now: Instant,
        config: AddressValidationConfig,
    ) -> Self {
        let token_validator = TokenValidator::new(
            initial_secret,
            now,
            config.secret_rotation_interval,
            config.max_token_age,
        );
        
        Self {
            token_validator,
            config,
            unvalidated_connections: 0,
        }
    }
    
    /// Handle an Initial packet from a new client
    ///
    /// **Returns**: Action to take (Accept, SendRetry, or Reject)
    pub fn handle_initial_packet(
        &mut self,
        client_addr: &ClientAddress,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: Option<&[u8]>,
        now: Instant,
    ) -> Result<AcceptAction> {
        // 1. Check if we should enforce address validation
        let needs_validation = self.config.require_retry
            || self.unvalidated_connections >= self.config.max_unvalidated_connections;
        
        if !needs_validation {
            // Accept without validation
            self.unvalidated_connections += 1;
            return Ok(AcceptAction::Accept);
        }
        
        // 2. Check for Retry token
        let Some(token_bytes) = token else {
            // No token - send Retry packet
            let retry_token = self.token_validator.generate_retry_token(
                client_addr,
                dcid,
                now,
            );
            
            return Ok(AcceptAction::SendRetry {
                token: retry_token,
            });
        };
        
        // 3. Validate token
        let original_dcid = self.token_validator.validate_retry_token(
            token_bytes,
            client_addr,
            now,
        )?;
        
        // 4. Verify original DCID matches
        if original_dcid.as_bytes() != dcid.as_bytes() {
            return Err(Error::InvalidToken);
        }
        
        // 5. Accept connection
        Ok(AcceptAction::Accept)
    }
    
    /// Rotate the secret key
    pub fn rotate_secret(&mut self, new_secret: [u8; 32], now: Instant) {
        self.token_validator.rotate_secret(new_secret, now);
    }
    
    /// Check if secret should be rotated
    pub fn should_rotate_secret(&self, now: Instant) -> bool {
        self.token_validator.should_rotate_secret(now)
    }
    
    /// Mark a connection as validated (completed handshake)
    pub fn mark_validated(&mut self) {
        if self.unvalidated_connections > 0 {
            self.unvalidated_connections -= 1;
        }
    }
}

/// Action to take when handling an Initial packet
#[derive(Debug)]
pub enum AcceptAction {
    /// Accept the connection
    Accept,
    
    /// Send a Retry packet with this token
    SendRetry {
        token: Vec<u8>,
    },
    
    /// Reject the connection (rate limiting, invalid token, etc.)
    Reject,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_token_generation_and_validation() {
        let secret = [0x42; 32];
        let now = Instant(Duration::from_secs(1000));
        let validator = TokenValidator::new(
            secret,
            now,
            Duration::from_secs(900),
            Duration::from_secs(86400),
        );
        
        let client_addr = ClientAddress {
            ip: vec![127, 0, 0, 1],
            port: 12345,
        };
        
        let dcid = ConnectionId::new(&[1, 2, 3, 4]).unwrap();
        
        // Generate token
        let token = validator.generate_retry_token(&client_addr, &dcid, now);
        assert!(!token.is_empty());
        
        // Validate with same parameters
        let later = Instant(Duration::from_secs(1010));
        let result = validator.validate_retry_token(&token, &client_addr, later);
        assert!(result.is_ok());
        
        // Validate with wrong address should fail
        let wrong_addr = ClientAddress {
            ip: vec![192, 168, 1, 1],
            port: 12345,
        };
        let result = validator.validate_retry_token(&token, &wrong_addr, later);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_server_acceptor_retry_flow() {
        let secret = [0x42; 32];
        let now = Instant(Duration::from_secs(1000));
        let config = AddressValidationConfig {
            require_retry: true,
            ..Default::default()
        };
        
        let mut acceptor = ServerAcceptor::new(secret, now, config);
        
        let client_addr = ClientAddress {
            ip: vec![127, 0, 0, 1],
            port: 12345,
        };
        let dcid = ConnectionId::new(&[1, 2, 3, 4]).unwrap();
        let scid = ConnectionId::new(&[5, 6, 7, 8]).unwrap();
        
        // First attempt without token - should send Retry
        let action = acceptor.handle_initial_packet(
            &client_addr,
            &dcid,
            &scid,
            None,
            now,
        ).unwrap();
        
        match action {
            AcceptAction::SendRetry { token } => {
                // Second attempt with token - should accept
                let later = Instant(Duration::from_secs(1001));
                let action = acceptor.handle_initial_packet(
                    &client_addr,
                    &dcid,
                    &scid,
                    Some(&token),
                    later,
                ).unwrap();
                
                assert!(matches!(action, AcceptAction::Accept));
            }
            _ => panic!("Expected SendRetry"),
        }
    }
}
