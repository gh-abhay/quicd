//! CONNECT method support per RFC 9114 Section 4.4.
//!
//! Implements both standard CONNECT (for TCP tunneling) and extended CONNECT
//! (with :protocol pseudo-header for protocols like WebSocket).

use bytes::Bytes;
use crate::error::H3Error;
use crate::validation::RequestPseudoHeaders;

/// State of a CONNECT tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectState {
    /// Waiting for response
    Pending,
    /// Tunnel established (2xx response sent)
    Established,
    /// Tunnel failed or closed
    Closed,
}

/// Manager for a CONNECT tunnel on a stream.
pub struct ConnectTunnel {
    /// Stream ID
    stream_id: u64,
    /// Current tunnel state
    state: ConnectState,
    /// Target authority (host:port)
    authority: String,
    /// Protocol for extended CONNECT (None for standard CONNECT)
    protocol: Option<String>,
    /// Buffered data waiting to be sent through tunnel
    pending_data: Vec<Bytes>,
}

impl ConnectTunnel {
    /// Create a new CONNECT tunnel.
    pub fn new(
        stream_id: u64,
        pseudo_headers: &RequestPseudoHeaders,
    ) -> Result<Self, H3Error> {
        // Validate this is a CONNECT request
        if !pseudo_headers.is_connect() {
            return Err(H3Error::Http("not a CONNECT request".into()));
        }

        let authority = pseudo_headers.authority.clone()
            .ok_or_else(|| H3Error::Http("CONNECT requires :authority".into()))?;

        Ok(Self {
            stream_id,
            state: ConnectState::Pending,
            authority,
            protocol: pseudo_headers.protocol.clone(),
            pending_data: Vec::new(),
        })
    }

    /// Get the stream ID.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Get the current state.
    pub fn state(&self) -> ConnectState {
        self.state
    }

    /// Check if this is an extended CONNECT.
    pub fn is_extended_connect(&self) -> bool {
        self.protocol.is_some()
    }

    /// Get the protocol for extended CONNECT.
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// Get the target authority.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Mark the tunnel as established (after sending 2xx response).
    pub fn mark_established(&mut self) {
        self.state = ConnectState::Established;
    }

    /// Mark the tunnel as closed.
    pub fn mark_closed(&mut self) {
        self.state = ConnectState::Closed;
    }

    /// Queue data to be sent through the tunnel.
    pub fn queue_data(&mut self, data: Bytes) {
        if self.state == ConnectState::Established {
            self.pending_data.push(data);
        }
    }

    /// Drain pending data.
    pub fn drain_pending_data(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.pending_data)
    }

    /// Validate that only DATA frames are sent after CONNECT is established.
    ///
    /// Per RFC 9114 Section 4.4: "Once the CONNECT method has completed,
    /// only DATA frames are permitted to be sent on the stream."
    pub fn validate_frame_type(&self, frame_type: &str) -> Result<(), H3Error> {
        if self.state != ConnectState::Established {
            return Ok(());
        }

        if frame_type != "DATA" {
            return Err(H3Error::Http(format!(
                "only DATA frames permitted after CONNECT, got {}",
                frame_type
            )));
        }

        Ok(())
    }
}

/// Validate CONNECT request pseudo-headers.
///
/// Per RFC 9114 Section 4.4:
/// - Standard CONNECT: MUST have :method and :authority, MUST NOT have :scheme and :path
/// - Extended CONNECT: MUST have :method, :protocol, :scheme, :authority, :path
pub fn validate_connect_request(
    pseudo_headers: &RequestPseudoHeaders,
) -> Result<(), H3Error> {
    if !pseudo_headers.is_connect() {
        return Ok(());
    }

    if pseudo_headers.is_extended_connect() {
        // Extended CONNECT: needs all pseudo-headers
        if pseudo_headers.scheme.is_none() {
            return Err(H3Error::Http("extended CONNECT requires :scheme".into()));
        }
        if pseudo_headers.path.is_none() {
            return Err(H3Error::Http("extended CONNECT requires :path".into()));
        }
        if pseudo_headers.authority.is_none() {
            return Err(H3Error::Http("extended CONNECT requires :authority".into()));
        }
    } else {
        // Standard CONNECT: no :scheme or :path
        if pseudo_headers.scheme.is_some() {
            return Err(H3Error::Http("standard CONNECT MUST NOT have :scheme".into()));
        }
        if pseudo_headers.path.is_some() {
            return Err(H3Error::Http("standard CONNECT MUST NOT have :path".into()));
        }
        if pseudo_headers.authority.is_none() {
            return Err(H3Error::Http("standard CONNECT requires :authority".into()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_connect_validation() {
        let pseudo = RequestPseudoHeaders {
            method: "CONNECT".to_string(),
            scheme: None,
            authority: Some("example.com:443".to_string()),
            path: None,
            protocol: None,
        };

        assert!(validate_connect_request(&pseudo).is_ok());
        
        let tunnel = ConnectTunnel::new(4, &pseudo);
        assert!(tunnel.is_ok());
        let tunnel = tunnel.unwrap();
        assert!(!tunnel.is_extended_connect());
        assert_eq!(tunnel.authority(), "example.com:443");
    }

    #[test]
    fn test_extended_connect_validation() {
        let pseudo = RequestPseudoHeaders {
            method: "CONNECT".to_string(),
            scheme: Some("https".to_string()),
            authority: Some("example.com".to_string()),
            path: Some("/chat".to_string()),
            protocol: Some("websocket".to_string()),
        };

        assert!(validate_connect_request(&pseudo).is_ok());
        
        let tunnel = ConnectTunnel::new(4, &pseudo);
        assert!(tunnel.is_ok());
        let tunnel = tunnel.unwrap();
        assert!(tunnel.is_extended_connect());
        assert_eq!(tunnel.protocol(), Some("websocket"));
    }

    #[test]
    fn test_invalid_standard_connect_with_scheme() {
        let pseudo = RequestPseudoHeaders {
            method: "CONNECT".to_string(),
            scheme: Some("https".to_string()), // Invalid for standard CONNECT
            authority: Some("example.com:443".to_string()),
            path: None,
            protocol: None,
        };

        assert!(validate_connect_request(&pseudo).is_err());
    }

    #[test]
    fn test_tunnel_state_transitions() {
        let pseudo = RequestPseudoHeaders {
            method: "CONNECT".to_string(),
            scheme: None,
            authority: Some("example.com:443".to_string()),
            path: None,
            protocol: None,
        };

        let mut tunnel = ConnectTunnel::new(4, &pseudo).unwrap();
        assert_eq!(tunnel.state(), ConnectState::Pending);

        tunnel.mark_established();
        assert_eq!(tunnel.state(), ConnectState::Established);

        tunnel.mark_closed();
        assert_eq!(tunnel.state(), ConnectState::Closed);
    }

    #[test]
    fn test_frame_validation_after_connect() {
        let pseudo = RequestPseudoHeaders {
            method: "CONNECT".to_string(),
            scheme: None,
            authority: Some("example.com:443".to_string()),
            path: None,
            protocol: None,
        };

        let mut tunnel = ConnectTunnel::new(4, &pseudo).unwrap();
        tunnel.mark_established();

        // DATA frames allowed
        assert!(tunnel.validate_frame_type("DATA").is_ok());

        // Other frames not allowed
        assert!(tunnel.validate_frame_type("HEADERS").is_err());
        assert!(tunnel.validate_frame_type("PRIORITY").is_err());
    }
}
