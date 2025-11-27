//! CONNECT method support per RFC 9114 Section 4.4.
//!
//! Implements both standard CONNECT (for TCP tunneling) and extended CONNECT
//! (with :protocol pseudo-header for protocols like WebSocket).

use bytes::Bytes;
use crate::error::H3Error;
use crate::validation::RequestPseudoHeaders;
use tokio::net::TcpStream;

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
    /// TCP connection to target authority
    tcp_stream: Option<TcpStream>,
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
            tcp_stream: None,
        })
    }

    /// Establish the TCP connection to the target authority.
    ///
    /// Per RFC 9114 Section 4.4, the proxy establishes a TCP connection to the
    /// server identified in the :authority pseudo-header field.
    ///
    /// Returns Ok(()) if connection established successfully.
    /// Returns H3Error::ConnectError if TCP connection fails (should be sent as H3_CONNECT_ERROR).
    pub async fn establish_connection(&mut self) -> Result<(), H3Error> {
        if self.state != ConnectState::Pending {
            return Err(H3Error::Http("tunnel not in pending state".into()));
        }

        // Establish TCP connection to authority
        match TcpStream::connect(&self.authority).await {
            Ok(stream) => {
                self.tcp_stream = Some(stream);
                Ok(())
            }
            Err(e) => {
                self.state = ConnectState::Closed;
                Err(H3Error::ConnectError(format!(
                    "failed to connect to {}: {}",
                    self.authority, e
                )))
            }
        }
    }

    /// Get a mutable reference to the TCP stream, if established.
    pub fn tcp_stream_mut(&mut self) -> Option<&mut TcpStream> {
        self.tcp_stream.as_mut()
    }

    /// Take ownership of the TCP stream.
    /// This is used when spawning a forwarding task that needs exclusive access.
    pub fn take_tcp_stream(&mut self) -> Option<TcpStream> {
        self.tcp_stream.take()
    }

    /// Write data to the TCP connection.
    ///
    /// Per RFC 9114 Section 4.4: "The payload of any DATA frame sent by the client
    /// is transmitted by the proxy to the TCP server."
    pub async fn write_to_tcp(&mut self, data: &[u8]) -> Result<(), H3Error> {
        if self.state != ConnectState::Established {
            return Err(H3Error::Http("tunnel not established".into()));
        }

        if let Some(tcp) = &mut self.tcp_stream {
            use tokio::io::AsyncWriteExt;
            tcp.write_all(data).await.map_err(|e| {
                H3Error::ConnectError(format!("TCP write failed: {}", e))
            })?;
            Ok(())
        } else {
            Err(H3Error::Http("no TCP connection".into()))
        }
    }

    /// Read data from the TCP connection.
    ///
    /// Per RFC 9114 Section 4.4: "data received from the TCP server is packaged
    /// into DATA frames by the proxy."
    ///
    /// Returns Some(data) if data was read, None if EOF (FIN received from TCP).
    pub async fn read_from_tcp(&mut self, buf: &mut [u8]) -> Result<Option<usize>, H3Error> {
        if self.state != ConnectState::Established {
            return Err(H3Error::Http("tunnel not established".into()));
        }

        if let Some(tcp) = &mut self.tcp_stream {
            use tokio::io::AsyncReadExt;
            match tcp.read(buf).await {
                Ok(0) => {
                    // EOF - TCP connection closed by peer
                    // Per RFC 9114: "When the proxy receives a packet with the FIN bit set,
                    // it will close the send stream that it sends to the client."
                    Ok(None)
                }
                Ok(n) => Ok(Some(n)),
                Err(e) => {
                    // TCP read error - should abort stream with H3_CONNECT_ERROR
                    Err(H3Error::ConnectError(format!("TCP read failed: {}", e)))
                }
            }
        } else {
            Err(H3Error::Http("no TCP connection".into()))
        }
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

/// Bidirectional TCP<->QUIC forwarding for CONNECT tunnels.
///
/// RFC 9114 Section 4.4: "The payload of any DATA frame sent by the client
/// is transmitted by the proxy to the TCP server; data received from the TCP
/// server is packaged into DATA frames by the proxy."
///
/// This function spawns tasks to forward data in both directions and handles
/// FIN propagation correctly.
pub async fn forward_connect_tunnel(
    mut tcp_stream: TcpStream,
    mut h3_recv_stream: quicd_x::RecvStream,
    h3_send_stream: quicd_x::SendStream,
) -> Result<(), H3Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use crate::frames::H3Frame;
    
    // Split TCP stream for simultaneous read/write
    let (mut tcp_read, mut tcp_write) = tcp_stream.split();
    
    // Task 1: Forward QUIC -> TCP (client to server)
    let quic_to_tcp = async move {
        loop {
            match h3_recv_stream.read().await {
                Ok(Some(quicd_x::StreamData::Data(data))) => {
                    // Parse DATA frames from QUIC stream
                    let mut cursor = 0;
                    while cursor < data.len() {
                        match H3Frame::parse(&data[cursor..]) {
                            Ok((H3Frame::Data { data: payload }, consumed)) => {
                                cursor += consumed;
                                // Write payload to TCP
                                if let Err(e) = tcp_write.write_all(&payload).await {
                                    return Err(H3Error::ConnectError(
                                        format!("TCP write failed: {}", e)
                                    ));
                                }
                            }
                            Ok((_, consumed)) => {
                                // Non-DATA frame - skip (should be validated elsewhere)
                                cursor += consumed;
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        }
                    }
                }
                Ok(Some(quicd_x::StreamData::Fin)) => {
                    // Client sent FIN - close TCP write side
                    let _ = tcp_write.shutdown().await;
                    break;
                }
                Ok(None) => {
                    // Stream closed
                    break;
                }
                Err(e) => {
                    return Err(H3Error::Stream(format!("QUIC read failed: {:?}", e)));
                }
            }
        }
        Ok(())
    };
    
    // Task 2: Forward TCP -> QUIC (server to client)
    let tcp_to_quic = async move {
        let mut buffer = vec![0u8; 16384]; // 16KB buffer for TCP reads
        
        loop {
            match tcp_read.read(&mut buffer).await {
                Ok(0) => {
                    // TCP FIN received - send FIN on QUIC stream
                    if let Err(e) = h3_send_stream.write(Bytes::new(), true).await {
                        return Err(H3Error::Stream(format!("QUIC FIN write failed: {:?}", e)));
                    }
                    break;
                }
                Ok(n) => {
                    // Wrap in DATA frame and send
                    let data_frame = H3Frame::Data {
                        data: Bytes::copy_from_slice(&buffer[..n]),
                    };
                    let frame_data = data_frame.encode();
                    
                    if let Err(e) = h3_send_stream.write(frame_data, false).await {
                        return Err(H3Error::Stream(format!("QUIC write failed: {:?}", e)));
                    }
                }
                Err(e) => {
                    // TCP read error - abort QUIC stream with H3_CONNECT_ERROR
                    return Err(H3Error::ConnectError(format!("TCP read failed: {}", e)));
                }
            }
        }
        Ok(())
    };
    
    // Run both forwarding tasks concurrently
    tokio::select! {
        result = quic_to_tcp => result,
        result = tcp_to_quic => result,
    }
}

/// Validate CONNECT request pseudo-headers.
///
/// Per RFC 9114 Section 4.4:
/// - Standard CONNECT: MUST have :method and :authority, MUST NOT have :scheme and :path
/// - Extended CONNECT: MUST have :method, :protocol, :scheme, :authority, :path
pub fn validate_connect_request(
    pseudo_headers: &RequestPseudoHeaders,
    enable_connect_protocol: bool,
) -> Result<(), H3Error> {
    if !pseudo_headers.is_connect() {
        return Ok(());
    }

    if pseudo_headers.is_extended_connect() {
        // RFC 9114 Section 4.4: Extended CONNECT requires SETTINGS_ENABLE_CONNECT_PROTOCOL
        // "A server MUST treat a CONNECT request with the :protocol pseudo-header field
        // present but the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter set to 0 as a
        // request error of type H3_MESSAGE_ERROR"
        if !enable_connect_protocol {
            return Err(H3Error::MessageError);
        }
        
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

        assert!(validate_connect_request(&pseudo, false).is_ok());
        
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

        // Should succeed when extended CONNECT is enabled
        assert!(validate_connect_request(&pseudo, true).is_ok());
        
        // Should fail when extended CONNECT is disabled
        assert!(matches!(
            validate_connect_request(&pseudo, false),
            Err(H3Error::MessageError)
        ));
        
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

        assert!(validate_connect_request(&pseudo, false).is_err());
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
