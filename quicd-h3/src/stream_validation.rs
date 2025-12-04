//! Stream ID validation per RFC 9114 Section 6.
//!
//! QUIC stream IDs have specific parity requirements:
//! - Client-initiated bidirectional: 0x00, 0x04, 0x08, ...  (client-initiated, type 0)
//! - Server-initiated bidirectional: 0x01, 0x05, 0x09, ...  (server-initiated, type 0)
//! - Client-initiated unidirectional: 0x02, 0x06, 0x0A, ... (client-initiated, type 1)
//! - Server-initiated unidirectional: 0x03, 0x07, 0x0B, ... (server-initiated, type 1)

use crate::error::H3Error;

/// Stream initiator (client or server)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInitiator {
    Client,
    Server,
}

/// Stream direction (bidirectional or unidirectional)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    Bidirectional,
    Unidirectional,
}

/// Get the initiator of a stream from its ID
pub fn stream_initiator(stream_id: u64) -> StreamInitiator {
    if stream_id & 0x01 == 0 {
        StreamInitiator::Client
    } else {
        StreamInitiator::Server
    }
}

/// Get the direction of a stream from its ID
pub fn stream_direction(stream_id: u64) -> StreamDirection {
    if stream_id & 0x02 == 0 {
        StreamDirection::Bidirectional
    } else {
        StreamDirection::Unidirectional
    }
}

/// Validate that a bidirectional stream is client-initiated.
///
/// RFC 9114 Section 6.1: "All client-initiated bidirectional streams are used
/// for HTTP requests and responses."
pub fn validate_client_bidirectional_stream(
    stream_id: u64,
    is_server: bool,
) -> Result<(), H3Error> {
    let initiator = stream_initiator(stream_id);
    let direction = stream_direction(stream_id);

    if direction != StreamDirection::Bidirectional {
        return Err(H3Error::Connection(format!(
            "H3_STREAM_CREATION_ERROR: stream {} is unidirectional, expected bidirectional",
            stream_id
        )));
    }

    if is_server && initiator != StreamInitiator::Client {
        return Err(H3Error::Connection(format!(
            "H3_STREAM_CREATION_ERROR: server received server-initiated bidirectional stream {}",
            stream_id
        )));
    }

    if !is_server && initiator != StreamInitiator::Server {
        // Client receiving bidirectional stream from server is not defined in HTTP/3
        return Err(H3Error::Connection(format!(
            "H3_STREAM_CREATION_ERROR: client received server-initiated bidirectional stream {}",
            stream_id
        )));
    }

    Ok(())
}

/// Validate that a unidirectional stream has the correct initiator for its purpose.
///
/// RFC 9114 Section 6.2:
/// - Control streams (type 0x00): Can be initiated by both client and server
/// - Push streams (type 0x01): MUST be server-initiated only
/// - QPACK encoder (type 0x02): Can be initiated by both
/// - QPACK decoder (type 0x03): Can be initiated by both
pub fn validate_unidirectional_stream_initiator(
    stream_id: u64,
    stream_type: u64,
    is_server: bool,
) -> Result<(), H3Error> {
    let direction = stream_direction(stream_id);

    if direction != StreamDirection::Unidirectional {
        return Err(H3Error::Connection(format!(
            "H3_STREAM_CREATION_ERROR: stream {} is bidirectional, expected unidirectional",
            stream_id
        )));
    }

    let initiator = stream_initiator(stream_id);

    match stream_type {
        0x01 => {
            // Push stream - RFC 9114 Section 6.2.2: "Only servers can push"
            if is_server {
                // Server receiving push stream from client
                if initiator == StreamInitiator::Client {
                    return Err(H3Error::Connection(
                        "H3_STREAM_CREATION_ERROR: push stream received by server (only servers can push)".into()
                    ));
                }
            } else {
                // Client receiving push stream from server - this is OK
                if initiator == StreamInitiator::Client {
                    return Err(H3Error::Connection(
                        "H3_STREAM_CREATION_ERROR: client-initiated push stream (only servers can push)".into()
                    ));
                }
            }
        }
        0x00 | 0x02 | 0x03 => {
            // Control, QPACK encoder, QPACK decoder - can be initiated by both
        }
        _ => {
            // Unknown or reserved stream types - no specific validation
        }
    }

    Ok(())
}

/// Check if a stream ID is valid for the current endpoint role.
///
/// RFC 9114 Section 6.1: "HTTP/3 does not use server-initiated bidirectional streams"
pub fn validate_stream_id_role(stream_id: u64, is_server: bool) -> Result<(), H3Error> {
    let initiator = stream_initiator(stream_id);
    let direction = stream_direction(stream_id);

    // RFC 9114 Section 6.1: Server MUST NOT initiate bidirectional streams
    if is_server
        && initiator == StreamInitiator::Server
        && direction == StreamDirection::Bidirectional
    {
        return Err(H3Error::Connection(
            "H3_STREAM_CREATION_ERROR: server attempted to initiate bidirectional stream".into(),
        ));
    }

    // RFC 9114 Section 6.1: Client receiving server-initiated bidirectional stream
    if !is_server
        && initiator == StreamInitiator::Server
        && direction == StreamDirection::Bidirectional
    {
        return Err(H3Error::Connection(
            "H3_STREAM_CREATION_ERROR: received server-initiated bidirectional stream".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_initiator() {
        // Client-initiated bidirectional
        assert_eq!(stream_initiator(0), StreamInitiator::Client);
        assert_eq!(stream_initiator(4), StreamInitiator::Client);

        // Server-initiated bidirectional
        assert_eq!(stream_initiator(1), StreamInitiator::Server);
        assert_eq!(stream_initiator(5), StreamInitiator::Server);

        // Client-initiated unidirectional
        assert_eq!(stream_initiator(2), StreamInitiator::Client);
        assert_eq!(stream_initiator(6), StreamInitiator::Client);

        // Server-initiated unidirectional
        assert_eq!(stream_initiator(3), StreamInitiator::Server);
        assert_eq!(stream_initiator(7), StreamInitiator::Server);
    }

    #[test]
    fn test_stream_direction() {
        // Bidirectional
        assert_eq!(stream_direction(0), StreamDirection::Bidirectional);
        assert_eq!(stream_direction(1), StreamDirection::Bidirectional);
        assert_eq!(stream_direction(4), StreamDirection::Bidirectional);

        // Unidirectional
        assert_eq!(stream_direction(2), StreamDirection::Unidirectional);
        assert_eq!(stream_direction(3), StreamDirection::Unidirectional);
        assert_eq!(stream_direction(6), StreamDirection::Unidirectional);
    }

    #[test]
    fn test_validate_client_bidirectional_stream() {
        // Server receiving client-initiated bidirectional (OK)
        assert!(validate_client_bidirectional_stream(0, true).is_ok());
        assert!(validate_client_bidirectional_stream(4, true).is_ok());

        // Server receiving server-initiated bidirectional (NOT OK)
        assert!(validate_client_bidirectional_stream(1, true).is_err());

        // Server receiving unidirectional (NOT OK)
        assert!(validate_client_bidirectional_stream(2, true).is_err());
    }

    #[test]
    fn test_validate_push_stream_initiator() {
        // Server initiating push stream (OK)
        assert!(validate_unidirectional_stream_initiator(3, 0x01, false).is_ok());

        // Client initiating push stream (NOT OK)
        assert!(validate_unidirectional_stream_initiator(2, 0x01, false).is_err());

        // Server receiving push stream from client (NOT OK)
        assert!(validate_unidirectional_stream_initiator(2, 0x01, true).is_err());
    }
}
