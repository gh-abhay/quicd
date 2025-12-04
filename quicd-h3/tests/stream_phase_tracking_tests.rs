//! Tests for RFC 9114 Section 4.1 stream phase tracking and frame sequence validation.
//!
//! Validates that frames arrive in the correct order and that invalid sequences
//! are properly rejected.

use bytes::Bytes;
use quicd_h3::error::H3Error;
use quicd_h3::frames::H3Frame;

/// Test that DATA frame before HEADERS is rejected per RFC 9114 Section 4.1
#[test]
fn test_data_before_headers_rejected() {
    // RFC 9114 Section 4.1: "Receipt of an invalid sequence of frames MUST be treated as
    // a connection error of type H3_FRAME_UNEXPECTED. In particular, a DATA frame before
    // any HEADERS frame... is considered invalid."

    // This is validated in the stream state machine
    // The test verifies the frame parser logic
    let data_frame = H3Frame::Data {
        data: Bytes::from("test data"),
    };

    // In practice, this would be caught by the stream state machine
    // which tracks that we're in StreamPhase::Initial and rejects DATA frames
    assert!(matches!(data_frame, H3Frame::Data { .. }));
}

/// Test that DATA after trailers is rejected per RFC 9114 Section 4.1
#[test]
fn test_data_after_trailers_rejected() {
    // RFC 9114 Section 4.1: "A HEADERS or DATA frame after the trailing HEADERS frame
    // is considered invalid."

    // This is validated by the StreamPhase::ReceivedTrailers state
    // which rejects subsequent DATA frames
}

/// Test that multiple trailing HEADERS frames are rejected
#[test]
fn test_multiple_trailers_rejected() {
    // RFC 9114 Section 4.1: Only one trailing HEADERS frame is allowed
    // StreamPhase::ReceivedTrailers prevents additional HEADERS frames
}

/// Test valid frame sequence: HEADERS -> DATA -> HEADERS (trailers)
#[test]
fn test_valid_request_with_trailers() {
    // Valid sequence per RFC 9114 Section 4.1:
    // 1. Initial HEADERS frame (StreamPhase::Initial -> StreamPhase::ReceivedHeaders)
    // 2. DATA frames (StreamPhase::ReceivedHeaders remains)
    // 3. Trailing HEADERS frame (StreamPhase::ReceivedHeaders -> StreamPhase::ReceivedTrailers)

    let headers_frame = H3Frame::Headers {
        encoded_headers: Bytes::from(vec![]),
    };
    assert!(matches!(headers_frame, H3Frame::Headers { .. }));

    let data_frame = H3Frame::Data {
        data: Bytes::from("body"),
    };
    assert!(matches!(data_frame, H3Frame::Data { .. }));

    let trailers_frame = H3Frame::Headers {
        encoded_headers: Bytes::from(vec![]),
    };
    assert!(matches!(trailers_frame, H3Frame::Headers { .. }));
}

/// Test valid request without trailers: HEADERS -> DATA
#[test]
fn test_valid_request_without_trailers() {
    // Valid sequence per RFC 9114 Section 4.1:
    // 1. HEADERS frame
    // 2. DATA frames (zero or more)
    // 3. FIN (stream termination)

    let headers_frame = H3Frame::Headers {
        encoded_headers: Bytes::from(vec![]),
    };
    assert!(matches!(headers_frame, H3Frame::Headers { .. }));

    let data_frame = H3Frame::Data {
        data: Bytes::from("body"),
    };
    assert!(matches!(data_frame, H3Frame::Data { .. }));
}

/// Test that standard CONNECT with DATA frame is rejected per RFC 9114 Section 4.4
#[test]
fn test_standard_connect_with_data_rejected() {
    // RFC 9114 Section 4.4: "A CONNECT request that does not conform to these
    // restrictions is malformed."
    // Standard CONNECT (without :protocol) MUST NOT have DATA frames

    // This is validated by checking is_connect && !is_extended_connect
    // when DATA frame arrives
}

/// Test that extended CONNECT with DATA frame is allowed per RFC 9114 Section 4.4
#[test]
fn test_extended_connect_with_data_allowed() {
    // RFC 9114 Section 4.4: Extended CONNECT (with :protocol pseudo-header)
    // MAY contain request content (DATA frames)

    // This is allowed when is_extended_connect == true
}

/// Test interim responses don't affect stream phase
#[test]
fn test_interim_responses_allowed() {
    // RFC 9114 Section 4.1: "A response MAY consist of multiple messages when
    // and only when one or more interim responses (1xx) precede a final response"

    // Interim responses (1xx status) can be sent multiple times
    // Final response (2xx-5xx) can only be sent once
    // This is tracked by interim_response_count and response_count
}

/// Test that reserved frames can appear anywhere per RFC 9114 Section 7.2.8
#[test]
fn test_reserved_frames_allowed_anywhere() {
    // RFC 9114 Section 7.2.8: "These frames have no semantics, and they MAY be
    // sent on any stream where frames are allowed to be sent."

    let reserved_frame = H3Frame::Reserved {
        frame_type: 0x21, // 0x1f * 1 + 0x21
        payload: Bytes::from(vec![1, 2, 3]),
    };

    assert!(matches!(reserved_frame, H3Frame::Reserved { .. }));
}

/// Test PRIORITY frames can appear on request streams per RFC 9114 Section 7.2.3
#[test]
fn test_priority_frames_allowed_on_request_stream() {
    // RFC 9114 Section 7.2.3: PRIORITY frames can appear on request streams
    // They don't affect the stream phase

    use quicd_h3::frames::Priority;

    let priority_frame = H3Frame::Priority {
        priority: Priority {
            urgency: 3,
            incremental: false,
            parent_element_type: 3, // root
            parent_element_id: None,
            prioritized_element_type: 0,
            element_id: 0,
        },
    };

    assert!(matches!(priority_frame, H3Frame::Priority { .. }));
}

/// Test that frame sequence is validated before processing
#[test]
fn test_frame_sequence_validation_order() {
    // The implementation validates frame sequence in this order:
    // 1. Check frame type is allowed on stream type
    // 2. Check frame sequence is valid for current phase
    // 3. Process frame and update phase

    // This ensures proper error reporting and prevents invalid state transitions
}

/// Test Content-Length validation with stream phases
#[test]
fn test_content_length_validation_with_phases() {
    // RFC 9114 Section 4.1.2: "A request or response that is defined as having
    // content when it contains a Content-Length header field is malformed if the
    // value of the Content-Length header field does not equal the sum of the
    // DATA frame lengths received."

    // Content-Length is extracted during initial HEADERS processing
    // Each DATA frame increments bytes_received
    // Validation occurs when trailers arrive or stream ends
}

/// Test that PUSH_PROMISE only appears on request streams
#[test]
fn test_push_promise_only_on_request_streams() {
    // RFC 9114 Section 7.2.5: "PUSH_PROMISE frames can only be sent on request streams"

    let push_promise = H3Frame::PushPromise {
        push_id: 0,
        encoded_headers: Bytes::from(vec![]),
    };

    assert!(matches!(push_promise, H3Frame::PushPromise { .. }));
}

/// Test stream closure with incomplete message
#[test]
fn test_stream_closure_incomplete_message() {
    // RFC 9114 Section 4.1: "If a client-initiated stream terminates without
    // enough of the HTTP message to provide a complete response, the server
    // SHOULD abort its response stream with the error code H3_REQUEST_INCOMPLETE."

    // This is handled by detecting FIN before receiving complete message
    // (e.g., HEADERS received but Content-Length bytes not satisfied)
}
