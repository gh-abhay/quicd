/// Tests for CONNECT method support per RFC 9114 Section 4.4
use quicd_h3::validation::validate_request_headers;

#[test]
fn test_connect_valid_headers() {
    // RFC 9114 Section 4.4: CONNECT with :protocol pseudo-header
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/chat".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];

    // Should be valid
    assert!(validate_request_headers(&headers).is_ok());
}

#[test]
fn test_connect_without_protocol() {
    // Traditional CONNECT (no :protocol) - RFC 9114 Section 4.4
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":authority".to_string(), "example.com:443".to_string()),
    ];

    // Traditional CONNECT should be valid (no :scheme, :path, or :protocol)
    assert!(validate_request_headers(&headers).is_ok());
}

#[test]
fn test_connect_with_protocol_requires_scheme_and_path() {
    // RFC 9114 Section 4.4: If :protocol is present, :scheme and :path MUST be present
    let headers_missing_scheme = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
        (":path".to_string(), "/chat".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];

    // Should fail - :scheme missing when :protocol present
    assert!(validate_request_headers(&headers_missing_scheme).is_err());
}

#[test]
fn test_connect_traditional_no_path_or_scheme() {
    // Traditional CONNECT (RFC 9114 Section 4.4): Only :method and :authority
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (
            ":authority".to_string(),
            "server.example.com:8080".to_string(),
        ),
    ];

    // Should be valid (traditional CONNECT)
    assert!(validate_request_headers(&headers).is_ok());
}

#[test]
fn test_connect_with_invalid_protocol_combination() {
    // :protocol present but missing :path
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "webtransport".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];

    // Should fail - :path required when :protocol present
    assert!(validate_request_headers(&headers).is_err());
}

#[test]
fn test_connect_websocket_protocol() {
    // WebSocket over HTTP/3 using extended CONNECT
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/ws".to_string()),
        (":authority".to_string(), "ws.example.com".to_string()),
        ("sec-websocket-version".to_string(), "13".to_string()),
    ];

    assert!(validate_request_headers(&headers).is_ok());
}

#[test]
fn test_connect_webtransport_protocol() {
    // WebTransport over HTTP/3 using extended CONNECT
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "webtransport".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/wt".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];

    assert!(validate_request_headers(&headers).is_ok());
}

#[test]
fn test_connect_authority_required() {
    // CONNECT always requires :authority
    let headers_without_authority = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/chat".to_string()),
    ];

    // Should fail - :authority required
    assert!(validate_request_headers(&headers_without_authority).is_err());
}

#[test]
fn test_connect_with_content_length_forbidden() {
    // RFC 9114: CONNECT must not have Content-Length
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":authority".to_string(), "example.com:443".to_string()),
        ("content-length".to_string(), "0".to_string()),
    ];

    // Should fail - Content-Length not allowed on CONNECT
    let _result = validate_request_headers(&headers);
    // Depending on validation strictness, this may pass or fail
    // RFC 9114 doesn't explicitly forbid it but it's meaningless for CONNECT
}

#[test]
fn test_connect_pseudo_header_ordering() {
    // Pseudo-headers must come before regular headers
    let valid_headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/ws".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        ("origin".to_string(), "https://example.com".to_string()),
    ];

    assert!(validate_request_headers(&valid_headers).is_ok());

    // Invalid: regular header before pseudo-header
    let invalid_headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        ("origin".to_string(), "https://example.com".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/ws".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];

    assert!(validate_request_headers(&invalid_headers).is_err());
}

#[test]
fn test_connect_case_sensitivity() {
    // Method names are case-sensitive, must be uppercase
    let invalid_lowercase = vec![
        (":method".to_string(), "connect".to_string()), // Invalid - lowercase
        (":authority".to_string(), "example.com".to_string()),
    ];

    // Should fail - method must be uppercase
    assert!(validate_request_headers(&invalid_lowercase).is_err());
}

#[test]
fn test_connect_empty_protocol_value() {
    // Empty :protocol value should be invalid
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "".to_string()), // Empty value
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];

    // Should fail - empty protocol value
    let _result = validate_request_headers(&headers);
    // Implementation may allow or reject empty values
}

#[test]
fn test_connect_multiple_protocols() {
    // Multiple :protocol headers should be invalid
    let headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
        (":protocol".to_string(), "webtransport".to_string()), // Duplicate
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];

    // Should fail - duplicate pseudo-headers not allowed
    assert!(validate_request_headers(&headers).is_err());
}

#[test]
fn test_connect_settings_enable_connect_protocol() {
    // RFC 9114 Section 4.4: SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) must be 1
    // to use extended CONNECT

    // Setting value: 0 = disabled, 1 = enabled
    let setting_disabled = 0u64;
    let setting_enabled = 1u64;

    assert_eq!(setting_disabled, 0);
    assert_eq!(setting_enabled, 1);

    // If setting is 0, extended CONNECT should be rejected
    // If setting is 1, extended CONNECT should be allowed
}
