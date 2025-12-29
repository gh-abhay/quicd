//! Unit tests for HTTP message framing and pseudo-header processing.

use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use quicd_h3::message::*;
use quicd_qpack::FieldLine;

#[test]
fn test_parse_request_pseudo_headers_valid() {
    let fields = vec![
        FieldLine::new(":method", "GET"),
        FieldLine::new(":scheme", "https"),
        FieldLine::new(":authority", "example.com"),
        FieldLine::new(":path", "/index.html"),
        FieldLine::new("user-agent", "test-client/1.0"),
        FieldLine::new("accept", "*/*"),
    ];

    let (method, uri, headers) = parse_request_pseudo_headers(&fields).unwrap();

    assert_eq!(method, Method::GET);
    assert_eq!(uri.to_string(), "https://example.com/index.html");
    assert_eq!(headers.len(), 2);
    assert_eq!(&headers[0].name[..], b"user-agent");
    assert_eq!(&headers[1].name[..], b"accept");
}

#[test]
fn test_parse_request_all_methods() {
    let methods = vec![
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH",
    ];

    for method in methods {
        let fields = vec![
            FieldLine::new(":method", method),
            FieldLine::new(":scheme", "https"),
            FieldLine::new(":authority", "example.com"),
            FieldLine::new(":path", "/"),
        ];

        let (parsed_method, _, _) = parse_request_pseudo_headers(&fields).unwrap();
        assert_eq!(
            parsed_method,
            Method::from_bytes(method.as_bytes()).unwrap()
        );
    }
}

#[test]
fn test_parse_request_missing_pseudo_header() {
    // Missing :scheme
    let fields = vec![
        FieldLine::new(":method", "GET"),
        FieldLine::new(":authority", "example.com"),
        FieldLine::new(":path", "/"),
    ];

    let result = parse_request_pseudo_headers(&fields);
    assert!(result.is_err());

    // Missing :path
    let fields = vec![
        FieldLine::new(":method", "GET"),
        FieldLine::new(":scheme", "https"),
        FieldLine::new(":authority", "example.com"),
    ];

    let result = parse_request_pseudo_headers(&fields);
    assert!(result.is_err());
}

#[test]
fn test_parse_request_pseudo_header_after_regular() {
    let fields = vec![
        FieldLine::new(":method", "GET"),
        FieldLine::new(":scheme", "https"),
        FieldLine::new("user-agent", "test"), // Regular header
        FieldLine::new(":authority", "example.com"), // Pseudo after regular - invalid
        FieldLine::new(":path", "/"),
    ];

    let result = parse_request_pseudo_headers(&fields);
    assert!(result.is_err());
}

#[test]
fn test_parse_request_duplicate_pseudo_header() {
    let fields = vec![
        FieldLine::new(":method", "GET"),
        FieldLine::new(":method", "POST"), // Duplicate
        FieldLine::new(":scheme", "https"),
        FieldLine::new(":authority", "example.com"),
        FieldLine::new(":path", "/"),
    ];

    let result = parse_request_pseudo_headers(&fields);
    assert!(result.is_err());
}

#[test]
fn test_parse_request_complex_uri() {
    let fields = vec![
        FieldLine::new(":method", "GET"),
        FieldLine::new(":scheme", "https"),
        FieldLine::new(":authority", "example.com:8443"),
        FieldLine::new(":path", "/api/v1/users?id=123&name=test#section"),
    ];

    let (method, uri, _) = parse_request_pseudo_headers(&fields).unwrap();

    assert_eq!(method, Method::GET);
    assert_eq!(uri.scheme_str(), Some("https"));
    assert_eq!(uri.authority().unwrap().as_str(), "example.com:8443");
    assert_eq!(uri.path(), "/api/v1/users");
    assert_eq!(uri.query(), Some("id=123&name=test"));
}

#[test]
fn test_parse_response_pseudo_headers_valid() {
    let fields = vec![
        FieldLine::new(":status", "200"),
        FieldLine::new("content-type", "text/html"),
        FieldLine::new("content-length", "1234"),
    ];

    let (status, headers) = parse_response_pseudo_headers(&fields).unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.len(), 2);
    assert_eq!(&headers[0].name[..], b"content-type");
    assert_eq!(&headers[1].name[..], b"content-length");
}

#[test]
fn test_parse_response_all_status_codes() {
    let test_cases = vec![
        ("200", StatusCode::OK),
        ("201", StatusCode::CREATED),
        ("204", StatusCode::NO_CONTENT),
        ("301", StatusCode::MOVED_PERMANENTLY),
        ("302", StatusCode::FOUND),
        ("304", StatusCode::NOT_MODIFIED),
        ("400", StatusCode::BAD_REQUEST),
        ("401", StatusCode::UNAUTHORIZED),
        ("403", StatusCode::FORBIDDEN),
        ("404", StatusCode::NOT_FOUND),
        ("500", StatusCode::INTERNAL_SERVER_ERROR),
        ("502", StatusCode::BAD_GATEWAY),
        ("503", StatusCode::SERVICE_UNAVAILABLE),
    ];

    for (status_str, expected) in test_cases {
        let fields = vec![FieldLine::new(":status", status_str)];
        let (status, _) = parse_response_pseudo_headers(&fields).unwrap();
        assert_eq!(status, expected);
    }
}

#[test]
fn test_parse_response_missing_status() {
    let fields = vec![FieldLine::new("content-type", "text/html")];

    let result = parse_response_pseudo_headers(&fields);
    assert!(result.is_err());
}

#[test]
fn test_parse_response_invalid_status() {
    let fields = vec![
        FieldLine::new(":status", "1000"), // Invalid status code (out of range)
    ];

    let result = parse_response_pseudo_headers(&fields);
    assert!(result.is_err());

    let fields = vec![
        FieldLine::new(":status", "abc"), // Not a number
    ];

    let result = parse_response_pseudo_headers(&fields);
    assert!(result.is_err());
}

#[test]
fn test_request_to_field_lines_roundtrip() {
    let request = HttpRequest {
        method: Method::POST,
        uri: Uri::from_static("https://example.com/api/data"),
        headers: vec![
            FieldLine::new("content-type", "application/json"),
            FieldLine::new("content-length", "42"),
        ],
        body: Bytes::from_static(b"{}"),
        trailers: None,
    };

    let fields = request_to_field_lines(&request);

    // Check pseudo-headers are first
    assert_eq!(&fields[0].name[..], b":method");
    assert_eq!(&fields[1].name[..], b":scheme");
    assert_eq!(&fields[2].name[..], b":authority");
    assert_eq!(&fields[3].name[..], b":path");

    // Parse back
    let (method, uri, headers) = parse_request_pseudo_headers(&fields).unwrap();

    assert_eq!(method, request.method);
    assert_eq!(uri, request.uri);
    assert_eq!(headers.len(), request.headers.len());
}

#[test]
fn test_response_to_field_lines_roundtrip() {
    let response = HttpResponse {
        status: StatusCode::CREATED,
        headers: vec![
            FieldLine::new("content-type", "application/json"),
            FieldLine::new("location", "/api/resource/123"),
        ],
        body: Bytes::from_static(b"{\"id\": 123}"),
        trailers: None,
    };

    let fields = response_to_field_lines(&response);

    // Check :status is first
    assert_eq!(&fields[0].name[..], b":status");
    assert_eq!(&fields[0].value[..], b"201");

    // Parse back
    let (status, headers) = parse_response_pseudo_headers(&fields).unwrap();

    assert_eq!(status, response.status);
    assert_eq!(headers.len(), response.headers.len());
}

#[test]
fn test_unknown_pseudo_header() {
    let fields = vec![
        FieldLine::new(":method", "GET"),
        FieldLine::new(":scheme", "https"),
        FieldLine::new(":authority", "example.com"),
        FieldLine::new(":path", "/"),
        FieldLine::new(":unknown", "value"), // Unknown pseudo-header
    ];

    let result = parse_request_pseudo_headers(&fields);
    assert!(result.is_err());
}

#[test]
fn test_empty_pseudo_header_value() {
    let fields = vec![
        FieldLine::new(":method", ""),
        FieldLine::new(":scheme", "https"),
        FieldLine::new(":authority", "example.com"),
        FieldLine::new(":path", "/"),
    ];

    let result = parse_request_pseudo_headers(&fields);
    assert!(result.is_err());
}
