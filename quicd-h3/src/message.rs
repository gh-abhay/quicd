//! HTTP message framing and pseudo-header processing per RFC 9114 Section 4.
//!
//! This module handles:
//! - HTTP request/response message framing on bidirectional streams
//! - Pseudo-header field validation and processing (:method, :path, :status, etc.)
//! - Message state machine tracking (awaiting headers, receiving body, complete, etc.)

use bytes::Bytes;
use http::{Method, StatusCode, Uri};
use quicd_qpack::FieldLine;
use std::str::FromStr;

use crate::error::{Error, ErrorCode, Result};

/// HTTP request message.
///
/// Represents a complete HTTP request with method, URI, headers, and body.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: Method,
    /// Request URI
    pub uri: Uri,
    /// HTTP headers (field lines without pseudo-headers)
    pub headers: Vec<FieldLine>,
    /// Request body (may be empty)
    pub body: Bytes,
    /// Optional trailers
    pub trailers: Option<Vec<FieldLine>>,
}

/// HTTP response message.
///
/// Represents a complete HTTP response with status, headers, and body.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: StatusCode,
    /// HTTP headers (field lines without pseudo-headers)
    pub headers: Vec<FieldLine>,
    /// Response body (may be empty)
    pub body: Bytes,
    /// Optional trailers
    pub trailers: Option<Vec<FieldLine>>,
}

impl HttpResponse {
    /// Create a simple response with status and body.
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            trailers: None,
        }
    }

    /// Add a header to the response.
    pub fn with_header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.headers.push(FieldLine::new(name, value));
        self
    }
}

/// HTTP message state machine for tracking message parsing progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageState {
    /// Awaiting HEADERS frame with pseudo-headers and initial headers.
    AwaitingHeaders,
    /// Receiving DATA frames (body content).
    ReceivingBody,
    /// Awaiting optional trailing HEADERS frame.
    AwaitingTrailers,
    /// Message is complete.
    Complete,
    /// Message encountered an error.
    Error,
}

/// Validate and extract pseudo-headers from a field section for HTTP request.
///
/// Per RFC 9114 Section 4.3:
/// - Request pseudo-headers: :method, :scheme, :authority, :path (all required for http/https)
/// - Pseudo-headers MUST appear before regular headers
/// - Unknown pseudo-headers cause connection error
///
/// Returns (method, uri, regular_headers).
pub fn parse_request_pseudo_headers(fields: &[FieldLine]) -> Result<(Method, Uri, Vec<FieldLine>)> {
    let mut method: Option<String> = None;
    let mut scheme: Option<String> = None;
    let mut authority: Option<String> = None;
    let mut path: Option<String> = None;
    let mut regular_headers = Vec::new();
    let mut saw_regular_header = false;

    for field in fields {
        let name = std::str::from_utf8(&field.name)
            .map_err(|_| Error::protocol(ErrorCode::MessageError, "invalid field name encoding"))?;

        if name.starts_with(':') {
            // Pseudo-header
            if saw_regular_header {
                return Err(Error::protocol(
                    ErrorCode::MessageError,
                    "pseudo-header after regular header",
                ));
            }

            let value = std::str::from_utf8(&field.value)
                .map_err(|_| Error::protocol(ErrorCode::MessageError, "invalid field value encoding"))?;

            match name {
                ":method" => {
                    if method.is_some() {
                        return Err(Error::protocol(
                            ErrorCode::MessageError,
                            "duplicate :method pseudo-header",
                        ));
                    }
                    method = Some(value.to_string());
                }
                ":scheme" => {
                    if scheme.is_some() {
                        return Err(Error::protocol(
                            ErrorCode::MessageError,
                            "duplicate :scheme pseudo-header",
                        ));
                    }
                    scheme = Some(value.to_string());
                }
                ":authority" => {
                    if authority.is_some() {
                        return Err(Error::protocol(
                            ErrorCode::MessageError,
                            "duplicate :authority pseudo-header",
                        ));
                    }
                    authority = Some(value.to_string());
                }
                ":path" => {
                    if path.is_some() {
                        return Err(Error::protocol(
                            ErrorCode::MessageError,
                            "duplicate :path pseudo-header",
                        ));
                    }
                    path = Some(value.to_string());
                }
                _ => {
                    return Err(Error::protocol(
                        ErrorCode::MessageError,
                        format!("unknown pseudo-header: {}", name),
                    ));
                }
            }
        } else {
            // Regular header
            saw_regular_header = true;
            regular_headers.push(field.clone());
        }
    }

    // Validate required pseudo-headers
    let method_str = method.ok_or_else(|| {
        Error::protocol(ErrorCode::MessageError, "missing :method pseudo-header")
    })?;

    let scheme_str = scheme.ok_or_else(|| {
        Error::protocol(ErrorCode::MessageError, "missing :scheme pseudo-header")
    })?;

    let authority_str = authority.ok_or_else(|| {
        Error::protocol(ErrorCode::MessageError, "missing :authority pseudo-header")
    })?;

    let path_str = path.ok_or_else(|| {
        Error::protocol(ErrorCode::MessageError, "missing :path pseudo-header")
    })?;

    // Parse method
    let method = Method::from_str(&method_str).map_err(|_| {
        Error::protocol(
            ErrorCode::MessageError,
            format!("invalid method: {}", method_str),
        )
    })?;

    // Construct URI from components
    let uri_str = format!("{}://{}{}", scheme_str, authority_str, path_str);
    let uri = Uri::from_str(&uri_str).map_err(|e| {
        Error::protocol(
            ErrorCode::MessageError,
            format!("invalid URI: {}", e),
        )
    })?;

    Ok((method, uri, regular_headers))
}

/// Validate and extract pseudo-headers from a field section for HTTP response.
///
/// Per RFC 9114 Section 4.3:
/// - Response pseudo-header: :status (required)
/// - Must appear before regular headers
///
/// Returns (status, regular_headers).
pub fn parse_response_pseudo_headers(fields: &[FieldLine]) -> Result<(StatusCode, Vec<FieldLine>)> {
    let mut status: Option<StatusCode> = None;
    let mut regular_headers = Vec::new();
    let mut saw_regular_header = false;

    for field in fields {
        let name = std::str::from_utf8(&field.name)
            .map_err(|_| Error::protocol(ErrorCode::MessageError, "invalid field name encoding"))?;

        if name.starts_with(':') {
            // Pseudo-header
            if saw_regular_header {
                return Err(Error::protocol(
                    ErrorCode::MessageError,
                    "pseudo-header after regular header",
                ));
            }

            let value = std::str::from_utf8(&field.value)
                .map_err(|_| Error::protocol(ErrorCode::MessageError, "invalid field value encoding"))?;

            match name {
                ":status" => {
                    if status.is_some() {
                        return Err(Error::protocol(
                            ErrorCode::MessageError,
                            "duplicate :status pseudo-header",
                        ));
                    }

                    let status_code = value.parse::<u16>().map_err(|_| {
                        Error::protocol(
                            ErrorCode::MessageError,
                            format!("invalid status code: {}", value),
                        )
                    })?;

                    status = Some(StatusCode::from_u16(status_code).map_err(|_| {
                        Error::protocol(
                            ErrorCode::MessageError,
                            format!("invalid status code: {}", status_code),
                        )
                    })?);
                }
                _ => {
                    return Err(Error::protocol(
                        ErrorCode::MessageError,
                        format!("unknown pseudo-header: {}", name),
                    ));
                }
            }
        } else {
            // Regular header
            saw_regular_header = true;
            regular_headers.push(field.clone());
        }
    }

    let status = status.ok_or_else(|| {
        Error::protocol(ErrorCode::MessageError, "missing :status pseudo-header")
    })?;

    Ok((status, regular_headers))
}

/// Convert HTTP request to field lines with pseudo-headers.
///
/// Generates the field section for encoding via QPACK.
/// Pseudo-headers appear first, followed by regular headers.
pub fn request_to_field_lines(request: &HttpRequest) -> Vec<FieldLine> {
    let mut fields = Vec::new();

    // Pseudo-headers first
    fields.push(FieldLine::new(
        Bytes::from_static(b":method"),
        Bytes::copy_from_slice(request.method.as_str().as_bytes()),
    ));
    fields.push(FieldLine::new(
        Bytes::from_static(b":scheme"),
        Bytes::copy_from_slice(
            request
                .uri
                .scheme_str()
                .unwrap_or("https")
                .as_bytes(),
        ),
    ));
    fields.push(FieldLine::new(
        Bytes::from_static(b":authority"),
        Bytes::copy_from_slice(
            request
                .uri
                .authority()
                .map(|a| a.as_str())
                .unwrap_or("")
                .as_bytes(),
        ),
    ));
    fields.push(FieldLine::new(
        Bytes::from_static(b":path"),
        Bytes::copy_from_slice(
            request
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .as_bytes(),
        ),
    ));

    // Regular headers
    fields.extend(request.headers.iter().cloned());

    fields
}

/// Convert HTTP response to field lines with pseudo-headers.
pub fn response_to_field_lines(response: &HttpResponse) -> Vec<FieldLine> {
    let mut fields = Vec::new();

    // Pseudo-header first
    fields.push(FieldLine::new(
        Bytes::from_static(b":status"),
        Bytes::copy_from_slice(response.status.as_str().as_bytes()),
    ));

    // Regular headers
    fields.extend(response.headers.iter().cloned());

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_pseudo_headers() {
        let fields = vec![
            FieldLine::new(":method", "GET"),
            FieldLine::new(":scheme", "https"),
            FieldLine::new(":authority", "example.com"),
            FieldLine::new(":path", "/index.html"),
            FieldLine::new("user-agent", "test"),
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
    fn test_missing_pseudo_header() {
        let fields = vec![
            FieldLine::new(":method", "GET"),
            // Missing :scheme
            FieldLine::new(":authority", "example.com"),
            FieldLine::new(":path", "/"),
        ];

        let result = parse_request_pseudo_headers(&fields);
        assert!(result.is_err());
    }

    #[test]
    fn test_pseudo_header_after_regular() {
        let fields = vec![
            FieldLine::new(":method", "GET"),
            FieldLine::new(":scheme", "https"),
            FieldLine::new("user-agent", "test"),
            FieldLine::new(":authority", "example.com"), // Pseudo after regular - invalid
            FieldLine::new(":path", "/"),
        ];

        let result = parse_request_pseudo_headers(&fields);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_response_pseudo_headers() {
        let fields = vec![
            FieldLine::new(":status", "200"),
            FieldLine::new("content-type", "text/html"),
            FieldLine::new("content-length", "1234"),
        ];

        let (status, headers) = parse_response_pseudo_headers(&fields).unwrap();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.len(), 2);
        assert_eq!(&headers[0].name[..], b"content-type");
    }

    #[test]
    fn test_request_roundtrip() {
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
        let (method, uri, headers) = parse_request_pseudo_headers(&fields).unwrap();

        assert_eq!(method, request.method);
        assert_eq!(uri, request.uri);
        assert_eq!(headers, request.headers);
    }
}
