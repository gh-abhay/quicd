//! HTTP/3 message validation per RFC 9114.
//!
//! This module implements validation for HTTP/3 messages including
//! pseudo-header validation, field name validation, and malformed message detection.

use crate::error::H3Error;
use http::Method;

/// RFC 9110 Section 9.1: HTTP method token validation
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / 
///         "0"-"9" / "A"-"Z" / "^" / "_" / "`" / "a"-"z" / "|" / "~"
fn is_valid_method(method: &str) -> bool {
    if method.is_empty() {
        return false;
    }
    method.chars().all(|c| {
        c.is_ascii_alphanumeric() 
        || matches!(c, '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~')
    })
}

/// RFC 3986 Section 3.1: Scheme validation
/// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
fn is_valid_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {},
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Validate pseudo-headers and regular headers for an HTTP/3 request.
///
/// RFC 9114 Section 4.3: Validates that:
/// - All required pseudo-headers are present
/// - Pseudo-headers appear before regular headers
/// - No uppercase characters in field names
/// - No prohibited headers (Connection, etc.)
/// - Pseudo-header values are valid
pub fn validate_request_headers(headers: &[(String, String)]) -> Result<RequestPseudoHeaders, H3Error> {
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;
    let mut protocol = None; // For extended CONNECT
    let mut seen_regular_header = false;
    let mut has_te_header = false;
    let mut te_value = String::new();

    for (name, value) in headers {
        // RFC 9114 Section 4.2: Field names MUST be lowercase
        if name.chars().any(|c| c.is_uppercase()) {
            return Err(H3Error::Http(format!(
                "field name contains uppercase characters: {}",
                name
            )));
        }

        // RFC 9114 Section 10.3 & Section 4.1.2: Field values MUST NOT contain
        // invalid characters (CR, LF, NUL) that could enable attacks
        // "carriage return (ASCII 0x0d), line feed (ASCII 0x0a), and the null
        // character (ASCII 0x00) might be exploited by an attacker"
        if value.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err(H3Error::Http(format!(
                "field value contains invalid characters (CR/LF/NUL): {} = {}",
                name, value
            )));
        }

        // RFC 9114 Section 4.2: Connection-specific headers MUST NOT be present
        // "An endpoint MUST NOT generate an HTTP/3 field section containing
        // connection-specific fields"
        match name.as_str() {
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" => {
                return Err(H3Error::Http(format!(
                    "connection-specific header not allowed: {}",
                    name
                )));
            }
            "te" => {
                // RFC 9114 Section 4.2: TE header MAY be present but MUST NOT
                // contain any value other than "trailers"
                has_te_header = true;
                te_value = value.to_lowercase();
            }
            _ => {}
        }

        if name.starts_with(':') {
            // Pseudo-header field
            if seen_regular_header {
                return Err(H3Error::Http(
                    "pseudo-header field after regular header field".into()
                ));
            }

            match name.as_str() {
                ":method" => {
                    if method.is_some() {
                        return Err(H3Error::Http("duplicate :method pseudo-header".into()));
                    }
                    // RFC 9114 Section 4.3.1: Validate method is non-empty and valid token
                    if value.is_empty() || !is_valid_method(value) {
                        return Err(H3Error::Http(format!("invalid :method value: {}", value)));
                    }
                    method = Some(value.clone());
                }
                ":scheme" => {
                    if scheme.is_some() {
                        return Err(H3Error::Http("duplicate :scheme pseudo-header".into()));
                    }
                    // RFC 9114 Section 4.3.1: Validate scheme format
                    if value.is_empty() || !is_valid_scheme(value) {
                        return Err(H3Error::Http(format!("invalid :scheme value: {}", value)));
                    }
                    scheme = Some(value.clone());
                }
                ":authority" => {
                    if authority.is_some() {
                        return Err(H3Error::Http("duplicate :authority pseudo-header".into()));
                    }
                    // RFC 9114 Section 4.3.1: Authority MUST NOT include deprecated userinfo
                    if value.contains('@') {
                        return Err(H3Error::Http(
                            ":authority must not include userinfo subcomponent".into()
                        ));
                    }
                    // RFC 3986 Section 3.2.2: Validate IPv6 literals in authority
                    // IPv6 addresses must be enclosed in brackets: [::1]:8080
                    if value.contains(':') && !value.starts_with('[') {
                        // Multiple colons without brackets - likely malformed IPv6 or invalid
                        let colon_count = value.matches(':').count();
                        if colon_count > 1 {
                            return Err(H3Error::Http(
                                ":authority contains IPv6 address not enclosed in brackets".into()
                            ));
                        }
                        // Single colon is valid for host:port
                    }
                    authority = Some(value.clone());
                }
                ":path" => {
                    if path.is_some() {
                        return Err(H3Error::Http("duplicate :path pseudo-header".into()));
                    }
                    // RFC 9114 Section 4.3.1: Path MUST NOT be empty for http/https
                    // (will be validated after we know the scheme)
                    path = Some(value.clone());
                }
                ":protocol" => {
                    // Extended CONNECT per RFC 9114 Section 4.4
                    if protocol.is_some() {
                        return Err(H3Error::Http("duplicate :protocol pseudo-header".into()));
                    }
                    protocol = Some(value.clone());
                }
                _ => {
                    return Err(H3Error::Http(format!(
                        "unknown pseudo-header field: {}",
                        name
                    )));
                }
            }
        } else {
            seen_regular_header = true;

            // RFC 9114 Section 4.2: Connection-specific fields MUST NOT be present
            if name == "connection" || name == "keep-alive" || name == "proxy-connection"
                || name == "transfer-encoding" {
                return Err(H3Error::Http(format!(
                    "connection-specific header field not allowed: {}",
                    name
                )));
            }

            // RFC 9114 Section 4.5: HTTP/3 does not support Upgrade
            if name == "upgrade" {
                return Err(H3Error::Http(
                    "Upgrade header field not allowed in HTTP/3".into()
                ));
            }

            // TE header field is allowed but MUST NOT contain anything other than "trailers"
            if name == "te" && value != "trailers" {
                return Err(H3Error::Http(
                    "TE header field MUST only contain 'trailers'".into()
                ));
            }
        }
    }
    
    // RFC 9114 Section 4.2: Validate TE header if present
    if has_te_header && te_value != "trailers" {
        return Err(H3Error::Http(
            "TE header field MUST only contain 'trailers'".into()
        ));
    }
    
    // Phase 3: Validate Content-Length is not duplicated (RFC 9110 Section 8.6)
    validate_content_length_uniqueness(headers)?;

    // Determine if this is a CONNECT request
    let is_connect = method.as_ref().map(|m| m == "CONNECT").unwrap_or(false);
    let is_extended_connect = is_connect && protocol.is_some();

    // Validate required pseudo-headers per RFC 9114 Section 4.3.1
    if is_connect && !is_extended_connect {
        // Standard CONNECT: MUST have :method and :authority, MUST NOT have :scheme and :path
        if method.is_none() {
            return Err(H3Error::Http("missing :method pseudo-header".into()));
        }
        if authority.is_none() {
            return Err(H3Error::Http("CONNECT request MUST have :authority".into()));
        }
        if scheme.is_some() {
            return Err(H3Error::Http("CONNECT request MUST NOT have :scheme".into()));
        }
        if path.is_some() {
            return Err(H3Error::Http("CONNECT request MUST NOT have :path".into()));
        }
    } else {
        // Normal request or extended CONNECT: MUST have :method, :scheme, :path
        if method.is_none() {
            return Err(H3Error::Http("missing :method pseudo-header".into()));
        }
        if scheme.is_none() {
            return Err(H3Error::Http("missing :scheme pseudo-header".into()));
        }
        if path.is_none() {
            return Err(H3Error::Http("missing :path pseudo-header".into()));
        }

        // For schemes with mandatory authority (http, https), validate authority or Host
        let scheme_val = scheme.as_ref().unwrap();
        if scheme_val == "http" || scheme_val == "https" {
            let has_authority = authority.is_some();
            let has_host = headers.iter().any(|(n, _)| n == "host");
            
            if !has_authority && !has_host {
                return Err(H3Error::Http(
                    "missing :authority or Host header for http/https scheme".into()
                ));
            }

            // If both present, they MUST match
            if has_authority && has_host {
                let host_value = headers.iter()
                    .find(|(n, _)| n == "host")
                    .map(|(_, v)| v)
                    .unwrap();
                
                if authority.as_ref().unwrap() != host_value {
                    return Err(H3Error::Http(
                        ":authority and Host header values do not match".into()
                    ));
                }
            }

            // MUST NOT be empty
            if let Some(auth) = &authority {
                if auth.is_empty() {
                    return Err(H3Error::Http(":authority MUST NOT be empty".into()));
                }
            }
        }

        // :path MUST NOT be empty for http/https
        if let Some(p) = &path {
            if p.is_empty() && (scheme.as_ref().unwrap() == "http" || scheme.as_ref().unwrap() == "https") {
                return Err(H3Error::Http(":path MUST NOT be empty for http/https".into()));
            }
        }
    }

    Ok(RequestPseudoHeaders {
        method: method.unwrap(),
        scheme,
        authority,
        path,
        protocol,
    })
}

/// Validate response pseudo-headers per RFC 9114 Section 4.3.2.
pub fn validate_response_headers(headers: &[(String, String)]) -> Result<u16, H3Error> {
    let mut status = None;
    let mut seen_regular_header = false;

    for (name, value) in headers {
        // RFC 9114 Section 4.2: Field names MUST be lowercase
        if name.chars().any(|c| c.is_uppercase()) {
            return Err(H3Error::Http(format!(
                "field name contains uppercase characters: {}",
                name
            )));
        }

        if name.starts_with(':') {
            if seen_regular_header {
                return Err(H3Error::Http(
                    "pseudo-header field after regular header field".into()
                ));
            }

            if name == ":status" {
                if status.is_some() {
                    return Err(H3Error::Http("duplicate :status pseudo-header".into()));
                }
                status = Some(value.parse::<u16>().map_err(|_| {
                    H3Error::Http(format!("invalid :status value: {}", value))
                })?);
            } else {
                return Err(H3Error::Http(format!(
                    "unknown response pseudo-header: {}",
                    name
                )));
            }
        } else {
            seen_regular_header = true;

            // Same connection-specific field checks
            if name == "connection" || name == "keep-alive" || name == "proxy-connection"
                || name == "transfer-encoding" || name == "upgrade" {
                return Err(H3Error::Http(format!(
                    "connection-specific header field not allowed: {}",
                    name
                )));
            }
        }
    }

    status.ok_or_else(|| H3Error::Http("missing :status pseudo-header".into()))
}

/// Validated pseudo-headers from a request.
#[derive(Debug, Clone)]
pub struct RequestPseudoHeaders {
    pub method: String,
    pub scheme: Option<String>,
    pub authority: Option<String>,
    pub path: Option<String>,
    pub protocol: Option<String>, // For extended CONNECT
}

impl RequestPseudoHeaders {
    /// Check if this is a CONNECT request.
    pub fn is_connect(&self) -> bool {
        self.method == "CONNECT"
    }

    /// Check if this is an extended CONNECT request.
    pub fn is_extended_connect(&self) -> bool {
        self.is_connect() && self.protocol.is_some()
    }

    /// Parse into http::Method.
    pub fn parse_method(&self) -> Result<Method, H3Error> {
        self.method.parse()
            .map_err(|_| H3Error::Http(format!("invalid method: {}", self.method)))
    }

    /// Construct URI for non-CONNECT requests.
    pub fn construct_uri(&self) -> Result<http::Uri, H3Error> {
        if self.is_connect() && !self.is_extended_connect() {
            // Standard CONNECT doesn't have a URI
            return Err(H3Error::Http("CONNECT request has no URI".into()));
        }

        let scheme = self.scheme.as_ref()
            .ok_or_else(|| H3Error::Http("missing scheme for URI".into()))?;
        let authority = self.authority.as_ref()
            .ok_or_else(|| H3Error::Http("missing authority for URI".into()))?;
        let path = self.path.as_ref()
            .ok_or_else(|| H3Error::Http("missing path for URI".into()))?;

        let uri_string = format!("{}://{}{}", scheme, authority, path);
        uri_string.parse()
            .map_err(|_| H3Error::Http(format!("invalid URI construction: {}", uri_string)))
    }
}

/// Phase 3: Validate Content-Length header uniqueness (RFC 9110 Section 8.6)
/// 
/// RFC 9110 Section 8.6: "If a message is received that has multiple Content-Length
/// header fields with field values consisting of the same decimal value, or a single
/// Content-Length header field with a field value containing a list of identical
/// decimal values (e.g., 'Content-Length: 42, 42'), indicating that duplicate
/// Content-Length header fields have been generated or combined by an upstream
/// message processor, then the recipient MUST either reject the message as invalid
/// or replace the duplicate field-values with a single valid Content-Length field
/// value prior to processing."
///
/// We choose to reject for safety.
pub fn validate_content_length_uniqueness(headers: &[(String, String)]) -> Result<(), H3Error> {
    let mut content_length_count = 0;
    
    for (name, _value) in headers {
        // RFC 9110: Header names are case-insensitive
        if name.eq_ignore_ascii_case("content-length") {
            content_length_count += 1;
            // RFC 9110 Section 8.6: Reject ANY multiple Content-Length headers
            if content_length_count > 1 {
                return Err(H3Error::Http("Request contains multiple Content-Length headers".to_string()));
            }
        }
    }
    
    Ok(())
}

/// Calculate the size of a field section per RFC 9114 Section 4.2.2.
///
/// Size is the sum of:
/// - Length of uncompressed name in bytes
/// - Length of uncompressed value in bytes  
/// - 32 bytes of overhead per field
pub fn calculate_field_section_size(headers: &[(String, String)]) -> usize {
    headers.iter()
        .map(|(name, value)| name.len() + value.len() + 32)
        .sum()
}

/// Validate field section size against limit.
pub fn validate_field_section_size(
    headers: &[(String, String)],
    max_size: u64,
) -> Result<(), H3Error> {
    if max_size == 0 {
        // 0 means unlimited
        return Ok(());
    }

    let size = calculate_field_section_size(headers);
    if size as u64 > max_size {
        return Err(H3Error::Http(format!(
            "field section size {} exceeds limit {}",
            size, max_size
        )));
    }

    Ok(())
}

/// Validate trailer headers per RFC 9114 Section 4.1.
///
/// RFC 9114 specifies that:
/// - Trailers MUST NOT contain pseudo-headers
/// - Trailers follow the same field name/value rules as headers
/// - Trailers MUST NOT contain certain headers (e.g., Content-Length, Transfer-Encoding)
/// - Trailers MUST NOT duplicate header names
/// - Trailers size is subject to SETTINGS_MAX_FIELD_SECTION_SIZE
pub fn validate_trailer_headers(trailers: &[(String, String)]) -> Result<(), H3Error> {
    use std::collections::HashSet;
    let mut seen_names = HashSet::new();
    
    for (name, value) in trailers {
        // RFC 9114 Section 4.3: Pseudo-header fields MUST NOT appear in trailer sections
        if name.starts_with(':') {
            return Err(H3Error::Http(format!(
                "H3_MESSAGE_ERROR: pseudo-header not allowed in trailers: {}",
                name
            )));
        }

        // RFC 9114 Section 4.2: Field names MUST be lowercase
        if name.chars().any(|c| c.is_uppercase()) {
            return Err(H3Error::Http(format!(
                "H3_MESSAGE_ERROR: field name contains uppercase characters: {}",
                name
            )));
        }

        // RFC 9114 Section 10.3: Field values MUST NOT contain invalid characters
        if value.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err(H3Error::Http(format!(
                "H3_MESSAGE_ERROR: field value contains invalid characters (CR/LF/NUL): {} = {}",
                name, value
            )));
        }
        
        // ISSUE FIX #2: RFC 9110 Section 6.5: Trailers MUST NOT duplicate header names
        // Header names are case-insensitive
        let name_lower = name.to_lowercase();
        if !seen_names.insert(name_lower) {
            return Err(H3Error::Http(format!(
                "H3_MESSAGE_ERROR: Duplicate trailer field name: {}",
                name
            )));
        }

        // RFC 9110 Section 6.5: Certain headers MUST NOT appear in trailers
        match name.as_str() {
            "content-length" | "content-encoding" | "content-type" | 
            "content-range" | "trailer" | "transfer-encoding" |
            "authorization" | "set-cookie" | "content-disposition" |
            "host" | "cache-control" | "max-forwards" | "te" | "www-authenticate" => {
                return Err(H3Error::Http(format!(
                    "H3_MESSAGE_ERROR: header not allowed in trailers: {}",
                    name
                )));
            }
            _ => {}
        }
    }

    Ok(())
}

/// Validate trailer field section size against limit.
/// This should be called in addition to validate_trailer_headers.
pub fn validate_trailer_section_size(
    trailers: &[(String, String)],
    max_size: u64,
) -> Result<(), H3Error> {
    if max_size == 0 {
        // 0 means unlimited
        return Ok(());
    }

    let size = calculate_field_section_size(trailers);
    if size as u64 > max_size {
        return Err(H3Error::Http(format!(
            "H3_MESSAGE_ERROR: Trailer section size {} exceeds maximum {}",
            size, max_size
        )));
    }
    
    Ok(())
}

/// Validate that interim responses (1xx) don't contain certain headers.
///
/// RFC 9114 Section 4.1: Interim responses cannot contain content or trailers.
/// RFC 9110 Section 15.2: "A 1xx response never contains content or trailers."
pub fn validate_interim_response_headers(headers: &[(String, String)]) -> Result<(), H3Error> {
    for (name, _value) in headers {
        // RFC 9110 Section 15.2: 1xx responses MUST NOT contain:
        // - Content-Length
        // - Transfer-Encoding (already banned in HTTP/3)
        // - Any representation metadata
        match name.as_str() {
            "content-length" | "content-type" | "content-encoding" | 
            "content-language" | "content-location" | "content-range" | "trailer" => {
                return Err(H3Error::Http(format!(
                    "H3_MESSAGE_ERROR: header '{}' not allowed in interim (1xx) response",
                    name
                )));
            }
            _ => {}
        }
    }

    Ok(())
}

/// Validate response headers based on status code.
///
/// RFC 9110 imposes different requirements for different status codes:
/// - 1xx: No content/trailers (handled by validate_interim_response_headers)
/// - 204 No Content: MUST NOT contain Content-Length or content
/// - 304 Not Modified: MUST NOT contain Content-Length or content
/// - 2xx for CONNECT: MUST NOT contain Content-Length
pub fn validate_response_headers_for_status(status: u16, headers: &[(String, String)]) -> Result<(), H3Error> {
    match status {
        // RFC 9110 Section 15.3.5: 204 No Content
        204 => {
            for (name, _) in headers {
                if name == "content-length" {
                    return Err(H3Error::Http(
                        "H3_MESSAGE_ERROR: 204 No Content MUST NOT contain Content-Length".into()
                    ));
                }
            }
        }
        // RFC 9110 Section 15.4.5: 304 Not Modified
        304 => {
            for (name, _) in headers {
                if name == "content-length" {
                    return Err(H3Error::Http(
                        "H3_MESSAGE_ERROR: 304 Not Modified MUST NOT contain Content-Length".into()
                    ));
                }
            }
        }
        _ => {}
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_request() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ];

        let result = validate_request_headers(&headers);
        assert!(result.is_ok());
        let pseudo = result.unwrap();
        assert_eq!(pseudo.method, "GET");
        assert_eq!(pseudo.scheme.as_deref(), Some("https"));
    }

    #[test]
    fn test_uppercase_field_name_rejected() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ];

        let result = validate_request_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_pseudo_header_after_regular_rejected() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            ("accept".to_string(), "*/*".to_string()),
            (":path".to_string(), "/".to_string()), // This should fail
        ];

        let result = validate_request_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_validation() {
        // Standard CONNECT - no :scheme, :path
        let headers = vec![
            (":method".to_string(), "CONNECT".to_string()),
            (":authority".to_string(), "example.com:443".to_string()),
        ];

        let result = validate_request_headers(&headers);
        assert!(result.is_ok());
        assert!(result.unwrap().is_connect());
    }

    #[test]
    fn test_extended_connect_validation() {
        // Extended CONNECT with :protocol
        let headers = vec![
            (":method".to_string(), "CONNECT".to_string()),
            (":protocol".to_string(), "websocket".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/chat".to_string()),
        ];

        let result = validate_request_headers(&headers);
        assert!(result.is_ok());
        let pseudo = result.unwrap();
        assert!(pseudo.is_extended_connect());
    }

    #[test]
    fn test_connection_header_rejected() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/".to_string()),
            ("connection".to_string(), "keep-alive".to_string()),
        ];

        let result = validate_request_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_field_section_size_calculation() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
        ];

        let size = calculate_field_section_size(&headers);
        // ":method" (7) + "GET" (3) + 32 = 42
        // ":path" (5) + "/" (1) + 32 = 38
        // Total = 80
        assert_eq!(size, 80);
    }

    #[test]
    fn test_field_section_size_limit() {
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
        ];

        // Should pass with higher limit
        assert!(validate_field_section_size(&headers, 100).is_ok());
        
        // Should fail with lower limit
        assert!(validate_field_section_size(&headers, 50).is_err());
        
        // Should pass with unlimited (0)
        assert!(validate_field_section_size(&headers, 0).is_ok());
    }
}
