//! HTTP/3 message validation per RFC 9114.
//!
//! This module implements validation for HTTP/3 messages including
//! pseudo-header validation, field name validation, and malformed message detection.

use crate::error::H3Error;
use http::Method;

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

    for (name, value) in headers {
        // RFC 9114 Section 4.2: Field names MUST be lowercase
        if name.chars().any(|c| c.is_uppercase()) {
            return Err(H3Error::Http(format!(
                "field name contains uppercase characters: {}",
                name
            )));
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
                    method = Some(value.clone());
                }
                ":scheme" => {
                    if scheme.is_some() {
                        return Err(H3Error::Http("duplicate :scheme pseudo-header".into()));
                    }
                    scheme = Some(value.clone());
                }
                ":authority" => {
                    if authority.is_some() {
                        return Err(H3Error::Http("duplicate :authority pseudo-header".into()));
                    }
                    authority = Some(value.clone());
                }
                ":path" => {
                    if path.is_some() {
                        return Err(H3Error::Http("duplicate :path pseudo-header".into()));
                    }
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
                || name == "transfer-encoding" || name == "upgrade" {
                return Err(H3Error::Http(format!(
                    "connection-specific header field not allowed: {}",
                    name
                )));
            }

            // TE header field is allowed but MUST NOT contain anything other than "trailers"
            if name == "te" && value != "trailers" {
                return Err(H3Error::Http(
                    "TE header field MUST only contain 'trailers'".into()
                ));
            }
        }
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
fn validate_content_length_uniqueness(headers: &[(String, String)]) -> Result<(), H3Error> {
    let mut content_length_values: Vec<&str> = Vec::new();
    
    for (name, value) in headers {
        if name == "content-length" {
            content_length_values.push(value);
        }
    }
    
    if content_length_values.len() > 1 {
        // Check if all values are identical
        let first = content_length_values[0];
        for value in &content_length_values[1..] {
            if *value != first {
                // Different Content-Length values - malformed
                return Err(H3Error::MessageError);
            }
        }
        // All values same but still reject for safety
        return Err(H3Error::MessageError);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_request_headers() {
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
