//! HTTP Request Parser (Sans-IO)
//!
//! Zero-copy HTTP request parsing using string slices.

/// Parsed HTTP request
#[derive(Debug)]
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
}

impl<'a> HttpRequest<'a> {
    /// Parse an HTTP request (Sans-IO, zero-copy)
    ///
    /// Uses string slices to avoid allocations
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let request_str = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8")?;

        let lines: Vec<&str> = request_str.lines().collect();
        if lines.is_empty() {
            return Err("Empty request");
        }

        // Parse request line: "METHOD PATH VERSION"
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 3 {
            return Err("Invalid request line");
        }

        Ok(HttpRequest {
            method: parts[0],
            path: parts[1],
            version: parts[2],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request() {
        let data = b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req = HttpRequest::parse(data).unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/test");
        assert_eq!(req.version, "HTTP/1.1");
    }

    #[test]
    fn test_parse_post_request() {
        let data = b"POST /submit HTTP/1.1\r\nContent-Length: 10\r\n\r\ntest";
        let req = HttpRequest::parse(data).unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/submit");
    }

    #[test]
    fn test_parse_invalid() {
        let data = b"INVALID";
        assert!(HttpRequest::parse(data).is_err());
    }
}
