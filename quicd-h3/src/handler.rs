//! Default file-serving HTTP handler.
//!
//! Provides a simple but production-ready file server with:
//! - Static file serving from configured directory
//! - Content-type detection
//! - Index file handling
//! - 404 responses for missing files
//! - Security checks (path traversal prevention)

use bytes::Bytes;
use http::{Method, StatusCode};
use mime_guess::from_path;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncReadExt;

use crate::config::HandlerConfig;
use crate::message::{HttpRequest, HttpResponse};
use crate::error::Result;

/// Default file-serving HTTP handler.
pub struct FileHandler {
    config: HandlerConfig,
}

impl FileHandler {
    /// Create a new file handler with the given configuration.
    pub fn new(config: HandlerConfig) -> Self {
        Self { config }
    }

    /// Handle an HTTP request.
    ///
    /// Returns an HTTP response. This method runs entirely within the connection task
    /// and never spawns additional tasks.
    pub async fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse> {
        // Only handle GET and HEAD methods
        if request.method != Method::GET && request.method != Method::HEAD {
            return Ok(HttpResponse::new(StatusCode::METHOD_NOT_ALLOWED, Bytes::new())
                .with_header("allow", "GET, HEAD"));
        }

        // Extract path from URI
        let uri_path = request.uri.path();
        
        // Security: prevent path traversal
        let safe_path = self.sanitize_path(uri_path)?;
        
        // Resolve to file system path
        let file_path = self.config.file_root.join(safe_path);

        // Check if path exists
        if !file_path.exists() {
            return Ok(self.not_found_response());
        }

        // Handle directories
        if file_path.is_dir() {
            return self.handle_directory(&file_path).await;
        }

        // Serve file
        self.serve_file(&file_path, request.method == Method::HEAD).await
    }

    /// Sanitize request path to prevent directory traversal.
    fn sanitize_path(&self, uri_path: &str) -> Result<PathBuf> {
        // Remove leading slash
        let path_str = uri_path.trim_start_matches('/');
        
        // Decode percent-encoding and build path
        let decoded = percent_decode(path_str);
        let path = PathBuf::from(decoded);

        // Check for directory traversal attempts
        for component in path.components() {
            if let std::path::Component::ParentDir = component {
                return Ok(PathBuf::from("/")); // Reject, serve root
            }
        }

        Ok(path)
    }

    /// Handle directory requests.
    async fn handle_directory(&self, dir_path: &Path) -> Result<HttpResponse> {
        // Try index files
        for index_file in &self.config.index_files {
            let index_path = dir_path.join(index_file);
            if index_path.exists() && index_path.is_file() {
                return self.serve_file(&index_path, false).await;
            }
        }

        // Directory listing not implemented yet / disabled
        Ok(self.not_found_response())
    }

    /// Serve a file.
    async fn serve_file(&self, file_path: &Path, head_only: bool) -> Result<HttpResponse> {
        // Open file
        let mut file = match fs::File::open(file_path).await {
            Ok(f) => f,
            Err(_) => return Ok(self.not_found_response()),
        };

        // Get file size
        let metadata = match file.metadata().await {
            Ok(m) => m,
            Err(_) => return Ok(self.internal_error_response()),
        };

        let file_size = metadata.len();

        // Determine content type
        let content_type = from_path(file_path)
            .first_or_octet_stream()
            .to_string();

        // Read file content (if not HEAD request)
        let body = if head_only {
            Bytes::new()
        } else {
            let mut buffer = Vec::with_capacity(file_size as usize);
            if let Err(_) = file.read_to_end(&mut buffer).await {
                return Ok(self.internal_error_response());
            }
            Bytes::from(buffer)
        };

        // Build response
        Ok(HttpResponse::new(StatusCode::OK, body)
            .with_header("content-type", content_type)
            .with_header("content-length", file_size.to_string()))
    }

    /// Generate 404 Not Found response.
    fn not_found_response(&self) -> HttpResponse {
        HttpResponse::new(
            StatusCode::NOT_FOUND,
            Bytes::from_static(b"404 Not Found"),
        )
        .with_header("content-type", "text/plain")
    }

    /// Generate 500 Internal Server Error response.
    fn internal_error_response(&self) -> HttpResponse {
        HttpResponse::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Bytes::from_static(b"500 Internal Server Error"),
        )
        .with_header("content-type", "text/plain")
    }
}

/// Simple percent-decode implementation.
fn percent_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Try to decode hex sequence
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // Failed to decode, keep as-is
            result.push('%');
            result.push_str(&hex);
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_path() {
        let config = HandlerConfig::default();
        let handler = FileHandler::new(config);

        // Normal paths
        assert_eq!(
            handler.sanitize_path("/index.html").unwrap(),
            PathBuf::from("index.html")
        );

        // Directory traversal attempts should be rejected
        let result = handler.sanitize_path("/../etc/passwd").unwrap();
        assert_eq!(result, PathBuf::from("/"));
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("test"), "test");
        assert_eq!(percent_decode("%2F"), "/");
    }
}
