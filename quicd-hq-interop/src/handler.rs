//! File serving handler for hq-interop protocol.

use bytes::Bytes;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{info, warn};

use crate::config::HandlerConfig;
use crate::error::{Error, Result};

/// Handler trait for processing requests.
///
/// This abstraction allows users to plug in custom business logic.
pub trait FileHandler: Send + Sync {
    /// Handle a request for the given path.
    ///
    /// Returns the file content as bytes, or an error.
    fn handle_request(&self, path: &str)
        -> impl std::future::Future<Output = Result<Bytes>> + Send;
}

/// Default static file handler.
///
/// Serves files from configured root directory with security checks.
#[derive(Clone)]
pub struct StaticFileHandler {
    config: HandlerConfig,
}

impl StaticFileHandler {
    /// Create a new static file handler.
    pub fn new(config: HandlerConfig) -> Self {
        Self { config }
    }

    /// Sanitize request path to prevent directory traversal.
    fn sanitize_path(&self, uri_path: &str) -> Result<PathBuf> {
        // Remove leading slash and query string
        let path_str = uri_path
            .trim_start_matches('/')
            .split('?')
            .next()
            .unwrap_or("");

        // Decode percent-encoding
        let decoded = percent_decode(path_str);
        let path = PathBuf::from(decoded);

        // Check for directory traversal attempts
        for component in path.components() {
            if let std::path::Component::ParentDir = component {
                return Err(Error::FileError("Path traversal not allowed".to_string()));
            }
        }

        Ok(path)
    }

    /// Handle directory requests by looking for index files.
    async fn handle_directory(&self, dir_path: &Path) -> Result<Bytes> {
        for index_file in &self.config.index_files {
            let index_path = dir_path.join(index_file);
            if index_path.exists() && index_path.is_file() {
                return self.read_file(&index_path).await;
            }
        }

        Err(Error::FileError("No index file found".to_string()))
    }

    /// Read file contents.
    async fn read_file(&self, file_path: &Path) -> Result<Bytes> {
        let mut file = fs::File::open(file_path)
            .await
            .map_err(|e| Error::FileError(format!("Failed to open file: {}", e)))?;

        let metadata = file
            .metadata()
            .await
            .map_err(|e| Error::FileError(format!("Failed to get metadata: {}", e)))?;

        let mut buffer = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut buffer)
            .await
            .map_err(|e| Error::FileError(format!("Failed to read file: {}", e)))?;

        Ok(Bytes::from(buffer))
    }
}

impl FileHandler for StaticFileHandler {
    async fn handle_request(&self, path: &str) -> Result<Bytes> {
        info!("hq-interop: Serving request for path: {}", path);

        // Sanitize path
        let safe_path = self.sanitize_path(path)?;

        // Resolve to filesystem path
        let file_path = self.config.file_root.join(&safe_path);

        // Check if path exists
        if !file_path.exists() {
            warn!("hq-interop: File not found: {:?}", file_path);
            return Err(Error::FileError("File not found".to_string()));
        }

        // Handle directories
        if file_path.is_dir() {
            return self.handle_directory(&file_path).await;
        }

        // Serve file
        info!("hq-interop: Reading file: {:?}", file_path);
        self.read_file(&file_path).await
    }
}

/// Simple percent-decode implementation.
fn percent_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
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
        let handler = StaticFileHandler::new(config);

        // Normal paths
        assert!(handler.sanitize_path("/index.html").is_ok());
        assert!(handler.sanitize_path("/path/to/file.txt").is_ok());

        // Directory traversal attempts should be rejected
        assert!(handler.sanitize_path("/../etc/passwd").is_err());
        assert!(handler.sanitize_path("/path/../../etc/passwd").is_err());
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("test"), "test");
        assert_eq!(percent_decode("%2F"), "/");
    }
}
