//! Core Service Traits and Types for Superd
//!
//! This crate provides the fundamental types and traits that all Superd services
//! must implement. It follows Sans-IO principles for maximum performance.

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;

/// Result type for service operations
pub type ServiceResult<T> = Result<T, ServiceError>;

/// Service error types
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Service not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Processing error: {0}")]
    ProcessingError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),
}

/// Request from a QUIC connection (Sans-IO)
#[derive(Debug, Clone)]
pub struct ServiceRequest {
    /// Connection ID
    pub connection_id: u64,

    /// Stream ID (if stream-based)
    pub stream_id: Option<u64>,

    /// Request data (zero-copy)
    pub data: Bytes,

    /// Is this a datagram (vs stream)?
    pub is_datagram: bool,
}

/// Response to send back (Sans-IO)
#[derive(Debug, Clone)]
pub struct ServiceResponse {
    /// Response data (zero-copy)
    pub data: Bytes,

    /// Should close the stream after sending?
    pub close_stream: bool,
}

/// Service handler trait (Sans-IO, no async)
///
/// This trait uses a synchronous API for maximum performance.
/// Services should be stateless or use Arc for shared state.
#[async_trait::async_trait]
pub trait ServiceHandler: Send + Sync {
    /// Service name (for logging/debugging)
    fn name(&self) -> &'static str;

    /// Service description
    fn description(&self) -> &'static str;

    /// Process a request and produce a response (Sans-IO, synchronous)
    ///
    /// This is the hot path - keep it fast:
    /// - No async/await overhead
    /// - No allocations if possible
    /// - Use zero-copy slicing
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse>;

    /// Called when a new connection is established (optional, async is OK here)
    async fn on_connect(&self, _connection_id: u64) {
        // Default: do nothing
    }

    /// Called when a connection is closed (optional, async is OK here)
    async fn on_disconnect(&self, _connection_id: u64) {
        // Default: do nothing
    }
}

/// Router trait for determining which service handles a request
pub trait Router: Send + Sync {
    /// Route a request to a service name
    fn route(&self, request: &ServiceRequest) -> &'static str;
}

/// Default router using request inspection
struct DefaultRouter;

impl Router for DefaultRouter {
    fn route(&self, request: &ServiceRequest) -> &'static str {
        // Fast path: check first bytes for HTTP methods
        if request.data.len() >= 4 {
            match &request.data[..4] {
                b"GET " | b"POST" | b"PUT " | b"DEL " | b"HEAD" | b"PATC" => {
                    return "http3";
                }
                _ => {}
            }
        }

        // Default to echo
        "echo"
    }
}

/// Service registry with automatic registration
pub struct ServiceRegistry {
    handlers: HashMap<&'static str, Arc<dyn ServiceHandler>>,
    router: Box<dyn Router>,
}

impl ServiceRegistry {
    /// Create a new registry with default router
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            router: Box::new(DefaultRouter),
        }
    }

    /// Create a registry with a custom router
    pub fn with_router(router: Box<dyn Router>) -> Self {
        Self {
            handlers: HashMap::new(),
            router,
        }
    }

    /// Register a service handler
    pub fn register(&mut self, handler: Arc<dyn ServiceHandler>) {
        let name = handler.name();
        self.handlers.insert(name, handler);
    }

    /// Get a service by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn ServiceHandler>> {
        self.handlers.get(name).cloned()
    }

    /// List all registered services
    pub fn list_services(&self) -> Vec<&'static str> {
        self.handlers.keys().copied().collect()
    }

    /// Process a request (Sans-IO, synchronous)
    ///
    /// This is the hot path - no async overhead
    pub fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // Route the request
        let service_name = self.router.route(&request);

        // Get the handler
        let handler = self
            .handlers
            .get(service_name)
            .ok_or_else(|| ServiceError::NotFound(service_name.to_string()))?;

        // Process the request (Sans-IO)
        handler.process(request)
    }

    /// Notify all services of a new connection
    pub fn on_connect(&self, connection_id: u64) {
        for handler in self.handlers.values() {
            let handler = Arc::clone(handler);
            tokio::spawn(async move {
                handler.on_connect(connection_id).await;
            });
        }
    }

    /// Notify all services of a closed connection
    pub fn on_disconnect(&self, connection_id: u64) {
        for handler in self.handlers.values() {
            let handler = Arc::clone(handler);
            tokio::spawn(async move {
                handler.on_disconnect(connection_id).await;
            });
        }
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_router() {
        let router = DefaultRouter;

        let http_request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("GET / HTTP/1.1\r\n"),
            is_datagram: false,
        };

        assert_eq!(router.route(&http_request), "http3");

        let echo_request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("hello"),
            is_datagram: false,
        };

        assert_eq!(router.route(&echo_request), "echo");
    }
}