//! Core Service Traits and Types for Superd
//!
//! This crate provides the fundamental types and traits that all Superd services
//! must implement. It follows Sans-IO principles for maximum performance.
//!
//! # Service Registration
//!
//! Services are registered at compile time using a const array. This provides:
//! - Zero runtime initialization cost
//! - Compile-time service discovery
//! - Maximum performance

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
    
    /// Negotiated ALPN protocol
    pub alpn: Option<Bytes>,
    
    /// Detected protocol (if multiplexed)
    pub protocol: Option<String>,
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

/// Compile-time service factory
///
/// This struct is used to register services at compile time.
/// The factory function is called once during ServiceRegistry initialization.
pub struct ServiceFactory {
    /// Service name (must be unique)
    pub name: &'static str,
    
    /// Service description
    pub description: &'static str,
    
    /// Factory function that creates the service handler
    /// This is called once during registry initialization
    pub factory: fn() -> Arc<dyn ServiceHandler>,
}

/// Registry of all services (defined at compile time)
///
/// To add a new service:
/// 1. Create your service crate and implement ServiceHandler
/// 2. Export a SERVICE_FACTORY constant from your crate
/// 3. Add it to this SERVICES array
/// 4. The service will be automatically available
///
/// This approach provides zero runtime initialization cost.
pub const SERVICES: &[ServiceFactory] = &[
    // Note: This will be populated by the main daemon crate
    // The daemon re-exports this with actual services included
];

/// Service registry with automatic registration
///
/// Routing is handled externally via ALPN and stream-type detection in the QUIC layer.
/// This registry simply maps service names to their handlers.
pub struct ServiceRegistry {
    handlers: HashMap<&'static str, Arc<dyn ServiceHandler>>,
}

impl ServiceRegistry {
    /// Create a new registry from a compile-time service array
    /// 
    /// This provides zero runtime initialization cost when using const SERVICES.
    pub fn from_services(services: &'static [ServiceFactory]) -> Self {
        let mut handlers = HashMap::with_capacity(services.len());
        
        // Build the handler map from the const array
        // The compiler can optimize this loop significantly
        for service in services {
            let handler = (service.factory)();
            handlers.insert(service.name, handler);
        }
        
        Self { handlers }
    }

    /// Create a new registry
    /// 
    /// Uses the global SERVICES array. For custom service arrays, use `from_services()`.
    pub fn new() -> Self {
        Self::from_services(SERVICES)
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
    /// This is the hot path - no async overhead.
    /// Routing is determined by the `protocol` field in the request,
    /// which is set by ALPN/stream-type detection in the QUIC layer.
    pub fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // Get service name from request protocol
        let service_name = request.protocol.as_deref()
            .ok_or_else(|| ServiceError::NotFound("No protocol specified in request".to_string()))?;

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
    fn test_service_registry_routing() {
        // Create a minimal test service
        struct TestService;
        impl ServiceHandler for TestService {
            fn name(&self) -> &'static str { "test" }
            fn description(&self) -> &'static str { "Test service" }
            fn process(&self, req: ServiceRequest) -> ServiceResult<ServiceResponse> {
                Ok(ServiceResponse {
                    data: req.data.clone(),
                    close_stream: true,
                })
            }
        }

        const TEST_SERVICE: ServiceFactory = ServiceFactory {
            name: "test",
            description: "Test service",
            factory: || Arc::new(TestService),
        };

        let registry = ServiceRegistry::from_services(&[TEST_SERVICE]);

        // Test with protocol specified (normal case from QUIC layer)
        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("hello"),
            is_datagram: false,
            alpn: Some(Bytes::from("test")),
            protocol: Some("test".to_string()),
        };

        let response = registry.process(request).unwrap();
        assert_eq!(response.data, Bytes::from("hello"));

        // Test with missing protocol (should error)
        let bad_request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("hello"),
            is_datagram: false,
            alpn: None,
            protocol: None,
        };

        assert!(registry.process(bad_request).is_err());
    }
}