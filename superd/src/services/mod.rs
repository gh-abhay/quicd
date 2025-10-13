//! Service Registry and Trait Definition
//!
//! This module defines the trait that all services must implement,
//! and provides a registry for managing multiple services.

use async_trait::async_trait;
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

/// Request from a QUIC connection
#[derive(Debug, Clone)]
pub struct ServiceRequest {
    /// Connection ID
    pub connection_id: u64,

    /// Stream ID (if stream-based)
    pub stream_id: Option<u64>,

    /// Request data
    pub data: bytes::Bytes,

    /// Is this a datagram (vs stream)?
    pub is_datagram: bool,
}

/// Response to send back
#[derive(Debug, Clone)]
pub struct ServiceResponse {
    /// Response data
    pub data: bytes::Bytes,

    /// Should close the stream after sending?
    pub close_stream: bool,
}

/// Trait that all services must implement
#[async_trait]
pub trait Service: Send + Sync {
    /// Service name (e.g., "echo", "http3")
    fn name(&self) -> &str;

    /// Service description
    fn description(&self) -> &str;

    /// Handle a request and produce a response
    async fn handle_request(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse>;

    /// Called when a new connection is established (optional hook)
    async fn on_connection_established(&self, connection_id: u64) -> ServiceResult<()> {
        let _ = connection_id;
        Ok(())
    }

    /// Called when a connection is closed (optional hook)
    async fn on_connection_closed(&self, connection_id: u64) -> ServiceResult<()> {
        let _ = connection_id;
        Ok(())
    }
}

/// Service registry for managing multiple services
pub struct ServiceRegistry {
    services: HashMap<String, Arc<dyn Service>>,
}

impl ServiceRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Register a service
    pub fn register(&mut self, service: Arc<dyn Service>) {
        let name = service.name().to_string();
        self.services.insert(name, service);
    }

    /// Get a service by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn Service>> {
        self.services.get(name).cloned()
    }

    /// List all registered services
    pub fn list_services(&self) -> Vec<String> {
        self.services.keys().cloned().collect()
    }

    /// Route a request to the appropriate service
    /// For now, we use a simple path-based routing
    pub async fn route_request(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // TODO: Implement proper routing based on HTTP path or stream namespace
        // For now, try to determine service from data

        // Simple heuristic: if data starts with "GET " or "POST ", route to http3
        // Otherwise, route to echo
        let service_name = if request.data.starts_with(b"GET ")
            || request.data.starts_with(b"POST ")
            || request.data.starts_with(b"PUT ")
            || request.data.starts_with(b"DELETE ")
        {
            "http3"
        } else {
            "echo"
        };

        let service = self
            .get(service_name)
            .ok_or_else(|| ServiceError::NotFound(service_name.to_string()))?;

        service.handle_request(request).await
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export service implementations
pub mod echo;
pub mod http3;
