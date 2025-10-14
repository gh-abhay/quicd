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

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// A trait combining AsyncRead and AsyncWrite for use in trait objects.
pub trait ReadWrite: AsyncRead + AsyncWrite {}

// Blanket implementation for any type that satisfies the bounds.
impl<T: AsyncRead + AsyncWrite> ReadWrite for T {}

/// A type-erased stream that implements AsyncRead and AsyncWrite.
/// Services will receive this to handle I/O for a QUIC stream.
pub type BoxedQuicStream = Box<dyn ReadWrite + Unpin + Send>;

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

/// Service handler trait.
///
/// Services implement this trait to handle incoming streams.
#[async_trait::async_trait]
pub trait ServiceHandler: Send + Sync {
    /// Service name (for logging/debugging).
    fn name(&self) -> &'static str;

    /// Service description.
    fn description(&self) -> &'static str;

    /// Handle a new incoming QUIC stream.
    ///
    /// This method is called by the `StreamProcessor` when a new stream
    /// is created and routed to this service. The service takes ownership
    /// of the stream and is responsible for its entire lifecycle.
    ///
    /// The provided `stream` is a dynamic trait object that implements
    /// `AsyncRead` and `AsyncWrite`, allowing it to be used directly by
    /// libraries like `tonic` or `h3`.
    async fn handle_stream(&self, stream: BoxedQuicStream);
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
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    // A mock stream for testing purposes.
    struct MockStream;
    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Unpin for MockStream {}

    #[tokio::test]
    async fn test_service_handler_trait() {
        struct TestService;
        #[async_trait::async_trait]
        impl ServiceHandler for TestService {
            fn name(&self) -> &'static str {
                "test"
            }
            fn description(&self) -> &'static str {
                "A test service"
            }
            async fn handle_stream(&self, _stream: BoxedQuicStream) {
                // In a real test, we would assert I/O on the stream.
            }
        }

        let service = TestService;
        let stream = Box::new(MockStream);
        service.handle_stream(stream).await;
        assert_eq!(service.name(), "test");
    }
}