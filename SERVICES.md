# Services Architecture

This document describes the modular service architecture in Superd.

## Overview

Superd uses a pluggable service architecture that allows multiple applications to share the same QUIC daemon infrastructure. Services are registered in a central `ServiceRegistry` and handle requests from QUIC connections.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                   Service Layer                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ServiceRegistry                                             │
│  ├─ EchoService      → handles echo requests                │
│  ├─ Http3Service     → handles HTTP/3 requests              │
│  └─ CustomService    → custom application logic             │
│                                                               │
│  Request Routing:                                            │
│    QUIC Connection → ServiceRegistry.route_request()         │
│                   → Appropriate Service.handle_request()     │
│                   → ServiceResponse                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Service Trait

All services must implement the `Service` trait:

```rust
#[async_trait]
pub trait Service: Send + Sync {
    /// Service name (e.g., "echo", "http3")
    fn name(&self) -> &str;
    
    /// Service description
    fn description(&self) -> &str;
    
    /// Handle a request and produce a response
    async fn handle_request(&self, request: ServiceRequest) 
        -> ServiceResult<ServiceResponse>;
    
    /// Called when a new connection is established (optional)
    async fn on_connection_established(&self, connection_id: u64) 
        -> ServiceResult<()>;
    
    /// Called when a connection is closed (optional)
    async fn on_connection_closed(&self, connection_id: u64) 
        -> ServiceResult<()>;
}
```

## Built-in Services

### Echo Service

**Location:** `superd/src/services/echo.rs`

**Purpose:** Simple echo service that returns received data unchanged.

**Use Cases:**
- Testing QUIC connectivity
- Debugging packet flow
- Benchmarking raw throughput

**Example:**
```rust
use superd::services::{ServiceRegistry, echo::EchoService};
use std::sync::Arc;

let mut registry = ServiceRegistry::new();
registry.register(Arc::new(EchoService::new()));
```

### HTTP/3 Service

**Location:** `superd/src/services/http3.rs`

**Purpose:** HTTP/3 service that returns "Hello, World!" JSON for all paths.

**Response Format:**
```json
{
  "message": "Hello, World!",
  "service": "superd-http3",
  "path": "/api/test",
  "timestamp": 1697234567
}
```

**Use Cases:**
- HTTP/3 API endpoints
- RESTful services
- CDN applications

**Example:**
```rust
use superd::services::{ServiceRegistry, http3::Http3Service};
use std::sync::Arc;

let mut registry = ServiceRegistry::new();
registry.register(Arc::new(Http3Service::new()));
```

## Creating Custom Services

### Step 1: Create Service Module

Create a new file in `superd/src/services/`:

```rust
// superd/src/services/myapp.rs

use super::{Service, ServiceRequest, ServiceResponse, ServiceResult};
use async_trait::async_trait;
use tracing::info;

pub struct MyAppService {
    // Your service state here
}

impl MyAppService {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Service for MyAppService {
    fn name(&self) -> &str {
        "myapp"
    }
    
    fn description(&self) -> &str {
        "My custom application service"
    }
    
    async fn handle_request(&self, request: ServiceRequest) 
        -> ServiceResult<ServiceResponse> {
        info!(
            connection_id = request.connection_id,
            stream_id = ?request.stream_id,
            "MyApp: processing request"
        );
        
        // Your application logic here
        let response_data = process_request(&request.data);
        
        Ok(ServiceResponse {
            data: response_data,
            close_stream: true,
        })
    }
}
```

### Step 2: Register in mod.rs

Add your service to `superd/src/services/mod.rs`:

```rust
// At the bottom of mod.rs
pub mod echo;
pub mod http3;
pub mod myapp;  // Add your module
```

### Step 3: Register in Daemon

Register your service in `superd/src/lib.rs`:

```rust
// In Superd::new() method
service_registry.register(Arc::new(services::echo::EchoService::new()));
service_registry.register(Arc::new(services::http3::Http3Service::new()));
service_registry.register(Arc::new(services::myapp::MyAppService::new()));
```

## Request/Response Model

### ServiceRequest

```rust
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
```

### ServiceResponse

```rust
pub struct ServiceResponse {
    /// Response data
    pub data: bytes::Bytes,
    
    /// Should close the stream after sending?
    pub close_stream: bool,
}
```

## Request Routing

The `ServiceRegistry` routes requests to appropriate services based on:

1. **HTTP-based routing** (default): Inspects request data
   - HTTP requests (GET, POST, etc.) → `http3` service
   - Other data → `echo` service

2. **Custom routing**: Implement your own routing logic
   ```rust
   impl ServiceRegistry {
       pub async fn route_request(&self, request: ServiceRequest) 
           -> ServiceResult<ServiceResponse> {
           // Your routing logic here
       }
   }
   ```

## Service Lifecycle

### Connection Lifecycle

```text
1. Client connects
   └─> on_connection_established(connection_id)

2. Client sends request
   └─> handle_request(ServiceRequest)
       └─> Service processes request
           └─> Returns ServiceResponse

3. Client closes connection
   └─> on_connection_closed(connection_id)
```

### Service Registration

```text
1. Daemon starts
   └─> ServiceRegistry::new()

2. Services registered
   └─> registry.register(service)

3. Service ready
   └─> Requests routed to service
```

## Best Practices

### 1. Keep Services Stateless

Services should be stateless or use external state management:

```rust
// ❌ Bad: Mutable state in service
pub struct BadService {
    counter: AtomicUsize,  // Don't do this
}

// ✅ Good: Stateless or external state
pub struct GoodService {
    database: Arc<Database>,  // External state
}
```

### 2. Use Async Efficiently

Avoid blocking operations in service handlers:

```rust
// ❌ Bad: Blocking operation
async fn handle_request(&self, request: ServiceRequest) 
    -> ServiceResult<ServiceResponse> {
    let data = std::fs::read("file.txt")?;  // Blocks!
    // ...
}

// ✅ Good: Async operation
async fn handle_request(&self, request: ServiceRequest) 
    -> ServiceResult<ServiceResponse> {
    let data = tokio::fs::read("file.txt").await?;
    // ...
}
```

### 3. Handle Errors Gracefully

Use descriptive error messages:

```rust
async fn handle_request(&self, request: ServiceRequest) 
    -> ServiceResult<ServiceResponse> {
    if request.data.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "Empty request data".to_string()
        ));
    }
    // ...
}
```

### 4. Add Comprehensive Tests

Test all service functionality:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_myapp_service() {
        let service = MyAppService::new();
        
        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("test"),
            is_datagram: false,
        };
        
        let response = service.handle_request(request).await.unwrap();
        assert!(!response.data.is_empty());
    }
}
```

### 5. Use Structured Logging

Use `tracing` for structured logging:

```rust
use tracing::{info, warn, error, debug};

async fn handle_request(&self, request: ServiceRequest) 
    -> ServiceResult<ServiceResponse> {
    debug!(
        connection_id = request.connection_id,
        data_len = request.data.len(),
        "Processing request"
    );
    
    // Process...
    
    info!("Request processed successfully");
    Ok(response)
}
```

## Service Configuration

Future enhancement: Service-specific configuration

```toml
# superd.toml

[services.echo]
enabled = true

[services.http3]
enabled = true
default_response = "Hello from Superd!"

[services.myapp]
enabled = true
config_file = "/etc/myapp/config.json"
```

## Performance Considerations

### 1. Zero-Copy Data Handling

Use `Bytes` for efficient data handling:

```rust
use bytes::Bytes;

// Zero-copy slice
let response_data = request.data.slice(0..10);
```

### 2. Connection Pooling

For services that need external connections (databases, caches):

```rust
pub struct MyService {
    pool: Arc<Pool<PostgresConnectionManager>>,
}
```

### 3. Caching

Cache frequently accessed data:

```rust
pub struct MyService {
    cache: Arc<Cache<String, Bytes>>,
}
```

## Testing Services

### Unit Tests

```bash
# Test specific service
cargo test --package superd --lib services::echo

# Test all services
cargo test --package superd --lib services
```

### Integration Tests

Create integration tests in `superd/tests/`:

```rust
// superd/tests/services_integration.rs

#[tokio::test]
async fn test_service_registry() {
    let mut registry = ServiceRegistry::new();
    registry.register(Arc::new(EchoService::new()));
    
    let services = registry.list_services();
    assert!(services.contains(&"echo".to_string()));
}
```

## Directory Structure

```
superd/src/services/
├── mod.rs          # Service trait and registry
├── echo.rs         # Echo service implementation
├── http3.rs        # HTTP/3 service implementation
└── myapp.rs        # Your custom service (example)
```

## Future Enhancements

- [ ] Dynamic service loading (plugins)
- [ ] Service-specific configuration
- [ ] Service metrics and monitoring
- [ ] Request/response middleware
- [ ] Path-based routing for HTTP/3
- [ ] WebSocket support
- [ ] gRPC support
- [ ] Service health checks
- [ ] Rate limiting per service
- [ ] Authentication/authorization hooks
