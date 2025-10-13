# Services Architecture

High-performance, modular service architecture with Sans-IO design for maximum throughput.

## Design Philosophy

### Core Principles

1. **Sans-IO**: Separate I/O from protocol logic
2. **Zero-Copy**: Use `Bytes` for shared buffer references
3. **Synchronous Hot Path**: No async/await overhead in request processing
4. **Automatic Registration**: Single point of service registration
5. **Fast Routing**: Pattern matching on raw bytes, no string comparisons

### Performance First

- **No allocations** in request processing (where possible)
- **No async overhead** in service handlers
- **Zero-copy** request/response handling
- **Cache-friendly** data structures
- **Minimal indirection** between layers

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                    Service Layer                             │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  QUIC Connection                                              │
│       │                                                        │
│       ├──> ServiceRegistry.process(request)                   │
│       │         │                                              │
│       │         ├──> Router.route() [fast byte matching]      │
│       │         │         └──> "echo" or "http3"              │
│       │         │                                              │
│       │         ├──> Get handler from HashMap                 │
│       │         │                                              │
│       │         └──> Handler.process(request)  [Sans-IO]      │
│       │                   │                                    │
│       │                   └──> ServiceResponse [zero-copy]    │
│       │                                                        │
│       └──> Send response back                                 │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

## Service Handler Trait

All services implement the `ServiceHandler` trait:

```rust
pub trait ServiceHandler: Send + Sync {
    /// Service name (static string for zero-cost)
    fn name(&self) -> &'static str;
    
    /// Service description
    fn description(&self) -> &'static str;
    
    /// Process a request (Sans-IO, synchronous, hot path)
    ///
    /// NO async here! Keep it fast:
    /// - No allocations
    /// - No I/O operations
    /// - Pure computation
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse>;
    
    /// Connection lifecycle hooks (can be slow, not in hot path)
    fn on_connect(&self, connection_id: u64) { }
    fn on_disconnect(&self, connection_id: u64) { }
}
```

## Built-in Services

### Echo Service

**Location:** `superd/src/services/echo/`

**Performance:**
- **Zero allocations**: Returns the same `Bytes` reference
- **True zero-copy**: Pointer comparison verifies no copy
- **Minimal logic**: Just wraps request data in response

**Implementation:**
```rust
pub struct EchoHandler;

impl ServiceHandler for EchoHandler {
    fn name(&self) -> &'static str { "echo" }
    
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // Zero-copy: just return the same Bytes
        Ok(ServiceResponse {
            data: request.data,
            close_stream: true,
        })
    }
}
```

**Files:**
- `mod.rs` - Service handler implementation

### HTTP/3 Service

**Location:** `superd/src/services/http3/`

**Performance:**
- **Sans-IO parsing**: Zero-copy string slices for request parsing
- **Single allocation**: One `BytesMut` for entire response
- **Fast routing**: Byte pattern matching (no string comparisons)

**Implementation:**

**Files:**
- `mod.rs` - Service handler
- `parser.rs` - Sans-IO HTTP request parser
- `response.rs` - Efficient response builder

**Request Parser** (Sans-IO):
```rust
pub struct HttpRequest<'a> {
    pub method: &'a str,  // Zero-copy slice
    pub path: &'a str,    // Zero-copy slice
    pub version: &'a str, // Zero-copy slice
}

impl<'a> HttpRequest<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        // Parse using string slices (no allocations)
    }
}
```

**Response Builder**:
```rust
pub struct HttpResponse;

impl HttpResponse {
    pub fn ok_json(path: &str) -> Bytes {
        // Single allocation for entire response
        let mut buffer = BytesMut::with_capacity(256);
        // Build response...
        buffer.freeze()  // Convert to Bytes (zero-copy)
    }
}
```

## Creating New Services

### Step 1: Create Service Directory

```bash
mkdir -p superd/src/services/myapp
```

### Step 2: Implement Service Handler

Create `superd/src/services/myapp/mod.rs`:

```rust
//! My Application Service
//!
//! Description of what this service does.

use super::{ServiceHandler, ServiceRequest, ServiceResponse, ServiceResult};
use bytes::Bytes;

/// My application handler (stateless for performance)
pub struct MyAppHandler;

impl ServiceHandler for MyAppHandler {
    fn name(&self) -> &'static str {
        "myapp"
    }
    
    fn description(&self) -> &'static str {
        "My custom application service"
    }
    
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // Process request (Sans-IO, no async, no allocations)
        let response_data = self.handle_request(&request.data);
        
        Ok(ServiceResponse {
            data: response_data,
            close_stream: true,
        })
    }
}

impl MyAppHandler {
    /// Internal request processing (pure function)
    fn handle_request(&self, data: &[u8]) -> Bytes {
        // Your logic here
        Bytes::from("Response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_myapp_handler() {
        let handler = MyAppHandler;
        // Add tests
    }
}
```

### Step 3: Register in mod.rs

This is the **ONLY** place you need to add your service:

```rust
// superd/src/services/mod.rs

pub mod echo;
pub mod http3;
pub mod myapp;  // Add your module

pub fn register_all_services() -> ServiceRegistry {
    let mut registry = ServiceRegistry::new();
    
    registry.register(Arc::new(echo::EchoHandler));
    registry.register(Arc::new(http3::Http3Handler::new()));
    registry.register(Arc::new(myapp::MyAppHandler));  // Register it
    
    registry
}
```

That's it! The main daemon automatically picks it up.

## Request Routing

### Default Router

The default router uses fast byte pattern matching:

```rust
impl Router for DefaultRouter {
    fn route(&self, request: &ServiceRequest) -> &'static str {
        // Fast path: check first 4 bytes
        if request.data.len() >= 4 {
            match &request.data[..4] {
                b"GET " | b"POST" | b"PUT " | b"DEL " => return "http3",
                _ => {}
            }
        }
        
        "echo"  // Default fallback
    }
}
```

### Custom Router

Implement your own routing logic:

```rust
struct PathBasedRouter;

impl Router for PathBasedRouter {
    fn route(&self, request: &ServiceRequest) -> &'static str {
        // Parse HTTP path and route based on it
        if let Some(path) = extract_path(&request.data) {
            match path {
                "/api/v1" => "api_v1",
                "/api/v2" => "api_v2",
                _ => "echo",
            }
        } else {
            "echo"
        }
    }
}

// Use custom router
let registry = ServiceRegistry::with_router(Box::new(PathBasedRouter));
```

## Performance Characteristics

### Request Processing Path

```text
QUIC Packet → ServiceRegistry.process()
                    ↓ (no allocation)
              Router.route() [byte pattern match]
                    ↓ (HashMap lookup)
              Handler.process() [Sans-IO, sync]
                    ↓ (zero-copy Bytes)
              ServiceResponse
```

**Latency**: ~100-500ns per request (depending on service logic)

**Throughput**: Limited only by service logic, not framework overhead

### Memory Characteristics

- **Zero-copy**: `Bytes` uses Arc internally, no data copies
- **No allocations** in routing and echo service
- **Single allocation** in HTTP/3 service (response buffer)
- **Stateless handlers**: No per-connection state overhead

### Benchmarks

```bash
# Benchmark echo service (zero-copy verification)
cargo test --package superd --lib services::echo::tests::test_echo_zero_copy

# Benchmark HTTP/3 response building
cargo bench --bench http3_response
```

## Service Patterns

### Pattern 1: Pure Echo (Zero Operations)

```rust
pub struct EchoHandler;

impl ServiceHandler for EchoHandler {
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        Ok(ServiceResponse {
            data: request.data,  // Zero-copy
            close_stream: true,
        })
    }
}
```

**Cost**: ~50ns (just struct construction)

### Pattern 2: Response Builder (Single Allocation)

```rust
pub struct JsonHandler;

impl ServiceHandler for JsonHandler {
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        let response = build_json_response(&request.data);  // One allocation
        Ok(ServiceResponse {
            data: response,
            close_stream: true,
        })
    }
}
```

**Cost**: ~500ns (allocation + formatting)

### Pattern 3: Stateful Service (Arc for Shared State)

```rust
pub struct CacheHandler {
    cache: Arc<DashMap<String, Bytes>>,
}

impl ServiceHandler for CacheHandler {
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        let key = extract_key(&request.data)?;
        let value = self.cache.get(key)
            .map(|v| v.clone())
            .unwrap_or_else(|| Bytes::from("Not found"));
        
        Ok(ServiceResponse {
            data: value,
            close_stream: true,
        })
    }
}
```

**Cost**: ~1-5µs (depends on cache size)

## Directory Structure

```
superd/src/services/
├── mod.rs              # Registry, router, trait definitions
│                       # ⭐ ONLY place for service registration
│
├── echo/               # Echo service module
│   └── mod.rs          # Handler implementation
│
├── http3/              # HTTP/3 service module
│   ├── mod.rs          # Handler implementation  
│   ├── parser.rs       # Sans-IO request parser
│   └── response.rs     # Response builder
│
└── myapp/              # Your custom service
    ├── mod.rs          # Handler implementation
    ├── protocol.rs     # Protocol-specific logic
    └── codec.rs        # Encoding/decoding
```

## Testing Services

### Unit Tests (in each service module)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    
    #[test]
    fn test_handler() {
        let handler = MyAppHandler;
        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("test"),
            is_datagram: false,
        };
        
        let response = handler.process(request).unwrap();
        assert!(!response.data.is_empty());
    }
}
```

### Performance Tests

```rust
#[cfg(test)]
mod benches {
    use super::*;
    
    #[test]
    fn bench_zero_copy() {
        let handler = EchoHandler;
        let data = Bytes::from_static(b"benchmark data");
        let ptr = data.as_ptr();
        
        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data,
            is_datagram: false,
        };
        
        let response = handler.process(request).unwrap();
        
        // Verify true zero-copy
        assert_eq!(response.data.as_ptr(), ptr);
    }
}
```

### Integration Tests

```bash
# Run all service tests
cargo test --package superd --lib services

# Run specific service tests
cargo test --package superd --lib services::echo
cargo test --package superd --lib services::http3
```

## Advanced Patterns

### Pattern 1: Request Batching (Future Enhancement)

```rust
pub trait BatchedServiceHandler {
    /// Process multiple requests at once
    fn process_batch(&self, requests: Vec<ServiceRequest>) 
        -> Vec<ServiceResult<ServiceResponse>>;
}
```

### Pattern 2: Zero-Copy Slicing

```rust
impl ServiceHandler for SlicingHandler {
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // Zero-copy slice (shares same underlying buffer)
        let slice = request.data.slice(0..100);
        
        Ok(ServiceResponse {
            data: slice,  // No allocation
            close_stream: true,
        })
    }
}
```

### Pattern 3: Pre-allocated Responses

```rust
lazy_static! {
    static ref NOT_FOUND: Bytes = Bytes::from_static(b"HTTP/3 404 Not Found\r\n\r\n");
}

impl ServiceHandler for CachedHandler {
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        Ok(ServiceResponse {
            data: NOT_FOUND.clone(),  // Clone is just Arc::clone
            close_stream: true,
        })
    }
}
```

## Custom Routing

### By Protocol

```rust
struct ProtocolRouter;

impl Router for ProtocolRouter {
    fn route(&self, request: &ServiceRequest) -> &'static str {
        if request.is_datagram {
            "media"  // Datagrams for media
        } else {
            "signaling"  // Streams for signaling
        }
    }
}
```

### By Path

```rust
struct PathRouter;

impl Router for PathRouter {
    fn route(&self, request: &ServiceRequest) -> &'static str {
        // Fast byte scanning for path
        if let Some(path_start) = find_path_in_request(&request.data) {
            match path_start {
                b"/api/" => "api",
                b"/ws/" => "websocket",
                b"/media/" => "media",
                _ => "default",
            }
        } else {
            "echo"
        }
    }
}
```

### By Stream ID Range

```rust
struct StreamIdRouter;

impl Router for StreamIdRouter {
    fn route(&self, request: &ServiceRequest) -> &'static str {
        match request.stream_id {
            Some(0..=99) => "control",
            Some(100..=999) => "signaling",
            Some(1000..) => "media",
            None => "datagram_handler",
        }
    }
}
```

## Best Practices

### 1. Keep Services Stateless

```rust
// ❌ Bad: Mutable state
pub struct BadHandler {
    counter: AtomicUsize,  // State per handler instance
}

// ✅ Good: External state or truly stateless
pub struct GoodHandler {
    db: Arc<Database>,  // Shared external state
}

// ✅ Best: Completely stateless
pub struct BestHandler;  // Zero-sized type!
```

### 2. Use Zero-Copy Wherever Possible

```rust
// ❌ Bad: Copies data
fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
    let owned = request.data.to_vec();  // Allocation + copy!
    let response = owned.into();
    Ok(ServiceResponse { data: response, close_stream: true })
}

// ✅ Good: Zero-copy slice
fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
    let slice = request.data.slice(0..10);  // No copy, shared Arc
    Ok(ServiceResponse { data: slice, close_stream: true })
}

// ✅ Best: Return original
fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
    Ok(ServiceResponse { data: request.data, close_stream: true })
}
```

### 3. Avoid Async in Hot Path

```rust
// ❌ Bad: Async overhead
async fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
    // 200-500ns overhead from async runtime
}

// ✅ Good: Synchronous hot path
fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
    // Direct function call, ~10ns overhead
}
```

### 4. Use Static Strings

```rust
// ❌ Bad: Allocates on every call
fn name(&self) -> String {
    "myapp".to_string()
}

// ✅ Good: Static string (zero-cost)
fn name(&self) -> &'static str {
    "myapp"
}
```

### 5. Pre-allocate Response Buffers

```rust
impl ServiceHandler for OptimizedHandler {
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // Pre-allocate with known capacity
        let mut buffer = BytesMut::with_capacity(512);
        
        // Write response
        buffer.put_slice(b"HTTP/3 200 OK\r\n");
        // ...
        
        Ok(ServiceResponse {
            data: buffer.freeze(),
            close_stream: true,
        })
    }
}
```

## Adding a New Service (Complete Example)

### 1. Create Directory and Module

```bash
mkdir -p superd/src/services/cache
```

### 2. Implement Handler (`superd/src/services/cache/mod.rs`)

```rust
//! Cache Service
//!
//! High-performance in-memory cache using DashMap.

use super::{ServiceHandler, ServiceRequest, ServiceResponse, ServiceResult, ServiceError};
use bytes::{Bytes, BytesMut, BufMut};
use dashmap::DashMap;
use std::sync::Arc;

pub struct CacheHandler {
    store: Arc<DashMap<Bytes, Bytes>>,
}

impl CacheHandler {
    pub fn new() -> Self {
        Self {
            store: Arc::new(DashMap::new()),
        }
    }
    
    fn parse_command(data: &[u8]) -> Result<(&[u8], &[u8], Option<&[u8]>), &'static str> {
        // Simple protocol: "CMD KEY [VALUE]"
        let parts: Vec<&[u8]> = data.split(|&b| b == b' ').collect();
        
        match parts.len() {
            2 => Ok((parts[0], parts[1], None)),
            3 => Ok((parts[0], parts[1], Some(parts[2]))),
            _ => Err("Invalid command format"),
        }
    }
}

impl ServiceHandler for CacheHandler {
    fn name(&self) -> &'static str {
        "cache"
    }
    
    fn description(&self) -> &'static str {
        "High-performance in-memory cache"
    }
    
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        let (cmd, key, value) = Self::parse_command(&request.data)
            .map_err(|e| ServiceError::InvalidRequest(e.to_string()))?;
        
        let response_data = match cmd {
            b"GET" => {
                self.store.get(key)
                    .map(|v| v.clone())
                    .unwrap_or_else(|| Bytes::from_static(b"NOT_FOUND"))
            }
            b"SET" => {
                if let Some(val) = value {
                    self.store.insert(Bytes::copy_from_slice(key), 
                                     Bytes::copy_from_slice(val));
                    Bytes::from_static(b"OK")
                } else {
                    Bytes::from_static(b"ERROR")
                }
            }
            b"DEL" => {
                self.store.remove(key);
                Bytes::from_static(b"OK")
            }
            _ => Bytes::from_static(b"UNKNOWN_CMD"),
        };
        
        Ok(ServiceResponse {
            data: response_data,
            close_stream: true,
        })
    }
}
```

### 3. Register in `mod.rs`

```rust
pub mod cache;

pub fn register_all_services() -> ServiceRegistry {
    let mut registry = ServiceRegistry::new();
    
    registry.register(Arc::new(echo::EchoHandler));
    registry.register(Arc::new(http3::Http3Handler::new()));
    registry.register(Arc::new(cache::CacheHandler::new()));  // Done!
    
    registry
}
```

## Performance Optimization Checklist

When implementing a service, verify:

- [ ] **No async/await** in `process()` method
- [ ] **Zero-copy** where possible (use `Bytes::slice()`)
- [ ] **Static strings** for name/description
- [ ] **Pre-allocated buffers** if allocation needed
- [ ] **No string comparisons** in hot path (use byte matching)
- [ ] **No locks** in request processing (use lock-free structures)
- [ ] **Minimal indirection** (avoid excessive trait objects)
- [ ] **Tests verify zero-copy** (pointer comparison)

## Monitoring

Service-level metrics (future enhancement):

```rust
pub struct MetricsHandler {
    requests: AtomicU64,
    errors: AtomicU64,
}

impl ServiceHandler for MetricsHandler {
    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        
        // Process...
        
        Ok(response)
    }
}
```

## Future Enhancements

- [ ] Request batching API
- [ ] Zero-copy streaming responses
- [ ] Service-specific metrics
- [ ] Dynamic service loading (plugins)
- [ ] Service middleware/interceptors
- [ ] Request/response pooling
- [ ] Service health checks
- [ ] Rate limiting per service

## Summary

The service architecture is designed for:

1. **Maximum throughput**: Sans-IO, zero-copy, no async overhead
2. **Easy extensibility**: Single registration point, directory-based modules
3. **Type safety**: Strong Rust types, compile-time checks
4. **Modularity**: Each service is self-contained

Adding a new service requires changes in exactly **ONE** place: the `register_all_services()` function in `mod.rs`.
