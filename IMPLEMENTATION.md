# End-to-End QUIC Stream Multiplexing Implementation

## Overview

This document describes the complete implementation of QUIC stream multiplexing in Superd, providing end-to-end packet flow from network → QUIC → services → QUIC → network.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Network Layer                            │
│  • UDP socket I/O                                                │
│  • Packet batching                                               │
│  • CPU pinning                                                   │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                      QUIC Protocol Layer                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Connection Management (quiche)                             │ │
│  │  • TLS handshake                                          │ │
│  │  • ALPN negotiation (h3, x-superd-mux, etc.)             │ │
│  │  • Stream/datagram processing                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Stream Multiplexer                                         │ │
│  │  • Protocol detection (ALPN or stream-type)               │ │
│  │  • Varint decoding for multiplexed streams                │ │
│  │  • Service routing                                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Stream Processor (Integration)                             │ │
│  │  • Read stream data → ServiceRequest                      │ │
│  │  • Route to service                                        │ │
│  │  • ServiceResponse → Write stream data                    │ │
│  └────────────────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                       Service Layer                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐                  │
│  │   Echo   │  │  HTTP/3  │  │  Custom...   │                  │
│  │  Service │  │  Service │  │   Services   │                  │
│  └──────────┘  └──────────┘  └──────────────┘                  │
│                                                                  │
│  • Sans-IO processing                                           │
│  • Zero-copy data handling                                      │
│  • Compile-time registration                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol Detection

### Method 1: ALPN-Based (Single Protocol)

**Best for**: HTTP/3, WebTransport, single-purpose connections

```rust
// Server configuration
config.set_application_protos(&[b"h3", b"webtransport"])?;

// Client connects with ALPN
// Server detects ALPN after handshake
let alpn = conn.application_proto(); // b"h3"

// All streams on this connection are HTTP/3
```

**Supported ALPN protocols**:
- `h3` - HTTP/3 (RFC 9114)
- `h3-29` - HTTP/3 draft 29
- `doq` - DNS over QUIC (RFC 9250)
- `moq-00` - Media over QUIC
- `webtransport` - WebTransport
- `x-superd-echo` - Echo service (custom)
- `x-superd-mux` - Multiplexed services (custom)

### Method 2: Stream-Type Header (Multiplexed)

**Best for**: Multiple services over single connection, custom protocols

```rust
// Client sets ALPN to multiplexing protocol
ALPN: x-superd-mux

// Each stream starts with protocol-type ID (QUIC varint)
Stream 0: [0xC0] + "hello world"    // 0xC0 = Echo service
Stream 4: [0x00] + "GET / HTTP/3"   // 0x00 = HTTP/3
Stream 8: [0xC1] + "custom data"    // 0xC1 = Custom service
```

**Protocol ID ranges** (RFC 9000 varint):
- `0x00 - 0x3F`: IETF standardized (HTTP/3, etc.)
- `0x40 - 0xBF`: Reserved for extensions
- `0xC0 - 0xFF`: Private/Experimental use

## Data Flow

### 1. Incoming Request (Client → Server)

```
1. Network receives UDP packet
2. QUIC engine processes packet
   - Decrypt with TLS
   - Parse QUIC frames
   - Update connection state
3. Stream becomes readable
4. StreamProcessor.process_stream():
   - Read stream data via conn.stream_recv()
   - Get ALPN via conn.application_proto()
   - Detect protocol via StreamMultiplexer
   - Extract payload (skip protocol-type header if present)
   - Create ServiceRequest with metadata
   - Route to appropriate service
5. Service processes request
   - Sans-IO, synchronous processing
   - Zero-copy data handling
6. Service returns ServiceResponse
```

### 2. Outgoing Response (Server → Client)

```
1. StreamProcessor receives ServiceResponse
2. Write to stream via conn.stream_send()
3. Close stream if response.close_stream == true
4. QUIC engine generates packets
   - Frame creation
   - Encryption with TLS
   - ACK generation
5. Network sends UDP packets
```

### 3. Datagram Flow (Unreliable)

```
1. Client sends QUIC datagram
2. QUIC engine receives dgram
3. StreamProcessor.process_datagram():
   - Get datagram via conn.dgram_recv()
   - Detect protocol
   - Route to service
4. Service processes and returns response
5. Send response via conn.dgram_send()
```

## Implementation Details

### Stream Multiplexer (`quic/src/stream_mux.rs`)

**Responsibilities**:
- Maintain ALPN → Protocol mappings
- Maintain Stream-Type ID → Protocol mappings
- Decode QUIC varints for multiplexed streams
- Route protocol to service name

**Key Functions**:
```rust
// Detect protocol from ALPN and optional stream-type header
fn detect_protocol(&self, alpn: &[u8], stream_data: &[u8]) -> ProtocolRoute

// Decode QUIC variable-length integer
fn decode_varint(data: &[u8]) -> Option<(u64, usize)>
```

### Stream Processor (`quic/src/integration.rs`)

**Responsibilities**:
- Bridge QUIC connection to services
- Process readable streams
- Handle datagrams
- Manage bidirectional data flow

**Key Functions**:
```rust
// Process single stream
fn process_stream(&self, conn: &mut Connection, conn_id: u64, stream_id: u64) -> Result<()>

// Process datagram
fn process_datagram(&self, conn: &mut Connection, conn_id: u64, data: Bytes) -> Result<()>

// Poll connection for all readable streams
fn poll_connection(&self, conn: &mut Connection, conn_id: u64) -> Result<()>
```

### ServiceRequest Extensions (`service/src/lib.rs`)

**Added Fields**:
```rust
pub struct ServiceRequest {
    // ... existing fields
    pub alpn: Option<Bytes>,      // Negotiated ALPN protocol
    pub protocol: Option<String>,  // Detected protocol name
}
```

## Performance Optimizations

### 1. Zero-Copy Data Handling
- Use `Bytes` (Arc-based) throughout the stack
- No data copying between QUIC and services
- Slice operations instead of allocations

### 2. Pre-Allocated Buffers
- 64KB buffers for stream reads
- Reused across requests
- Minimal allocations in hot path

### 3. Batched Stream Processing
- Process all readable streams in single iteration
- Minimize context switches
- Efficient ACK generation

### 4. Compile-Time Protocol Registry
- Protocol mappings known at compile time
- Fast HashMap lookups (O(1))
- No runtime discovery overhead

## Usage Examples

### Server Configuration

```rust
// In QUIC engine initialization
let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
config.set_application_protos(&[
    b"h3",              // HTTP/3
    b"x-superd-mux",    // Multiplexed services
    b"x-superd-echo",   // Echo service
])?;

// Create multiplexer
let mux = Arc::new(StreamMultiplexer::new());

// Create stream processor
let processor = Arc::new(StreamProcessor::new(mux, services));

// In event loop
for event in quic_events {
    match event {
        QuicEvent::StreamReadable { conn_id, stream_id } => {
            processor.process_stream(&mut conn, conn_id, stream_id)?;
        }
        // ... other events
    }
}
```

### Client Connection (HTTP/3)

```
1. Client initiates QUIC connection
2. TLS handshake with ALPN = "h3"
3. Client opens stream and sends HTTP/3 request
4. Server detects ALPN = "h3" → routes to HTTP/3 service
5. HTTP/3 service processes request
6. Server sends HTTP/3 response on same stream
```

### Client Connection (Multiplexed)

```
1. Client initiates QUIC connection
2. TLS handshake with ALPN = "x-superd-mux"
3. Client opens multiple streams:
   - Stream 0: [0xC0] + "hello" (Echo)
   - Stream 4: [0x00] + "GET /" (HTTP/3)
4. Server detects ALPN = "x-superd-mux"
5. Each stream:
   - Read protocol-type ID (varint)
   - Route to appropriate service
   - Process and respond
```

## Adding New Services

### 1. Create Service Crate

```rust
// my-service/src/lib.rs
pub struct MyService;

impl ServiceHandler for MyService {
    fn name(&self) -> &'static str { "myservice" }
    fn process(&self, req: ServiceRequest) -> ServiceResult<ServiceResponse> {
        // Process request
        Ok(ServiceResponse { 
            data: Bytes::from("response"),
            close_stream: true,
        })
    }
}

pub const MY_SERVICE: service::ServiceFactory = service::ServiceFactory {
    name: "myservice",
    description: "My custom service",
    factory: || Arc::new(MyService),
};
```

### 2. Register Protocol

```rust
// Option A: ALPN-based (single protocol)
mux.register_alpn(b"x-my-protocol", Protocol::Custom(100), "myservice");

// Option B: Stream-type (multiplexed)
mux.register_stream_type(0xC3, Protocol::Custom(100), "myservice");
```

### 3. Update Service Array

```rust
// superd/src/lib.rs
pub const ALL_SERVICES: &[ServiceFactory] = &[
    echo::ECHO_SERVICE,
    http3::HTTP3_SERVICE,
    my_service::MY_SERVICE,  // Add here
];
```

## Testing

### Unit Tests
- Varint encoding/decoding
- ALPN detection
- Stream-type detection
- Protocol routing

### Integration Tests
```rust
#[test]
fn test_echo_via_alpn() {
    let mux = StreamMultiplexer::new();
    let route = mux.detect_protocol(b"x-superd-echo", b"hello");
    assert_eq!(route.service_name, "echo");
    assert_eq!(route.data_offset, 0);
}

#[test]
fn test_http3_via_stream_type() {
    let mux = StreamMultiplexer::new();
    let data = vec![0x00, b'G', b'E', b'T']; // Type 0x00 + "GET"
    let route = mux.detect_protocol(b"x-superd-mux", &data);
    assert_eq!(route.service_name, "http3");
    assert_eq!(route.data_offset, 1); // Skip varint
}
```

## References

### RFCs
- **RFC 9000**: QUIC Transport Protocol
- **RFC 9114**: HTTP/3
- **RFC 9297**: HTTP/3 Datagrams
- **RFC 9218**: Extensible Prioritization Scheme for HTTP
- **RFC 9250**: DNS over Dedicated QUIC Connections

### Implementation
- **Quiche**: https://docs.rs/quiche/latest/quiche/
- **IETF ALPN Registry**: https://www.iana.org/assignments/tls-extensiontype-values/

### Performance
- Stream priorities (RFC 9218)
- Zero-copy I/O
- CPU pinning (NUMA-aware)
- Batch processing

## Conclusion

The implementation provides:

✅ **Standards-compliant** QUIC stream multiplexing  
✅ **Flexible protocol detection** (ALPN or stream-type)  
✅ **Zero-copy data flow** (network → service → network)  
✅ **Extensible service architecture** (compile-time registration)  
✅ **Maximum performance** (Sans-IO, batch processing)  

The system is production-ready for high-throughput, low-latency QUIC services with support for both standardized protocols (HTTP/3) and custom multiplexed services.
