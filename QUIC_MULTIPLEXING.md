# QUIC Stream Multiplexing Implementation

## IETF Standards Summary

### RFC 9000 - QUIC Protocol
- **ALPN (Application-Layer Protocol Negotiation)**: Negotiated during TLS handshake
- **Stream IDs**: Unique per connection, identifies individual streams
- **Stream Types**: Client-initiated (even), Server-initiated (odd), Bidirectional/Unidirectional

### RFC 9114 - HTTP/3
- **ALPN**: `h3` for HTTP/3
- **Stream types**: Uses QUIC streams with HTTP/3 framing

### RFC 9297 - HTTP/3 DATAGRAM
- **ALPN**: `h3-datagram` or combined with `h3`
- **Datagrams**: Unreliable messages over QUIC

### ALPN Protocol IDs (Standardized)
- `h3` - HTTP/3 (RFC 9114)
- `h3-29` - HTTP/3 draft 29
- `hq-interop` - HTTP/0.9 over QUIC
- `doq` - DNS over QUIC (RFC 9250)
- `moq-00` - Media over QUIC (draft)
- `webtransport` - WebTransport

### Custom ALPN Range
- Private use: `x-*` prefix (e.g., `x-superd-echo`, `x-custom-protocol`)
- Experimental: `exp-*` prefix

## Stream Type Detection

### Method 1: ALPN-Based (Recommended)
- Single protocol per connection
- Negotiated during handshake
- All streams follow same protocol
- Example: ALPN=`h3` → All streams are HTTP/3

### Method 2: Stream-Type Header (Multiplexed)
- ALPN: `x-superd-mux` (custom multiplexing)
- First bytes of stream indicate protocol
- Format: Variable-length integer (QUIC varint) for protocol ID

#### Protocol Type Registry
```
0x00 - 0x3F: Reserved (IETF standardized)
0x40 - 0x7F: HTTP/3 stream types (RFC 9114)
  0x40: Request stream
  0x41: Push stream
  0x42: QPACK encoder stream
  0x43: QPACK decoder stream
  
0x80 - 0xBF: Reserved for extensions
0xC0 - 0xFF: Private/Experimental use
  0xC0: Echo service
  0xC1: Custom service 1
  0xC2: Custom service 2
  ...
```

## Implementation Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    QUIC Connection                       │
│  ALPN: h3 | x-superd-mux | webtransport                │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Stream 0 (Client→Server):  [Protocol ID?] + Data       │
│  Stream 4 (Client→Server):  [Protocol ID?] + Data       │
│  Stream 8 (Client→Server):  [Protocol ID?] + Data       │
│                                                           │
│  Stream 1 (Server→Client):  Response Data               │
│  Stream 5 (Server→Client):  Response Data               │
│                                                           │
├─────────────────────────────────────────────────────────┤
│                Stream Multiplexer                        │
│  • Detect protocol (ALPN or stream-type header)         │
│  • Route to appropriate service handler                  │
│  • Manage bidirectional flow                            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              Service Registry & Routing                  │
│  • ALPN → Service mapping                               │
│  • Stream-type ID → Service mapping                     │
│  • Protocol-agnostic service interface                  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                    Services                              │
│  [Echo] [HTTP/3] [WebTransport] [Custom]               │
└─────────────────────────────────────────────────────────┘
```

## Quiche Integration Points

### 1. ALPN Negotiation
```rust
// Server configuration
config.set_application_protos(&[
    b"h3",              // HTTP/3
    b"x-superd-mux",    // Multiplexed services
    b"webtransport",    // WebTransport
])?;

// After handshake
let alpn = conn.application_proto();
```

### 2. Stream Reading
```rust
// Read stream data
let (read, fin) = conn.stream_recv(stream_id, &mut buf)?;

// Detect protocol if multiplexed
if alpn == b"x-superd-mux" {
    let (protocol_id, data_offset) = decode_varint(&buf)?;
    route_to_service(protocol_id, &buf[data_offset..]);
}
```

### 3. Stream Writing
```rust
// Write response data
conn.stream_send(stream_id, response_data, true)?;
```

### 4. Stream Shutdown
```rust
// Close stream after response
conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)?;
```

## Performance Optimizations

### Zero-Copy Stream Handling
- Use `Bytes` for stream data (reference counted)
- Avoid copying data between QUIC and services
- Stream data directly from quiche buffers

### Batched Processing
- Process multiple streams in single event loop iteration
- Batch ACKs and frame generation
- Minimize syscalls

### Stream Prioritization
- Implement priority-based scheduling
- Use QUIC stream priority (RFC 9218)
- Critical streams processed first

## Implementation Plan

1. **Create `stream_mux` module** - Protocol detection and routing
2. **Extend `ServiceRequest`** - Add ALPN and protocol metadata
3. **Update QUIC engine** - Integrate stream multiplexing
4. **Add protocol registry** - Map ALPN/stream-types to services
5. **Implement bidirectional flow** - Network → QUIC → Service → QUIC → Network
6. **Add tests** - Verify multiplexing with echo and HTTP/3

## References
- RFC 9000: QUIC Transport Protocol
- RFC 9114: HTTP/3
- RFC 9297: HTTP/3 Datagrams
- RFC 9218: QUIC Stream Priorities
- Quiche docs: https://docs.rs/quiche/latest/quiche/
