# superd

superd is a high-performance, high-throughput network daemon for edge nodes in a modern telecom infrastructure. It provides various network services to clients using QUIC as the transport protocol.

## Primary Objectives

- **Maximize concurrency, minimize latency, maximize throughput**
- Focus on performance and scalability over feature completeness
- Support real-time communication use cases

## Supported Use Cases

1. **Multi-user voice calls** - Low-latency audio streaming
2. **Multi-user video calls (SFU)** - Selective forwarding for video conferencing
3. **General signaling** - Session and control plane messaging
4. **API/HTTP calls** - CDN and standard HTTP services
5. **Live broadcast** - High-concurrency media distribution
6. **Custom message relaying** - Chat and pub/sub functionality

## Transport Stack

- **Base transport**: QUIC (HTTP/3)
- **Library**: quiche (Rust)
- **Browser clients**: WebTransport over HTTP/3
- **Native clients**: Direct QUIC

## Connection Model

- **Single UDP port per server instance**
- **Single QUIC connection per client**
- **Multiplexing**: All services share one connection via streams and datagrams
  - **Reliable streams**: API calls, signaling, message relay
  - **Unreliable datagrams**: Media plane (audio/video packets)
- **Service namespaces**: Logical separation via stream ID ranges or HTTP paths

## Architecture

The daemon is structured as a monorepo with separate crates for modularity:

- **`quic/`**: Sans-IO QUIC engine (currently stubbed, ready for full quiche integration)
- **`io/`**: Batched I/O reactor for high-performance UDP operations
- **`services/`**: Service registry with pluggable services
- **`superd/`**: Main server that orchestrates the components

### Sans-IO Design

All components follow the Sans-IO pattern:
- **QUIC Engine**: Pure logic, no I/O
- **I/O Reactor**: Handles network I/O, passes packets to QUIC
- **Services**: Process requests, generate responses
- **Main Server**: Routes data through the pipeline with zero-copy

### Zero-Copy Data Flow

1. **Receive**: I/O reactor batches UDP packets
2. **Process**: QUIC engine processes packets, extracts events
3. **Route**: Server routes events to appropriate services
4. **Handle**: Services process data without copying
5. **Respond**: Services generate responses
6. **Send**: I/O reactor sends batched responses

## Services

Currently implemented demo services:

### Echo Service
- Echoes back received data on streams or datagrams
- Useful for testing the data pipeline

### HTTP/3 Service
- Returns JSON `{"message": "Hello World", "path": "any", "timestamp": ...}` for any request
- Demonstrates HTTP/3 over QUIC streams

## Building

```bash
cargo build --release
```

## Running

```bash
./target/release/superd --listen 0.0.0.0:4433
```

## Current Status

- ✅ Modular crate architecture with separate quic/, io/, services/ crates
- ✅ Sans-IO design with zero-copy data flow
- ✅ Batched I/O reactor for high-performance UDP
- ✅ Service registry with pluggable services
- ✅ Demo echo and HTTP/3 services implemented
- ✅ Zero-copy request/response handling
- 🚧 Full QUIC implementation (quiche integration pending)
- 🚧 Per-core sharding with SO_REUSEPORT
- 🚧 Advanced I/O batching (recvmmsg/sendmmsg)
- 🚧 Production service implementations (SFU, broadcast, etc.)

## Running

```bash
cargo run --bin superd
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.