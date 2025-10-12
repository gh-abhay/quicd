# Superd Architecture

## Overview

Superd is a high-performance QUIC daemon designed for **maximum single-machine throughput** and **ultra-low latency**. The architecture is inspired by proven systems like **Kafka**, **NATS**, **Discord**, and **Cloudflare**.

## Design Principles

### 1. Task-Based Architecture (Kafka/NATS-Inspired)
- **Separation of Concerns**: Network I/O, request processing, and service handling run as independent async tasks
- **Non-Blocking Communication**: Tasks communicate via Tokio channels with configurable buffer sizes
- **Graceful Shutdown**: All tasks coordinate shutdown through a broadcast channel

### 2. Low-Latency Optimization
- **Single-Packet Processing**: No batching - packets processed immediately upon receipt
- **Zero-Copy Buffers**: Using `Bytes` crate for zero-allocation buffer management
- **Lock-Free Metrics**: Atomic counters (`AtomicU64`) for zero-overhead statistics

### 3. Maximum Scalability (Discord/Cloudflare-Inspired)
- **High Connection Limits**: Default 100K connections to support massive concurrent user bases
- **Large Socket Buffers**: 8MB buffers for high-throughput scenarios
- **Efficient Resource Cleanup**: Periodic cleanup tasks for stale connections
- **Best-in-Class Defaults**: Optimized settings out of the box, customizable as needed

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Superd Daemon                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │  Network I/O     │      │  Request         │            │
│  │  Task            │─────▶│  Processing Task │            │
│  │                  │      │  (QUIC Engine)   │            │
│  │  • UDP Recv      │      │                  │            │
│  │  • UDP Send      │      │  • Parse QUIC    │            │
│  │  • Metrics       │◀─────│  • Generate      │            │
│  └──────────────────┘      │    Events        │            │
│                             └────────┬─────────┘            │
│                                      │                       │
│                                      ▼                       │
│                             ┌──────────────────┐            │
│                             │  Service         │            │
│                             │  Handling Task   │            │
│                             │                  │            │
│                             │  • Route Events  │            │
│                             │  • Echo Service  │            │
│                             │  • HTTP/3        │            │
│                             └──────────────────┘            │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Monitoring Tasks                                     │  │
│  │  • Metrics Logging (every 10s)                       │  │
│  │  • Connection Cleanup (every 60s)                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Shared State (Arc-wrapped)                          │  │
│  │  • Config                                            │  │
│  │  • Metrics (Lock-Free Atomics)                       │  │
│  │  • QUIC Engine (Mutex)                               │  │
│  │  • Service Registry (Mutex)                          │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### Configuration (`config.rs`)

Best-in-class configuration optimized for maximum performance:

```rust
pub struct Config {
    pub listen_addr: SocketAddr,
    pub max_connections: usize,        // Default: 100K
    pub channel_buffer_size: usize,    // Default: 8192
    pub socket_recv_buffer_size: usize,// Default: 8MB
    pub socket_send_buffer_size: usize,// Default: 8MB
    pub metrics_interval: Duration,    // Default: 10s
    pub cleanup_interval: Duration,    // Default: 60s
}
```

**Philosophy:**
- **Best Defaults**: Optimized for peak performance out of the box
- **Full Customization**: Every setting can be overridden via CLI
- **No Presets**: One optimal configuration, customizable as needed
- **Production-Ready**: Settings inspired by Discord and Cloudflare

### Metrics (`metrics.rs`)

Lock-free atomic metrics for zero-overhead monitoring:

```rust
pub struct Metrics {
    packets_received: AtomicU64,
    packets_sent: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    connections_accepted: AtomicU64,
    connections_closed: AtomicU64,
    errors: AtomicU64,
    start_time: Instant,
}
```

**Features:**
- `Relaxed` memory ordering for maximum performance
- Real-time throughput (Mbps) and packet rate calculations
- Periodic logging (every 10s) for observability

### Error Handling (`error.rs`)

Comprehensive error types with context using `thiserror`:

```rust
#[derive(Debug, Error)]
pub enum SuperdError {
    #[error("QUIC error: {0}")]
    Quic(#[from] quic::QuicError),
    
    #[error("I/O error: {0}")]
    Io(#[from] io::IoError),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),
    
    // ... more variants
}
```

**ErrorContext Trait:**
```rust
pub trait ErrorContext<T> {
    fn context(self, context: &str) -> Result<T, SuperdError>;
}
```

Enables rich error messages: `.context("Failed to bind socket")`

### Task Architecture

#### 1. Network I/O Task (`tasks/network_io.rs`)

**Responsibilities:**
- Receive UDP packets from socket
- Send UDP packets to socket
- Record metrics for all I/O operations
- Forward packets to QUIC processing

**Flow:**
```
UDP Socket ──recv()──▶ [Metrics] ──▶ to_quic_channel
to_io_channel ──▶ [Metrics] ──send()──▶ UDP Socket
```

**Error Handling:**
- Non-fatal errors logged but task continues
- Fatal errors (channel closed) trigger shutdown

#### 2. Request Processing Task (`tasks/request_processing.rs`)

**Responsibilities:**
- Process incoming QUIC packets
- Maintain QUIC connection state
- Generate QUIC events for services
- Create outgoing QUIC packets

**Flow:**
```
from_io_channel ──▶ QuicEngine.recv() ──▶ QuicEvents ──▶ to_service_channel
ServiceResponses ──▶ QuicEngine.send() ──▶ QuicPackets ──▶ to_io_channel
```

**QUIC Engine:**
- Uses `quiche` library with Sans-IO design
- Zero-copy packet handling with `Bytes`
- Connection limits enforced

#### 3. Service Handling Task (`tasks/service_handling.rs`)

**Responsibilities:**
- Route QUIC events to appropriate services
- Invoke service handlers (Echo, HTTP/3)
- Generate responses back to QUIC engine

**Flow:**
```
from_quic_channel ──▶ ServiceRegistry.handle() ──▶ ServiceResponse ──▶ to_quic_channel
```

**Services:**
- **EchoService**: Simple echo for testing
- **Http3Service**: Full HTTP/3 request/response

#### 4. Monitoring Tasks (`tasks/monitoring.rs`)

**Metrics Logging:**
- Runs every 10 seconds
- Logs throughput, packet rates, connection counts
- Useful for production observability

**Connection Cleanup:**
- Runs every 60 seconds
- Prunes stale/timed-out connections
- Prevents memory leaks

## Performance Optimizations

### 1. Zero-Copy Buffers
```rust
use bytes::Bytes;

// No allocation - just reference counting
let packet = Bytes::from(buffer);
```

### 2. Lock-Free Metrics
```rust
metrics.packets_received.fetch_add(1, Ordering::Relaxed);
```

### 3. Channel Sizing (Discord-Inspired)
- **Development**: 256 buffer size
- **Production**: 1024 buffer size  
- **High-Performance**: 8192 buffer size

Prevents backpressure while avoiding excessive memory usage.

### 4. Socket Buffers (Cloudflare-Inspired)
- **Development**: 256KB
- **Production**: 2MB
- **High-Performance**: 8MB

Large OS buffers prevent packet drops during traffic spikes.

### 5. Connection Limits
- Prevents resource exhaustion
- Graceful rejection of excess connections
- Configurable per deployment scenario

## Configuration & Usage

### Default (Best-in-Class Performance)
```bash
# Runs with optimal settings: 100K connections, 8MB buffers, 8192 channel size
cargo run --release
```

**Default Config:**
- 100,000 max connections (Discord-inspired)
- 8,192 channel buffer (high throughput)
- 8MB socket buffers (Cloudflare-inspired)
- 10s metrics interval
- 60s cleanup interval

**Use Case:** Production deployments, maximum performance

### Custom Configuration
```bash
# Override specific settings as needed
cargo run --release -- \
  --listen 0.0.0.0:4433 \
  --max-connections 50000 \
  --channel-buffer-size 4096
```

**Use Case:** Tailored to specific workload requirements

### Development/Testing
```bash
# Smaller limits for local development
cargo run -- \
  --max-connections 1000 \
  --channel-buffer-size 256 \
  --socket-recv-buffer-kb 256 \
  --socket-send-buffer-kb 256
```

**Use Case:** Local testing, debugging, resource-constrained environments

## Best Practices Applied

### From Discord
- **Massive Concurrency**: Default 100K connections for large user bases
- **Channel Buffering**: Large buffers handle bursty traffic without blocking

### From Cloudflare
- **Large Socket Buffers**: 8MB OS-level buffering prevents packet loss
- **Graceful Degradation**: Connection limits prevent resource exhaustion

### From Kafka/NATS
- **Task Separation**: Independent components for I/O, processing, services
- **Channel-Based Communication**: Decoupled, non-blocking message passing

### General Rust Best Practices
- **Error Propagation**: `?` operator with context for debugging
- **Type Safety**: Strong typing prevents runtime errors
- **Documentation**: Comprehensive module and function docs
- **Testing**: Unit tests for critical components (TODO)

## Future Enhancements

### Short-Term
- [ ] Add `socket2` crate for fine-grained socket control
- [ ] Implement comprehensive test suite
- [ ] Add tracing/OpenTelemetry integration
- [ ] Connection pooling optimizations

### Medium-Term
- [ ] Dynamic configuration reload
- [ ] Prometheus metrics export
- [ ] Rate limiting per-connection
- [ ] Zero-downtime deployment support

### Long-Term
- [ ] Multi-threaded I/O (io_uring on Linux)
- [ ] QUIC connection migration
- [ ] Advanced congestion control
- [ ] Horizontal scaling coordination

## Benchmarking

### Target Metrics (Single Daemon)
- **Throughput**: 10+ Gbps
- **Connections**: 100K+ concurrent
- **Latency**: P99 < 10ms
- **CPU**: < 80% on 8-core system

### Benchmarking Tools
```bash
# Use quiche's HTTP/3 client
cargo run --example http3-client https://localhost:4433/

# Or wrk2 for HTTP/3 load testing
wrk2 -t 8 -c 1000 -d 60s --latency https://localhost:4433/
```

## Troubleshooting

### High CPU Usage
- Check metrics for excessive connections
- Verify channel buffer sizes aren't too small
- Consider scaling to multiple daemons

### Packet Loss
- Increase socket buffer sizes
- Check OS limits: `sysctl net.core.rmem_max`
- Monitor network interface stats

### Connection Timeouts
- Increase `idle_timeout_ms`
- Check firewall/NAT settings
- Verify QUIC handshake completion

## References

- [QUIC Specification (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)
- [quiche Library](https://github.com/cloudflare/quiche)
- [Tokio Async Runtime](https://tokio.rs/)
- [Discord Engineering Blog](https://discord.com/category/engineering)
- [Cloudflare Blog](https://blog.cloudflare.com/)
