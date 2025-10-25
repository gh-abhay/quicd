# SuperD - High-Performance UDP Socket Service

A modern, high-throughput UDP server built with Rust, featuring:
- **io_uring**: Linux's cutting-edge async I/O for maximum performance
- **Zero-Copy Architecture**: Buffers flow through the stack without copying
- **Event-Driven I/O**: Inspired by NGINX and ejabberd
- **Sans-IO Design**: Clean separation of network, protocol, and application layers

## Architecture

```
┌─────────────────────────────────────────────────┐
│         Application Layer (Tokio Async)         │
└────────────────────┬────────────────────────────┘
                     │ Zero-Copy Buffers
┌────────────────────▼────────────────────────────┐
│      Protocol Layer - QUIC (Tokio Async)        │
└────────────────────┬────────────────────────────┘
                     │ Zero-Copy Buffers
┌────────────────────▼────────────────────────────┐
│  Network Layer (Native Threads + io_uring)      │
│   • Fixed thread count                          │
│   • CPU pinning                                 │
│   • SO_REUSEPORT load balancing                 │
│   • Batch I/O operations                        │
└─────────────────────────────────────────────────┘
```

## Features

### Performance
- **io_uring**: 60+ I/O operations per syscall (vs 4-5 with epoll)
- **Zero-Copy**: Arc-based buffer sharing across layers
- **CPU Pinning**: Interleaved pinning to reduce cache thrashing
- **Batch Processing**: Minimize syscalls and context switches

### Scalability
- **Fixed Thread Pools**: Predictable resource usage
- **Event-Driven**: Thousands of connections per thread
- **SO_REUSEPORT**: Kernel-level load balancing
- **Millions of Connections**: Proven patterns from NGINX

### Design
- **Sans-IO**: Independent network, protocol, and application layers
- **Type-Safe**: Strong typing for zero-copy buffers
- **Async Runtime**: Tokio for protocol and application layers
- **Comprehensive Metrics**: Built-in observability

## Quick Start

### Build
```bash
cargo build --release
```

### Run
```bash
./target/release/superd --listen 0.0.0.0:4433
```

### With Custom Configuration
```bash
./target/release/superd \
  --listen 0.0.0.0:4433 \
  --network-threads 4 \
  --protocol-threads 8 \
  --cpu-pinning true
```

### Using Config File
```bash
./target/release/superd --config config.toml
```

Example `config.toml`:
```toml
listen = "0.0.0.0:4433"
network_threads = 4
protocol_threads = 8
cpu_pinning = true

[telemetry]
otlp_endpoint = "http://localhost:4317"
service_name = "superd"

[quic]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
verify_peer = false
enable_early_data = false
application_protos = ["superd/0.1"]
```

## Configuration

### Thread Allocation
- **Network Threads**: Auto-tuned based on available CPUs for io_uring workers
- **Protocol Threads**: Auto-tuned (often 2-4x network threads) for QUIC processing

Example on 16-core system:
- 4 network threads (io_uring)
- 8 protocol tasks (QUIC parsing + crypto)
- Application tasks scale dynamically per connection/stream

### CPU Pinning
Interleaved strategy to reduce cache contention:
- Thread 0 → CPU 0
- Thread 1 → CPU 2
- Thread 2 → CPU 4
- Thread 3 → CPU 6

## Performance Expectations

Based on research and proven systems:

- **Throughput**: 9.5+ Gbps per node
- **Latency**: Sub-millisecond with io_uring
- **Connections**: Millions per node
- **Memory**: ~28-50KB per connection
- **Packets/sec**: 1M+ packets/sec

## Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) - Comprehensive design documentation
- [Implementation Summary](docs/IMPLEMENTATION_SUMMARY.md) - What we built and why

## Technology Stack

### Core
- **Rust 2021**: Memory safety + performance
- **Tokio**: Async runtime for protocol and application
- **io_uring**: Modern Linux async I/O (via tokio-uring)

### Network
- **quiche**: QUIC protocol implementation with TLS
- **tokio-uring**: High-performance UDP I/O
- **socket2**: Low-level socket control

### Observability
- **tracing**: Structured logging
- **OpenTelemetry**: Metrics and traces
- **OTLP**: Export to observability backends

## Inspiration

This project applies best practices from industry leaders:

### NGINX
- Event-driven non-blocking I/O
- Fixed worker processes
- Thread pools for blocking operations
- Proven to handle millions of connections

### ejabberd
- 2M concurrent users on single node
- Lightweight concurrency model (adapted to Rust)
- Efficient memory usage (~28KB per user)
- Message passing architecture

### Modern Linux
- io_uring for minimal syscalls
- SO_REUSEPORT for kernel load balancing
- Large socket buffers for throughput
- CPU pinning for cache efficiency

## Development Status

✅ **Phase 1 Complete**: Network Layer
- io_uring-based I/O
- Zero-copy buffer pool
- CPU pinning
- Metrics and observability

🚧 **Phase 2 In Progress**: Protocol Layer
- QUIC implementation (quiche)
- Connection management
- Flow control and reliability

📋 **Phase 3 Planned**: Application Layer
- Business logic framework
- Request routing
- Integration tests
- Performance benchmarks

## Requirements

- **Linux**: io_uring requires Linux 5.14+
- **Rust**: 1.70+
- **Tokio**: 1.x

## License

[Your License Here]

## Contributing

Contributions welcome! When making changes:
1. Maintain zero-copy principles
2. No blocking operations in async code
3. Add tests for new features
4. Update documentation
5. Follow Rust idioms

## References

- [io_uring and Network I/O](https://developers.redhat.com/articles/2023/04/12/why-you-should-use-iouring-network-io)
- [NGINX Architecture](https://www.nginx.com/blog/inside-nginx-how-we-designed-for-performance-scale/)
- [ejabberd 2M Users](https://blog.process-one.net/ejabberd-massive-scalability-2million-concurrent-users/)
- [QUIC Protocol](https://www.chromium.org/quic/)
