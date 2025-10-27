# SuperD

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/klaalabs/superd/ci.yml)](https://github.com/klaalabs/superd/actions)

A high-performance, zero-copy UDP server built with Rust, designed for million-user scale with sub-microsecond latency. SuperD leverages Linux's io_uring for maximum I/O performance and implements the QUIC protocol for secure, multiplexed connections.

## 🚀 Key Features

- **Blazing Fast I/O**: Uses Linux io_uring for asynchronous I/O operations
- **Zero-Copy Architecture**: Buffers flow through the stack without copying
- **QUIC Protocol**: Modern transport protocol with TLS 1.3 encryption
- **HTTP/3 Support**: Content serving and WebTransport APIs
- **Event-Driven Design**: Inspired by NGINX and ejabberd patterns
- **Sans-IO Architecture**: Clean separation of network, protocol, and application layers
- **SO_REUSEPORT**: Kernel-level load balancing across multiple processes
- **OpenTelemetry**: Comprehensive observability and monitoring
- **Auto-Tuning**: Automatic configuration based on system capabilities

## 📊 Performance

- **Throughput**: 9.5+ Gbps per node
- **Latency**: Sub-millisecond packet processing
- **Connections**: Millions of concurrent connections
- **Memory**: ~28-50KB per active connection

## 🏗️ Architecture

SuperD uses a multi-layer async architecture for optimal performance and scalability:

```
┌─────────────────────────────────────────────────┐
│   Application Layer (Dynamic Per-Stream Tasks)  │
│   • Spawned on-demand per QUIC stream          │
│   • ALPN-based routing (HTTP/3, WebTransport)   │
│   • Ephemeral: lifecycle tied to stream        │
└────────────────────┬────────────────────────────┘
                     │ Stream Data
┌────────────────────▼────────────────────────────┐
│      Protocol Layer - QUIC (Async Tasks)        │
│   • CPU-bound: TLS 1.3 crypto operations       │
│   • Connection state & congestion control       │
│   • 2-4x network tasks (crypto scaling)         │
└────────────────────┬────────────────────────────┘
                     │ Encrypted Packets
┌────────────────────▼────────────────────────────┐
│  Network Layer (Async io_uring Tasks)           │
│   • I/O-bound: raw socket operations           │
│   • 1 task per physical core                   │
│   • SO_REUSEPORT load balancing                 │
│   • Fan-out to protocol tasks                   │
└─────────────────────────────────────────────────┘
```

## 🛠️ Quick Start

### Prerequisites

- Rust 1.70 or later
- Linux kernel 5.10+ (for io_uring support)
- TLS certificates (self-signed or CA-issued)

### Installation

```bash
# Clone the repository
git clone https://github.com/klaalabs/superd.git
cd superd

# Build the project
cargo build --release

# Run tests
cargo test
```

### Basic Usage

```bash
# Start with default configuration (auto-tuned for your system)
./target/release/superd

# Start with custom config file
./target/release/superd --config config.toml

# Start with CLI configuration
./target/release/superd --listen 0.0.0.0:4433 --network-threads 4 --protocol-threads 8

# Enable debug logging
RUST_LOG=debug ./target/release/superd
```

### Configuration

SuperD supports multiple configuration methods:

#### Configuration File (config.toml)

```toml
listen = "0.0.0.0:4433"
network_threads = 4
protocol_threads = 12
cpu_pinning = true

[telemetry]
otlp_endpoint = "http://localhost:4317"
service_name = "superd"

[quic]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
verify_peer = false
enable_early_data = false
application_protos = ["h3"]
max_idle_timeout_ms = 30000
initial_max_data = 4194304
initial_max_stream_data_bidi_local = 1048576
initial_max_stream_data_bidi_remote = 1048576
initial_max_stream_data_uni = 1048576
initial_max_streams_bidi = 128
initial_max_streams_uni = 64
max_send_udp_payload_size = 1350
max_recv_udp_payload_size = 65536
```

#### Command Line Options

```bash
superd --help
```

#### Auto-Tuning

SuperD automatically tunes configuration based on your system's capabilities:

```bash
# Enable auto-tuning (default: true)
./target/release/superd --auto-tune true
```

### TLS Certificates

Generate self-signed certificates for development:

```bash
# Create certs directory
mkdir -p certs

# Generate private key
openssl genrsa -out certs/server.key 2048

# Generate certificate
openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

## 📡 Supported Protocols

### HTTP/3 Content Serving

SuperD serves HTTP/3 content with endpoints for:
- Health checks (`GET /health`)
- API information (`GET /api`)
- Static content serving

### WebTransport APIs

Real-time bidirectional communication over HTTP/3 streams:
- Generic API channels
- Events API for pub/sub patterns
- Realtime API for low-latency data

## 🔍 Monitoring & Observability

SuperD provides comprehensive telemetry:

### Logging

Structured logging with configurable levels:

```bash
# Set log level
RUST_LOG=info ./target/release/superd
RUST_LOG=debug ./target/release/superd
```

### Metrics

OpenTelemetry integration for external monitoring:

```toml
[telemetry]
otlp_endpoint = "http://localhost:4317"
service_name = "superd"
```

### Health Checks

Built-in health endpoints:
- `GET /health` - Server health status
- `GET /api` - API information and capabilities

## 🧪 Testing & Benchmarks

```bash
# Run all tests
cargo test

# Run benchmarks
cargo bench

# Run specific test
cargo test test_name

# Run with release optimizations
cargo test --release
```

## 🚀 Production Deployment

### System Requirements

- **OS**: Linux (kernel 5.10+)
- **CPU**: Multi-core system (4+ cores recommended)
- **Memory**: 4GB+ RAM
- **Network**: High-speed networking (10Gbps+)

### Scaling Configuration

For high-scale deployments:

```toml
# Scale network threads with CPU cores
network_threads = 8

# Scale protocol threads for crypto operations
protocol_threads = 32

# Optimize buffer pools for your workload
# (Auto-tuned by default)
```

### Load Balancing

Use SO_REUSEPORT for multi-process load balancing:

```bash
# Start multiple instances on the same port
./target/release/superd --listen 0.0.0.0:4433 &
./target/release/superd --listen 0.0.0.0:4433 &
./target/release/superd --listen 0.0.0.0:4433 &
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone and build
git clone https://github.com/klaalabs/superd.git
cd superd
cargo build

# Run tests
cargo test

# Format code
cargo fmt

# Lint code
cargo clippy
```

### Architecture Guidelines

- **Zero-Copy**: Minimize data copying throughout the stack
- **Async First**: Use async/await patterns consistently
- **Layer Separation**: Keep network, protocol, and application concerns separate
- **Performance**: Profile and optimize hot paths

## 📚 Documentation

- [API Documentation](https://docs.rs/superd/) - Generated Rust docs
- [Architecture Overview](docs/architecture.md) - Detailed architecture docs
- [Performance Guide](docs/performance.md) - Performance tuning guide
- [Deployment Guide](docs/deployment.md) - Production deployment instructions

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

SuperD builds upon the excellent work of:
- [quiche](https://github.com/cloudflare/quiche) - Cloudflare's QUIC implementation
- [tokio-uring](https://github.com/tokio-rs/tokio-uring) - Tokio's io_uring integration
- [buffer-pool](https://github.com/klaalabs/buffer-pool) - Zero-copy buffer management

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/klaalabs/superd/issues)
- **Discussions**: [GitHub Discussions](https://github.com/klaalabs/superd/discussions)
- **Documentation**: [Wiki](https://github.com/klaalabs/superd/wiki)

---

**SuperD** - High-performance networking, reimagined in Rust.
