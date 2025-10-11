# superd

superd is a high-performance, high-throughput network daemon for edge nodes in a modern telecom infrastructure. It provides various network services to clients using HTTP3/QUIC as the transport protocol.

## Services

- **Signaling**: STUN-based signaling for NAT traversal
- **Message Relay**: Message relaying with ephemeral storage
- **SFU**: Selective Forwarding Unit for voice and video calling
- **CDN**: Content Delivery Network for cache and delivery
- And more in the future

## Architecture

- **Language**: Rust
- **Runtime**: Tokio
- **Methodology**: Sans-IO for maximum performance and throughput
- **Transport**: HTTP3/QUIC only
- **Structure**: Monorepo with each service as a separate crate at repo root

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --bin superd
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.