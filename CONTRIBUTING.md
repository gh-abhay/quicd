# Contributing to superd

## Guidelines for LLM Agents

As an LLM agent working on this project, please adhere to the following principles and practices:

### Core Principles

- **Rust First**: All code must be written in Rust.
- **Tokio Runtime**: Use Tokio for asynchronous operations.
- **Sans-IO Methodology**: Implement services using Sans-IO patterns for non-blocking, high-throughput operations.
- **HTTP3/QUIC Only**: All transport must use HTTP3 over QUIC. Use quiche library if external QUIC support is needed.
- **High Performance**: Optimize for maximum throughput and low latency. Avoid blocking operations.
- **Monorepo Structure**: Each service is a separate crate at repo root.

### Code Structure

- `core`: Common utilities, Sans-IO abstractions, traits.
- `transport`: QUIC/HTTP3 transport layer.
- `signaling`: STUN signaling service.
- `message-relay`: Message relay with ephemeral storage.
- `sfu`: SFU for voice/video.
- `cdn`: CDN cache and delivery.
- `daemon`: Main daemon binary that orchestrates services.

### Development Workflow

1. **Understand the Task**: Read relevant code, docs, and issues before implementing.
2. **Sans-IO Design**: Design services as state machines that process inputs to outputs without I/O.
3. **Testing**: Write comprehensive tests, especially for performance and concurrency.
4. **Documentation**: Document public APIs and complex logic.
5. **Performance**: Profile and optimize bottlenecks.
6. **Security**: Ensure secure handling of data and connections.

### Best Practices

- Use workspace dependencies for common crates.
- Implement proper error handling with `thiserror` or similar.
- Use `tracing` for logging.
- Follow Rust idioms and clippy suggestions.
- Keep crates focused on single responsibilities.

### Communication

- Update this doc if new guidelines emerge.
- Document architectural decisions in code comments or separate docs.