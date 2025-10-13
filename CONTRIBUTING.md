# Contributing to Superd

Thank you for your interest in contributing to Superd! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Architecture Principles](#architecture-principles)
- [Performance Guidelines](#performance-guidelines)

## Code of Conduct

This project follows the Rust Code of Conduct. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Rust 1.70+ (stable)
- Basic understanding of:
  - Async/await in Rust
  - Network programming (UDP, sockets)
  - QUIC protocol basics
  - Multi-threaded programming

### First Steps

1. **Fork and clone** the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/superd.git
   cd superd
   ```

2. **Build the project**:
   ```bash
   cargo build
   ```

3. **Run tests**:
   ```bash
   cargo test
   ```

4. **Check code quality**:
   ```bash
   cargo clippy
   cargo fmt --check
   ```

## Development Setup

### Recommended Tools

- **IDE**: VS Code with rust-analyzer extension
- **Debugging**: `rust-gdb` or `rust-lldb`
- **Profiling**: `perf`, `flamegraph`, `cargo-flamegraph`
- **Benchmarking**: `criterion` (for microbenchmarks)

### Environment Setup

```bash
# Install development tools
cargo install cargo-watch
cargo install cargo-expand
cargo install cargo-flamegraph

# Set up git hooks (recommended)
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
cargo fmt --check
cargo clippy -- -D warnings
EOF
chmod +x .git/hooks/pre-commit
```

## Project Structure

```
superd/
├── network/              # Network I/O layer
│   ├── src/
│   │   ├── lib.rs       # Public API exports
│   │   ├── config.rs    # Network configuration
│   │   ├── io_thread.rs # I/O thread implementation
│   │   └── thread_mgmt.rs # CPU pinning, priorities
│   └── Cargo.toml
│
├── quic/                 # QUIC protocol layer
│   ├── src/
│   │   ├── lib.rs       # Public API and quiche integration
│   │   └── protocol_handler.rs # QUIC handler threads
│   └── Cargo.toml
│
├── superd/               # Main daemon binary
│   ├── src/
│   │   ├── main.rs      # CLI entry point
│   │   ├── lib.rs       # Daemon orchestration
│   │   └── config.rs    # Configuration management
│   └── Cargo.toml
│
└── Cargo.toml            # Workspace definition
```

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `perf/description` - Performance improvements
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) standard:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `perf`: Performance improvement
- `refactor`: Code refactoring
- `docs`: Documentation changes
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

**Examples:**
```
feat(network): add SO_REUSEPORT support

Implements SO_REUSEPORT to enable kernel-level load balancing
across multiple I/O threads.

Closes #42
```

```
perf(quic): optimize packet processing loop

Reduces allocations by reusing buffers. Improves throughput by 15%.
```

## Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` with default settings
- Maximum line length: 100 characters
- Use meaningful variable names (avoid single letters except for iterators)

### Code Organization

```rust
// Module structure (order matters)
use std::...;          // Standard library imports
use external_crate::...;  // External crate imports
use crate::...;        // Internal crate imports

mod submodule;         // Module declarations

// Constants and statics
const MAX_SIZE: usize = 1024;

// Type definitions
type Result<T> = std::result::Result<T, Error>;

// Structs and enums
pub struct MyStruct { ... }

// Trait implementations
impl MyStruct { ... }

// Functions
pub fn main() { ... }
```

### Error Handling

- Use `Result<T, E>` for recoverable errors
- Use `panic!` only for unrecoverable programmer errors
- Provide context with errors using `anyhow` or custom error types
- Document error conditions in function documentation

```rust
/// Processes a QUIC packet.
///
/// # Errors
///
/// Returns an error if:
/// - Packet is malformed
/// - Connection ID is invalid
/// - Buffer is too small
pub fn process_packet(packet: &[u8]) -> Result<ProcessedPacket> {
    // Implementation
}
```

### Documentation

- **Public APIs**: Must have documentation comments
- **Complex logic**: Add inline comments explaining "why", not "what"
- **Examples**: Include examples for non-trivial APIs

```rust
/// Creates a new network I/O thread.
///
/// The thread will be pinned to the specified CPU core and will use
/// SO_REUSEPORT for load balancing.
///
/// # Arguments
///
/// * `thread_id` - Unique identifier for this thread
/// * `cpu_core` - CPU core to pin this thread to
/// * `socket_addr` - Address to bind the UDP socket to
///
/// # Examples
///
/// ```
/// use network::IoThread;
/// use std::net::SocketAddr;
///
/// let addr: SocketAddr = "0.0.0.0:4433".parse().unwrap();
/// let thread = IoThread::new(0, 0, addr)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Socket binding fails
/// - CPU pinning fails (if enabled)
pub fn new(thread_id: usize, cpu_core: usize, socket_addr: SocketAddr) 
    -> Result<Self> {
    // Implementation
}
```

## Testing Guidelines

### Test Organization

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Test implementation
    }

    #[test]
    #[should_panic(expected = "invalid state")]
    fn test_error_condition() {
        // Test implementation
    }

    #[tokio::test]
    async fn test_async_functionality() {
        // Async test implementation
    }
}
```

### Test Coverage

- **Unit tests**: Test individual functions and methods
- **Integration tests**: Test crate interactions (in `tests/` directory)
- **Benchmarks**: For performance-critical code (in `benches/` directory)

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test --package network

# Run tests with output
cargo test -- --nocapture

# Run ignored tests (e.g., requires special setup)
cargo test -- --ignored
```

### Performance Tests

For performance-critical changes, include benchmark results:

```bash
# Run benchmarks
cargo bench

# Compare before/after
cargo bench --bench my_benchmark > before.txt
# Make changes
cargo bench --bench my_benchmark > after.txt
# Compare results
```

## Pull Request Process

### Before Submitting

1. **Update documentation** for any changed APIs
2. **Add tests** for new functionality
3. **Run all checks**:
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```
4. **Update CHANGELOG.md** (if applicable)
5. **Rebase** on latest `main` branch

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Motivation
Why is this change needed? What problem does it solve?

## Changes
- List of changes made
- One change per line

## Testing
How was this tested? Include:
- Unit tests added/modified
- Integration tests added/modified
- Manual testing performed

## Performance Impact
(If applicable)
- Benchmarks before/after
- Memory usage impact
- CPU usage impact

## Breaking Changes
(If applicable)
List any breaking changes and migration path.

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code follows project style
- [ ] All tests pass
- [ ] Clippy warnings addressed
- [ ] Code formatted with rustfmt
```

### Review Process

1. **Automated checks** must pass (CI)
2. **Code review** by at least one maintainer
3. **Performance review** for performance-critical changes
4. **Documentation review** for public API changes

## Architecture Principles

### Three-Layer Design

All changes must respect the three-layer architecture:

1. **Network I/O Layer** (`network` crate)
   - OS threads for UDP operations
   - CPU pinning and thread priorities
   - SO_REUSEPORT load balancing

2. **QUIC Protocol Layer** (`quic` crate)
   - QUIC packet processing
   - Connection state management
   - Protocol-level operations

3. **Application Layer** (`superd` crate)
   - Connection management
   - Service routing
   - Business logic

### Separation of Concerns

- **No I/O in QUIC layer**: QUIC handlers receive packets via channels
- **No business logic in network layer**: I/O threads only do network operations
- **Clear boundaries**: Use well-defined interfaces between layers

### Example Layering

```rust
// ❌ Bad: I/O logic in application layer
async fn handle_connection() {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.recv_from(&mut buf).await?;
}

// ✅ Good: Use network layer abstraction
async fn handle_connection() {
    let packet = network_rx.recv().await?;
    process_packet(packet);
}
```

## Performance Guidelines

### Key Principles

1. **Zero-copy when possible**: Use `Bytes` for shared buffers
2. **Avoid allocations in hot paths**: Reuse buffers
3. **Lock-free data structures**: Use atomics, channels
4. **CPU cache locality**: Keep related data together
5. **Minimize context switches**: Use CPU pinning

### Performance Checklist

- [ ] No allocations in packet processing loop
- [ ] Buffer reuse for repeated operations
- [ ] Appropriate data structure choices (HashMap vs Vec)
- [ ] Atomic operations use `Relaxed` ordering when appropriate
- [ ] No locks in critical path
- [ ] CPU pinning configured correctly

### Benchmarking

For performance-critical code, provide benchmarks:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn process_packet_benchmark(c: &mut Criterion) {
    let packet = create_test_packet();
    
    c.bench_function("process_packet", |b| {
        b.iter(|| process_packet(black_box(&packet)))
    });
}

criterion_group!(benches, process_packet_benchmark);
criterion_main!(benches);
```

## Common Contribution Areas

### Good First Issues

Look for issues labeled `good-first-issue`:
- Documentation improvements
- Test coverage improvements
- Error message improvements
- Configuration validation

### Advanced Contributions

- Performance optimizations
- New QUIC features
- Advanced CPU scheduling strategies
- NUMA optimizations

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue with reproduction steps
- **Security**: Email security@example.com (do not open public issues)

## License

By contributing, you agree that your contributions will be dual-licensed under MIT and Apache-2.0.

---

Thank you for contributing to Superd! 🚀
