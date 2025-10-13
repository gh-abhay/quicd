# superd - High-Performance QUIC Multi-Service Daemon

**Version 2.0** - Production-Ready Architecture

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

A high-performance QUIC daemon designed for maximum throughput and scalability, inspired by production systems at Cloudflare, Kafka, and Discord.

## 🚀 Performance Targets

- **100,000+** concurrent connections
- **1,000,000+** packets per second
- **Sub-millisecond** latency (p99 < 1ms)
- **Zero packet loss** under normal load

## 🏗️ Architecture

superd implements a three-layer architecture optimized for high-throughput packet processing:

```
┌─────────────────────────────────────────────────────────────┐
│                  superd Architecture V2                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Layer 1: Network I/O Threads (OS threads, CPU-pinned)       │
│  ├─ Thread 0: UDP recv/send → Channel 0                     │
│  ├─ Thread 1: UDP recv/send → Channel 1                     │
│  └─ ...                                                       │
│                                                               │
│  Layer 2: QUIC Protocol Handlers (OS threads, CPU-pinned)    │
│  ├─ Handler 0: Channel 0 → QUIC processing                  │
│  ├─ Handler 1: Channel 1 → QUIC processing                  │
│  └─ ...                                                       │
│                                                               │
│  Layer 3: Connection Management (Tokio tasks)                │
│  ├─ Task 1: Connection 1                                     │
│  ├─ Task 2: Connection 2                                     │
│  └─ ... (100K+ tasks)                                        │
│                                                               │
│  Tokio Runtime: Multi-threaded work-stealing runtime         │
│  └─ Workers: Dedicated or Shared CPUs (configurable)        │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Layer 1: Network I/O Threads

**Purpose:** UDP socket reception and transmission

**Characteristics:**
- OS-level threads (not Tokio tasks)
- CPU-pinned for cache locality
- NUMA-aware placement
- SO_REUSEPORT for kernel load balancing
- Capacity: ~500K pps per thread (Cloudflare proven)

### Layer 2: QUIC Protocol Handlers

**Purpose:** QUIC packet processing (decrypt, parse, state management)

**Characteristics:**
- OS-level threads (not Tokio tasks)
- CPU-pinned adjacent to I/O threads
- 1:1 mapping with I/O threads (dedicated channels)
- Zero channel contention
- Capacity: ~500K pps per handler

### Layer 3: Connection Management

**Purpose:** Per-connection application logic

**Characteristics:**
- Tokio async tasks (lightweight)
- Spawn on-demand (one per connection)
- Work-stealing scheduler
- Scales to millions of connections

## 📊 Performance Comparison

| Configuration | Throughput | Connections | Latency |
|--------------|------------|-------------|---------|
| 4-core | 500K pps | 50K+ | <1ms |
| 8-core | 1M pps | 100K+ | <500µs |
| 16-core | 2M pps | 200K+ | <500µs |
| 32-core | 4M pps | 500K+ | <300µs |

## 🔧 Installation

### Prerequisites

- Rust 1.70 or later
- Linux kernel 3.9+ (for SO_REUSEPORT)
- (Optional) CAP_SYS_NICE capability for high-priority threads

### Build from Source

```bash
git clone https://github.com/klaalabs/superd.git
cd superd
cargo build --release
```

The binary will be at `target/release/superd`.

### Install

```bash
cargo install --path superd
```

## 🚀 Quick Start

### Run with Default Settings

```bash
superd
```

This auto-detects your CPU count and configures optimal thread counts.

### Custom Configuration

```bash
# 4 I/O threads, 4 QUIC handlers
superd --network-io-threads 4 --quic-handlers 4

# Listen on specific address
superd --listen 0.0.0.0:443

# High-priority I/O threads (requires CAP_SYS_NICE)
superd --io-priority max

# Disable CPU pinning (for containers)
superd --no-pin-io --no-pin-quic
```

### Load from Config File

```bash
superd --config /etc/superd/config.toml
```

See `superd.toml.example` for a full configuration example.

## ⚙️ Configuration

### Auto-Detected Defaults

superd automatically detects your hardware and configures optimal settings:

| CPU Cores | I/O Threads | QUIC Handlers | Tokio Workers |
|-----------|-------------|---------------|---------------|
| 1 | 1 | 1 | 1 |
| 2-4 | 1 | 1 | 2-3 |
| 5-8 | 2 | 2 | 4 |
| 9-16 | 4 | 4 | 8 |
| 17-32 | 8 | 8 | 16 |
| 33+ | 8 | 8 | 24+ |

### Thread Placement

**Interleaved Strategy** (Default):
```
CPU 0: I/O Thread 0
CPU 1: QUIC Handler 0
CPU 2: I/O Thread 1
CPU 3: QUIC Handler 1
CPU 4-7: Tokio Workers
```

Benefits:
- I/O and QUIC pairs share L3 cache
- Optimal memory locality
- Thermal distribution

### CPU Allocation Modes

#### Dedicated Mode (Default, Safe)

```bash
superd --tokio-cpu-mode dedicated
```

- Tokio workers use **only unpinned CPUs**
- Zero cache pollution on I/O path
- Predictable performance
- **Recommended for production**

#### Shared Mode (Experimental, Efficient)

```bash
superd --tokio-cpu-mode shared
```

- Tokio workers can use **all CPUs** (work-stealing)
- Uses idle cycles from I/O/QUIC threads
- Requires I/O+QUIC < 50% CPU usage
- **Use only after profiling**

## 📝 Configuration Options

### Network I/O Layer

| Option | Default | Description |
|--------|---------|-------------|
| `--network-io-threads` | auto | Number of I/O threads (1-8) |
| `--no-pin-io` | false | Disable CPU pinning |
| `--no-numa` | false | Disable NUMA awareness |
| `--io-priority` | high | Thread priority (low/normal/high/max) |
| `--cpu-affinity` | interleaved | CPU placement strategy |

### QUIC Protocol Layer

| Option | Default | Description |
|--------|---------|-------------|
| `--quic-handlers` | auto | Number of handlers (must equal I/O threads) |
| `--no-pin-quic` | false | Disable CPU pinning |
| `--quic-priority` | normal | Thread priority |
| `--channel-buffer` | 8192 | Channel buffer size (packets) |

### Tokio Runtime

| Option | Default | Description |
|--------|---------|-------------|
| `--tokio-workers` | auto | Number of worker threads |
| `--tokio-cpu-mode` | dedicated | CPU allocation mode |

### Server

| Option | Default | Description |
|--------|---------|-------------|
| `--listen` | 0.0.0.0:4433 | Listen address |
| `--max-connections` | 100000 | Max concurrent connections |
| `--socket-recv-buffer` | 8388608 | Socket RX buffer (bytes) |
| `--socket-send-buffer` | 8388608 | Socket TX buffer (bytes) |

### Monitoring

| Option | Default | Description |
|--------|---------|-------------|
| `--metrics-interval` | 10 | Metrics logging interval (seconds) |
| `--debug` | false | Enable debug logging |
| `--profiling` | false | Enable profiling hooks |

## 📈 Monitoring

### Metrics Logging

superd logs performance metrics every 10 seconds (configurable):

```
[INFO] Metrics:
  Packets received: 1,234,567
  Packets processed: 1,234,567
  Active connections: 12,345
  CPU usage: 45%
  Memory usage: 2.3 GB
```

### Performance Profiling

Enable profiling hooks for integration with `perf` and `flamegraph`:

```bash
superd --profiling

# In another terminal
sudo perf record -F 99 -p $(pgrep superd) -g -- sleep 30
sudo perf script | flamegraph.pl > flame.svg
```

## 🔒 Security & Permissions

### Running as Non-Root

superd can run as non-root, but some features require privileges:

| Feature | Requires | Workaround |
|---------|----------|------------|
| Bind to port < 1024 | CAP_NET_BIND_SERVICE | Use port ≥ 1024 or setcap |
| High-priority threads | CAP_SYS_NICE | Run with normal priority |
| CPU pinning | CAP_SYS_ADMIN (containers) | Disable pinning |

#### Grant Capabilities

```bash
sudo setcap 'cap_net_bind_service,cap_sys_nice=+ep' ./superd
```

### Running in Containers

Disable CPU pinning and NUMA awareness in containers:

```bash
docker run -p 4433:4433 superd \
  --no-pin-io \
  --no-pin-quic \
  --no-numa
```

## 🧪 Benchmarking

### Built-in Load Generator

```bash
# Run server
superd --debug

# In another terminal, generate load
cargo run --bin superd-bench -- \
  --target localhost:4433 \
  --connections 10000 \
  --rate 100000
```

### External Benchmarks

```bash
# Using iperf3 (UDP mode)
iperf3 -c localhost -u -p 4433 -b 1G -t 60

# Using wrk2 (HTTP/3)
wrk2 -t 8 -c 1000 -d 60s -R 100000 https://localhost:4433
```

## 🐛 Troubleshooting

### High CPU Usage

Check if I/O+QUIC threads are saturated:

```bash
# Monitor per-thread CPU usage
top -H -p $(pgrep superd)

# If I/O threads > 80% CPU:
superd --network-io-threads 8  # Increase threads

# If QUIC handlers > 80% CPU:
# This is expected at high load
```

### Packet Loss

Check if channels are full:

```bash
# Increase channel buffer
superd --channel-buffer 16384

# Increase socket buffers
superd --socket-recv-buffer 16777216  # 16 MB
```

### Context Switches

Check context switch rate:

```bash
perf stat -e context-switches -p $(pgrep superd) sleep 10

# If > 100K context switches/sec:
# - Ensure CPU pinning is enabled
# - Use dedicated CPU mode for Tokio
```

## 📚 References

This architecture is inspired by production systems:

- **Cloudflare:** [How to Receive a Million Packets Per Second](https://blog.cloudflare.com/how-to-receive-a-million-packets/)
- **Kafka:** [Network Layer Design](https://kafka.apache.org/documentation/#design_network)
- **Tokio:** [Best Practices](https://tokio.rs/tokio/topics/bridging)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🙏 Acknowledgments

- Cloudflare for SO_REUSEPORT best practices
- Apache Kafka for network layer architecture
- Discord for scaling insights
- Tokio team for async runtime

---

**Built with ❤️ by the superd team**
