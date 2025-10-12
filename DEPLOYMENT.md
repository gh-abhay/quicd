# Deployment & Benchmarking Guide

## System Requirements

### Minimum (Development)
- CPU: 2 cores
- RAM: 2GB
- Network: 100 Mbps
- OS: Linux (kernel 4.18+), macOS, Windows

### Recommended (Production)
- CPU: 8 cores (16 recommended)
- RAM: 16GB (32GB for high-performance)
- Network: 10 Gbps NIC
- OS: Linux (kernel 5.10+ for best performance)
- Disk: SSD for logging

### High-Performance
- CPU: 16+ cores
- RAM: 64GB+
- Network: 25+ Gbps NIC
- OS: Linux with io_uring support (kernel 5.19+)
- Disk: NVMe SSD

## OS Tuning

### Linux Socket Buffers

```bash
# Increase socket buffer limits
sudo sysctl -w net.core.rmem_max=8388608    # 8MB
sudo sysctl -w net.core.wmem_max=8388608    # 8MB
sudo sysctl -w net.core.rmem_default=2097152 # 2MB
sudo sysctl -w net.core.wmem_default=2097152 # 2MB

# Make permanent
echo "net.core.rmem_max=8388608" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=8388608" | sudo tee -a /etc/sysctl.conf
echo "net.core.rmem_default=2097152" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_default=2097152" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### File Descriptor Limits

```bash
# Check current limits
ulimit -n

# Increase (temporary)
ulimit -n 1048576

# Make permanent (/etc/security/limits.conf)
* soft nofile 1048576
* hard nofile 1048576
```

### TCP/UDP Performance

```bash
# Increase connection backlog
sudo sysctl -w net.core.somaxconn=4096
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=4096

# Optimize UDP
sudo sysctl -w net.ipv4.udp_rmem_min=4096
sudo sysctl -w net.ipv4.udp_wmem_min=4096

# Make permanent
echo "net.core.somaxconn=4096" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog=4096" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.udp_rmem_min=4096" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.udp_wmem_min=4096" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## Deployment Modes

## Deployment

### Default Deployment (Optimized for Production)

```bash
# Build with release optimizations
cargo build --release

# Run with best-in-class defaults
./target/release/superd

# Or with custom listen address
./target/release/superd --listen 0.0.0.0:4433
```

**Default Configuration:**
- 100,000 max connections
- 8,192 channel buffer
- 8MB socket buffers (recv/send)
- 10s metrics interval
- 60s cleanup interval

**Use Case:**
- Production deployments
- Maximum throughput scenarios
- Large-scale user bases

**Expected Performance:**
- 100K+ connections
- 10+ Gbps throughput
- Optimized resource usage

### Custom Configuration

```bash
# Build with CPU optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Run with custom tuning
./target/release/superd \
  --listen 0.0.0.0:4433 \
  --max-connections 50000 \
  --channel-buffer-size 4096 \
  --socket-recv-buffer-kb 4096 \
  --socket-send-buffer-kb 4096
```

**Use Case:**
- Tailored to specific workload requirements
- Fine-tuning for specific hardware

### Development/Testing Deployment

```bash
# Build for development
cargo build

# Run with smaller limits for local testing
cargo run -- \
  --listen 127.0.0.1:4433 \
  --max-connections 1000 \
  --channel-buffer-size 256 \
  --socket-recv-buffer-kb 256 \
  --socket-send-buffer-kb 256 \
  --debug
```

**Use Case:**
- Local development
- Testing
- Debugging
- Resource-constrained environments

**Expected Performance:**
- 1K connections
- < 1 Gbps throughput
- Low resource usage

## Systemd Service

### Service File (`/etc/systemd/system/superd.service`)

```ini
[Unit]
Description=Superd QUIC Daemon
After=network.target

[Service]
Type=simple
User=superd
Group=superd
WorkingDirectory=/opt/superd
ExecStart=/opt/superd/target/release/superd --listen 0.0.0.0:4433
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

# Resource limits
MemoryMax=64G
CPUQuota=1600%  # 16 cores

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=superd

[Install]
WantedBy=multi-user.target
```

### Setup

```bash
# Create user
sudo useradd -r -s /bin/false superd

# Install service
sudo cp superd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable superd
sudo systemctl start superd

# Check status
sudo systemctl status superd
sudo journalctl -u superd -f
```

## Monitoring

### Real-Time Metrics

Metrics are logged every 10 seconds:

```
[INFO superd::metrics] Performance: 1234.56 Mbps | 98765 pkt/s | 
  Packets: 123456/123456 (rx/tx) | Bytes: 1234567890/1234567890 | 
  Connections: 5432 | Errors: 0
```

### Parse Metrics

```bash
# Extract throughput
journalctl -u superd -f | grep -oP '\d+\.\d+ Mbps'

# Extract packet rate
journalctl -u superd -f | grep -oP '\d+ pkt/s'

# Extract connection count
journalctl -u superd -f | grep -oP 'Connections: \d+' | grep -oP '\d+$'
```

### System Monitoring

```bash
# CPU usage
top -p $(pgrep superd)

# Memory usage
ps aux | grep superd

# Network stats
watch -n 1 'netstat -s | grep -i udp'

# Socket stats
ss -u -a | grep 4433

# File descriptors
ls /proc/$(pgrep superd)/fd | wc -l
```

## Benchmarking

### HTTP/3 Load Test

```bash
# Using h2load (nghttp2)
h2load -n 100000 -c 1000 -t 8 https://localhost:4433/

# Parameters:
# -n: Total requests
# -c: Concurrent clients
# -t: Threads
```

### Custom QUIC Benchmark

```bash
# Build quiche examples
cd /path/to/quiche
cargo build --release --examples

# Run client benchmark
for i in {1..1000}; do
  ./target/release/examples/http3-client https://localhost:4433/ &
done
wait
```

### Throughput Test

```bash
# Using iperf3 with QUIC (if available)
# Server
iperf3 -s -p 4433

# Client
iperf3 -c localhost -p 4433 -t 60 -P 100
```

### Connection Limit Test

```python
#!/usr/bin/env python3
import asyncio
import socket
import time

async def connect_one():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"QUIC_INITIAL_PACKET", ("localhost", 4433))
    await asyncio.sleep(60)  # Hold connection

async def test_connections(target=10000):
    tasks = [connect_one() for _ in range(target)]
    await asyncio.gather(*tasks)

asyncio.run(test_connections())
```

### Latency Test

```bash
# Using ping-like QUIC client
while true; do
  start=$(date +%s%N)
  curl --http3 https://localhost:4433/ > /dev/null 2>&1
  end=$(date +%s%N)
  echo "Latency: $(( (end - start) / 1000000 )) ms"
  sleep 1
done
```

## Performance Baselines

### Expected Performance (Single Daemon)

With default best-in-class settings:

| Metric | Default | Custom (Lower) | Custom (Higher) |
|--------|---------|----------------|-----------------|
| Max Connections | 100,000 | 10,000 | 200,000+ |
| Throughput | 10+ Gbps | 1-5 Gbps | 20+ Gbps |
| Latency (P50) | < 5ms | < 5ms | < 5ms |
| Latency (P99) | < 10ms | < 10ms | < 10ms |
| CPU Usage | < 80% | < 50% | < 90% |
| Memory Usage | < 32GB | < 8GB | < 64GB |

### Tuning for Your Workload

#### Low Latency Priority (Smaller Buffers)
```bash
./target/release/superd \
  --channel-buffer-size 256 \
  --socket-recv-buffer-kb 256 \
  --socket-send-buffer-kb 256
```

#### Maximum Throughput Priority (Larger Buffers)
```bash
./target/release/superd \
  --channel-buffer-size 16384 \
  --socket-recv-buffer-kb 16384 \
  --socket-send-buffer-kb 16384
```

#### Resource-Constrained Environment
```bash
./target/release/superd \
  --max-connections 5000 \
  --channel-buffer-size 1024 \
  --socket-recv-buffer-kb 1024 \
  --socket-send-buffer-kb 1024
```

## Troubleshooting

### High CPU Usage

**Symptom:** CPU > 80%

**Diagnosis:**
```bash
# Check task distribution
sudo perf top -p $(pgrep superd)
```

**Solutions:**
- Reduce `max_connections`
- Increase `channel_buffer_size` (reduce context switching)
- Check for error storms in logs

### Packet Loss

**Symptom:** Dropped packets in metrics

**Diagnosis:**
```bash
# Check socket buffer stats
netstat -su | grep -i drop
```

**Solutions:**
- Increase socket buffers: `--socket-recv-buffer-kb 8192`
- Increase OS limits (see OS Tuning section)
- Check network interface for errors: `ethtool -S eth0`

### Connection Timeouts

**Symptom:** Frequent connection closures

**Diagnosis:**
```bash
# Check connection lifecycle in logs
journalctl -u superd | grep -i "connection"
```

**Solutions:**
- Increase idle timeout (modify `config.rs`)
- Check firewall/NAT settings
- Verify QUIC handshake completion

### Memory Leaks

**Symptom:** Memory grows over time

**Diagnosis:**
```bash
# Monitor memory
watch -n 5 'ps -p $(pgrep superd) -o rss,vsz'
```

**Solutions:**
- Check connection cleanup task is running
- Verify connections are properly closed
- Use `valgrind` for leak detection:
  ```bash
  cargo build
  valgrind --leak-check=full ./target/debug/superd
  ```

## Production Checklist

- [ ] OS tuning applied (socket buffers, file descriptors)
- [ ] Systemd service configured
- [ ] Monitoring setup (metrics logging)
- [ ] Resource limits set
- [ ] Benchmarks run and validated
- [ ] Firewall rules configured
- [ ] TLS certificates in place
- [ ] Logging rotation configured
- [ ] Backup/recovery plan
- [ ] Runbook documentation

## Security Considerations

### TLS Configuration
- Use strong cipher suites
- Rotate certificates regularly
- Enable certificate pinning if applicable

### Network Security
```bash
# Firewall rules (example)
sudo ufw allow 4433/udp
sudo ufw enable
```

### Rate Limiting
- Configure `max_connections` appropriately
- Consider per-IP connection limits (future enhancement)
- Monitor for DDoS patterns

### Resource Limits
```bash
# Prevent resource exhaustion
ulimit -m 67108864  # 64GB memory limit
ulimit -n 1048576   # 1M file descriptors
```

## Next Steps

1. **Baseline Performance**: Run benchmarks in your environment
2. **Tune Configuration**: Adjust based on workload characteristics
3. **Monitor Production**: Watch metrics for anomalies
4. **Iterate**: Continuously optimize based on real-world data

For questions or issues, check:
- [ARCHITECTURE.md](ARCHITECTURE.md) - Design documentation
- [README.md](README.md) - Quick start guide
- [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) - Implementation details
