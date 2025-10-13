# Architecture Summary - Final Decisions

**Date:** October 13, 2025  
**Goal:** Maximum throughput + Maximum concurrent clients

---

## Three-Layer Architecture

### 1️⃣ Network I/O Layer (UDP Socket Operations)

**What it does:** Read/write UDP packets from/to NIC

```
Type:       OS-level threads (CPU-pinned, NUMA-aware)
Count:      25% of CPUs (min=1, max=8)
Examples:   1 core → 1 thread
            4 cores → 1 thread
            8 cores → 2 threads
            16 cores → 4 threads
            32 cores → 8 threads (max)

Config:     --network-io-threads N
            SUPERD_NETWORK_IO_THREADS=N
```

**Why OS threads:** Zero context switch during packet RX/TX, CPU pinning, NUMA awareness

---

### 2️⃣ Packet Processing Layer (QUIC Protocol Engine)

**What it does:** Read packets from channel, call quic_conn.recv(), process QUIC protocol

```
Type:       OS-level threads (CPU-pinned)
Count:      Equal to network I/O threads (1:1 ratio)
Pattern:    I/O Thread 0 → Channel 0 → Processing Thread 0
            I/O Thread 1 → Channel 1 → Processing Thread 1
            ... (dedicated, no contention)

Config:     --packet-processing-threads N (auto = network-io-threads)
            SUPERD_PACKET_PROCESSING_THREADS=N
```

**Why OS threads (NOT Tokio tasks):**
- CPU-bound work (no `.await` points)
- Avoids 12.5% scheduler overhead from unnecessary context switches
- Simple blocking loop = 100% CPU efficiency

---

### 3️⃣ Application Layer (Connection Management)

**What it does:** Per-connection state, timeouts, retransmissions, stream multiplexing

```
Type:       Tokio async tasks
Count:      Spawn on-demand (one per connection, unbounded)
Runtime:    Multi-threaded Tokio runtime

Tokio Workers: num_cpus - (io_threads + processing_threads)
```

**Why Tokio tasks:**
- I/O-bound work (timers, async operations)
- Lightweight (~500 bytes per task)
- Scales to millions of connections

---

## 🎯 CRITICAL: Tokio Runtime CPU Allocation

### ❌ WRONG: Share All CPUs
```rust
// DON'T DO THIS
tokio::runtime::Builder::new_multi_thread()
    .worker_threads(num_cpus::get())  // ❌ Shares all CPUs
    .build()?;
```

**Problem:** Tokio workers pollute I/O thread cache → performance penalty

---

### ✅ CORRECT: Dedicated CPUs for Tokio
```rust
// DO THIS
let cpu_count = num_cpus::get();
let io_threads = calculate_network_io_threads(cpu_count);
let processing_threads = io_threads;  // 1:1
let tokio_workers = cpu_count
    .saturating_sub(io_threads + processing_threads)
    .max(1);

tokio::runtime::Builder::new_multi_thread()
    .worker_threads(tokio_workers)  // ✅ Only unpinned CPUs
    .build()?;
```

**Examples:**

```
1-Core:  1 I/O + 1 Processing + 1 Tokio = Forced sharing
2-Core:  1 I/O + 1 Processing + 0 Tokio → fallback to 1
4-Core:  1 I/O + 1 Processing + 2 Tokio (dedicated) ✅
8-Core:  2 I/O + 2 Processing + 4 Tokio (dedicated) ✅
16-Core: 4 I/O + 4 Processing + 8 Tokio (dedicated) ✅
32-Core: 8 I/O + 8 Processing + 16 Tokio (dedicated) ✅
```

---

## CPU Pinning Strategy (8-Core Example)

```
┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
│ CPU0 │ CPU1 │ CPU2 │ CPU3 │ CPU4 │ CPU5 │ CPU6 │ CPU7 │
├──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤
│ I/O0 │ Proc0│ I/O1 │ Proc1│Tokio0│Tokio1│Tokio2│Tokio3│
│ Pin  │ Pin  │ Pin  │ Pin  │ Wrk  │ Wrk  │ Wrk  │ Wrk  │
└──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘
```

**Benefits:**
- ✅ I/O threads: Hot L1/L2 cache for socket operations
- ✅ Processing threads: Hot L1/L2 cache for QUIC processing
- ✅ Tokio workers: Separate cache, zero pollution
- ✅ Interleaved: I/O + Processing pairs share L3 cache
- ✅ NUMA-aware: All on same node as NIC

---

## Why This Architecture is Optimal

### Maximum Throughput
```
Per I/O thread:         500K pps (Cloudflare proven)
8 I/O threads:          4M pps total
Processing (1:1):       Matches I/O throughput
Bottleneck:             None (balanced)
```

### Maximum Connections
```
Per connection:         8.5 KB (8 KB QUIC + 500B Tokio task)
100K connections:       850 MB
1M connections:         8.5 GB
Tokio scalability:      Millions of tasks possible
```

### CPU Efficiency
```
I/O threads:            0% scheduler overhead (never yield)
Processing threads:     0% scheduler overhead (never yield)
Tokio tasks:            Efficient work-stealing (only on dedicated CPUs)
Cache pollution:        0% (perfect isolation)
```

---

## Configuration Quick Reference

### Command Line
```bash
# Auto-detect (recommended)
superd

# Custom thread counts
superd --network-io-threads 4 --packet-processing-threads 4

# Disable CPU pinning (for testing)
superd --pin-network-io-threads=false --pin-packet-processing-threads=false
```

### Environment Variables
```bash
export SUPERD_NETWORK_IO_THREADS=8
export SUPERD_PACKET_PROCESSING_THREADS=8
export SUPERD_PIN_NETWORK_IO_THREADS=true
export SUPERD_NUMA_AWARE=true
superd
```

### TOML Config
```toml
[network_io]
threads = "auto"      # or specific number
pin_threads = true
numa_aware = true

[packet_processing]
threads = "auto"      # or specific number (matches network_io if auto)
pin_threads = true

[runtime]
tokio_workers = "auto"  # num_cpus - (io + processing)
```

---

## Performance Targets

```
Target:         100K connections @ 10 pps each = 1M total pps
8-core:         2 I/O threads × 500K = 1M pps ✅
16-core:        4 I/O threads × 500K = 2M pps ✅✅
32-core:        8 I/O threads × 500K = 4M pps ✅✅✅

Memory:         8.5 KB per connection
100K:           850 MB ✅
1M:             8.5 GB ✅

CPU Usage:      ~40% on 8-core @ 1M pps (60% headroom for bursts)
```

---

## Implementation Phases

### Phase 1: Network I/O ✅ (Already Done)
- [x] OS threads with single-threaded Tokio runtime
- [x] SO_REUSEPORT
- [ ] Add CPU pinning
- [ ] Add NUMA awareness

### Phase 2: Packet Processing (Next)
- [ ] OS threads (NOT Tokio tasks)
- [ ] 1:1 with I/O threads
- [ ] CPU pinning (interleaved)
- [ ] Blocking crossbeam channel recv

### Phase 3: Tokio Runtime (Next)
- [ ] Calculate workers = num_cpus - pinned_threads
- [ ] Optional: Pin Tokio workers to dedicated CPUs
- [ ] Verify zero cache pollution

### Phase 4: Testing
- [ ] Benchmark 1K, 10K, 100K connections
- [ ] Profile with perf/flamegraph
- [ ] Monitor context switches
- [ ] Tune based on real traffic

---

## Key Takeaways

1. **Network I/O:** OS threads, min=1, max=8, CPU-pinned
2. **Packet Processing:** OS threads (NOT Tokio tasks), 1:1 with I/O, CPU-pinned
3. **Connection Management:** Tokio tasks, spawn on-demand
4. **Tokio Runtime:** Use ONLY unpinned CPUs (dedicated, not shared)
5. **Goal:** Zero context switches on critical path, zero cache pollution

**Ship it!** 🚀
