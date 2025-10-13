# CPU Allocation Analysis - Rethinking the 25% + 25% = 50% Question

**Date:** October 13, 2025  
**Question:** Does Network I/O + QUIC Processing really need 50% of CPU?

---

## Current Allocation (Under Question)

```
8-Core Machine:
├── Network I/O:        2 threads (25%) = 2 cores
├── QUIC Processing:    2 threads (25%) = 2 cores
├── Application:        4 threads (50%) = 4 cores
└── Total:              8 cores

Question: Is 50% for I/O+QUIC too much?
```

---

## Reality Check: What Do These Layers Actually Do?

### Network I/O Thread (per packet)
```rust
loop {
    // 1. Receive UDP packet from kernel
    let (len, addr) = socket.recv_from(&mut buf)?;  // ~500ns (syscall)
    
    // 2. Send to channel
    channel.send(Packet { buf, addr })?;             // ~100ns (mpsc)
    
    // Total: ~600ns per packet
}
```

**Analysis:**
- **Pure I/O operation:** Just syscall + channel send
- **No computation:** Zero processing logic
- **Time per packet:** ~600ns
- **At 500K pps:** 500K × 600ns = 300ms = **30% CPU usage**
- **Actual CPU need:** ~30% per thread, NOT 100%

### QUIC Processing Thread (per packet)
```rust
loop {
    // 1. Receive from channel
    let packet = channel.recv()?;                    // ~100ns (blocking)
    
    // 2. Lock QUIC engine
    let mut engine = quic_engine.lock().await;       // ~100ns
    
    // 3. Process QUIC packet
    engine.recv(packet.buf, packet.addr)?;           // ~1-5µs (crypto, state)
    
    // 4. Unlock
    drop(engine);                                     // ~100ns
    
    // Total: ~1-5µs per packet
}
```

**Analysis:**
- **CPU-bound work:** QUIC processing (crypto, congestion control)
- **Time per packet:** ~1-5µs (average ~3µs)
- **At 125K pps (per thread):** 125K × 3µs = 375ms = **37.5% CPU usage**
- **Actual CPU need:** ~40% per thread, NOT 100%

---

## 🎯 Key Insight: These Threads Are NOT 100% Busy!

```
Network I/O Thread:
├── At 500K pps: 500K × 600ns = 300ms/sec = 30% CPU
├── Idle time: 70% (waiting for packets)
└── Why pinned? Cache locality, not CPU saturation

QUIC Processing Thread:
├── At 125K pps: 125K × 3µs = 375ms/sec = 37.5% CPU
├── Idle time: 62.5% (waiting for channel)
└── Why pinned? Avoid context switch overhead, not CPU saturation
```

**Implication:** Tokio CAN share these CPUs efficiently!

---

## Revised Understanding: Sharing vs Dedicated

### Option A: Dedicated CPUs (Current Plan)
```
8-Core Machine:
├── CPU 0: I/O thread 0 (30% busy, 70% idle)
├── CPU 1: QUIC thread 0 (37.5% busy, 62.5% idle)
├── CPU 2: I/O thread 1 (30% busy, 70% idle)
├── CPU 3: QUIC thread 1 (37.5% busy, 62.5% idle)
├── CPU 4-7: Tokio workers (4 workers)
└── Wasted: 2 cores worth of idle cycles (CPUs 0-3)

Effective Capacity:
├── I/O+QUIC: 1.35 cores actually used (out of 4 allocated)
├── Wasted: 2.65 cores idle
└── Tokio: 4 cores available
```

**Waste:** 2.65 cores sitting idle while I/O+QUIC wait for packets!

### Option B: Shared CPUs with Pinning (BETTER!)
```
8-Core Machine:
├── CPU 0: I/O thread 0 (pinned, 30% busy)
├── CPU 1: QUIC thread 0 (pinned, 37.5% busy)
├── CPU 2: I/O thread 1 (pinned, 30% busy)
├── CPU 3: QUIC thread 1 (pinned, 37.5% busy)
├── Tokio: 8 workers (can use ALL CPUs when idle)
└── Wasted: 0 cores

Effective Capacity:
├── I/O+QUIC: 1.35 cores when busy (still pinned)
├── Tokio: 8 cores total - 1.35 active = 6.65 cores available
└── Waste: Zero (Tokio uses idle cycles)
```

**Benefit:** Tokio gets 6.65 cores instead of 4 cores!

---

## Cache Pollution Re-Analysis

### My Previous Concern (Overstated)
```
"Tokio worker lands on CPU 0, evicts I/O thread cache"

Reality Check:
├── I/O thread cache: ~100 KB (socket, buffers)
├── L2 cache size: 256 KB
├── L3 cache size: 16 MB (shared)
└── Problem: L2 is NOT that fragile
```

### Modern CPU Cache Behavior
```
Intel/AMD L2 Cache (256 KB):
├── 8-way set associative
├── Can hold multiple contexts
├── Eviction: LRU (least recently used)
└── Reality: Small Tokio context won't fully evict I/O cache

L3 Cache (16 MB shared):
├── Holds most working set
├── I/O thread hot data: ~100 KB (fits easily)
├── QUIC hot data: ~200 KB (fits easily)
└── Even with Tokio: Total ~500 KB << 16 MB
```

**Correction:** Cache pollution is MINIMAL if I/O thread is pinned and has priority.

---

## 🎯 Revised Recommendation

### New Allocation Strategy: **Pinned + Shared**

```rust
// Pin I/O and QUIC threads to specific CPUs
// But let Tokio use ALL CPUs (work-stealing)

let cpu_count = num_cpus::get();
let io_threads = calculate_io_threads(cpu_count);
let quic_threads = io_threads;  // 1:1

// Pin I/O and QUIC to specific CPUs
pin_thread(io_thread_0, CPU 0);
pin_thread(quic_thread_0, CPU 1);
pin_thread(io_thread_1, CPU 2);
pin_thread(quic_thread_1, CPU 3);

// Tokio uses ALL CPUs (work-stealing)
let tokio_workers = cpu_count;  // Use all CPUs!

tokio::runtime::Builder::new_multi_thread()
    .worker_threads(tokio_workers)  // 8 workers on 8-core
    .build()?;
```

**How This Works:**
1. I/O threads pinned → always run on designated CPU
2. QUIC threads pinned → always run on designated CPU
3. Tokio workers (8 total) → work-steal across all CPUs
4. When I/O thread idle (70% of time) → Tokio uses that CPU
5. When QUIC thread idle (62.5% of time) → Tokio uses that CPU
6. **Result:** Tokio effectively gets ~6.65 cores instead of 4

---

## Thread Count Adjustment

### OLD Formula (Too Conservative)
```
io_threads = 25% of CPUs (min=1, max=8)
quic_threads = io_threads
tokio_workers = remaining CPUs

8-core: 2 I/O + 2 QUIC + 4 Tokio
16-core: 4 I/O + 4 QUIC + 8 Tokio
32-core: 8 I/O + 8 QUIC + 16 Tokio
```

### NEW Formula (Optimized)
```
io_threads = 12.5% of CPUs (min=1, max=4)
quic_threads = io_threads
tokio_workers = num_cpus (shares all CPUs)

8-core: 1 I/O + 1 QUIC + 8 Tokio (shares)
16-core: 2 I/O + 2 QUIC + 16 Tokio (shares)
32-core: 4 I/O + 4 QUIC + 32 Tokio (shares)
64-core: 4 I/O + 4 QUIC + 64 Tokio (shares)
```

**Rationale:**
1. **I/O threads:** 1 thread can handle 500K pps @ 30% CPU
   - 8-core: 1 thread = 500K pps (enough for target)
   - 16-core: 2 threads = 1M pps
   - 32-core: 4 threads = 2M pps
   - Cap at 4 (not 8) since we don't need more

2. **QUIC threads:** 1:1 with I/O (no contention)

3. **Tokio workers:** Use ALL CPUs, work-steal around pinned threads

---

## Performance Comparison

### Scenario: 8-Core, 1M pps, 100K connections

#### OLD Allocation (Dedicated)
```
2 I/O threads:      2 × 500K = 1M pps ✅
CPU usage:          2 × 30% = 60% of 2 cores = 0.6 cores
Wasted:             1.4 cores idle

2 QUIC threads:     2 × 500K = 1M pps ✅
CPU usage:          2 × 37.5% = 75% of 2 cores = 0.75 cores
Wasted:             1.25 cores idle

4 Tokio workers:    4 cores available
Total waste:        2.65 cores idle
```

#### NEW Allocation (Shared)
```
1 I/O thread:       500K pps @ 30% CPU = 0.3 cores
NEED 2 threads:     1M pps target
CPU usage:          2 × 30% = 0.6 cores
Wasted:             0 cores (Tokio uses idle time)

2 QUIC threads:     2 × 500K = 1M pps
CPU usage:          2 × 37.5% = 0.75 cores
Wasted:             0 cores (Tokio uses idle time)

8 Tokio workers:    8 cores total
Effective:          8 - 0.6 - 0.75 = 6.65 cores for Tokio ✅✅
Waste:              Zero
```

**Result:** Tokio gets 66% more cores (6.65 vs 4)!

---

## Better Terminology

### Current: "Packet Processing" (Too Generic)

### Better Options:

1. **"QUIC Protocol Handler"** ✅ (Best - clear purpose)
2. **"QUIC Engine Thread"** ✅ (Also good)
3. **"Protocol Processing"** (Better than "packet")
4. **"Connection Handler"** (Misleading - that's Tokio's job)
5. **"Packet Router"** (Wrong - we're not routing)

**Recommended:** **"QUIC Protocol Handler"**

---

## Final Recommended Architecture

### Layer Names (Clear & Accurate)
```
Layer 1: Network I/O Threads
         └─ Purpose: UDP socket recv/send operations

Layer 2: QUIC Protocol Handlers
         └─ Purpose: QUIC packet processing, crypto, state management

Layer 3: Connection Management (Tokio Tasks)
         └─ Purpose: Per-connection logic, application state
```

### Thread Allocation (8-Core)
```
┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
│ CPU0 │ CPU1 │ CPU2 │ CPU3 │ CPU4 │ CPU5 │ CPU6 │ CPU7 │
├──────┼──────┼──────┼──────┼──────┼──────┼──────┼──────┤
│ I/O0 │ QUIC0│ I/O1 │ QUIC1│      │      │      │      │
│ Pin  │ Pin  │ Pin  │ Pin  │      │      │      │      │
│ 30%  │ 37%  │ 30%  │ 37%  │      │      │      │      │
└──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘
    ▲      ▲      ▲      ▲      ▲      ▲      ▲      ▲
    └──────┴──────┴──────┴──────┴──────┴──────┴──────┘
              Tokio Runtime (8 workers)
         Work-steals across ALL CPUs
      Uses idle cycles on CPUs 0-3 (70% of time)
```

### Allocation Formula
```rust
fn calculate_threads(cpu_count: usize) -> ThreadConfig {
    let io_threads = match cpu_count {
        1 => 1,
        2..=8 => 1,                      // 1 thread up to 8 cores
        9..=16 => 2,                     // 2 threads for 9-16 cores
        17..=32 => 3,                    // 3 threads for 17-32 cores
        _ => 4,                          // Cap at 4 threads
    };
    
    let quic_handlers = io_threads;      // Always 1:1
    let tokio_workers = cpu_count;       // Use ALL CPUs
    
    ThreadConfig {
        io_threads,
        quic_handlers,
        tokio_workers,
    }
}
```

**Examples:**
```
1 core:   1 I/O + 1 QUIC + 1 Tokio
2 cores:  1 I/O + 1 QUIC + 2 Tokio
4 cores:  1 I/O + 1 QUIC + 4 Tokio
8 cores:  1 I/O + 1 QUIC + 8 Tokio   (2 I/O if need >500K pps)
16 cores: 2 I/O + 2 QUIC + 16 Tokio
32 cores: 3 I/O + 3 QUIC + 32 Tokio
64 cores: 4 I/O + 4 QUIC + 64 Tokio
```

---

## Addressing Cache Concerns

### Strategy: Thread Priorities + CPU Affinity

```rust
use thread_priority::{ThreadPriority, set_current_thread_priority};

// Network I/O thread (highest priority)
std::thread::spawn(|| {
    set_current_thread_priority(ThreadPriority::Max).ok();
    core_affinity::set_for_current(CoreId { id: 0 });
    
    // I/O loop - gets CPU first when ready
    loop { socket.recv_from(&mut buf)?; }
});

// QUIC handler (high priority)
std::thread::spawn(|| {
    set_current_thread_priority(ThreadPriority::High).ok();
    core_affinity::set_for_current(CoreId { id: 1 });
    
    // QUIC loop
    loop { process_packet(); }
});

// Tokio workers (normal priority)
// Will yield to higher priority threads automatically
```

**Result:**
- I/O thread gets CPU immediately when packet arrives
- QUIC handler gets CPU immediately when packet ready
- Tokio workers use remaining cycles
- **Zero starvation, zero pollution**

---

## ⚠️ WAIT - Critical Correction!

### I Need to Reconsider: What About HIGH LOAD?

My analysis above assumes **30% I/O usage** and **37.5% QUIC usage**.

But let me recalculate at ACTUAL TARGET LOAD...

```
Target: 1M packets/sec on 8-core machine

With 2 I/O threads (500K pps each):
├── Per packet: 600ns (syscall + channel send)
├── Per thread: 500K × 600ns = 300ms = 30% ✅ (Correct!)

With 2 QUIC threads (500K pps each):
├── Per packet: 3µs (QUIC processing)
├── Per thread: 500K × 3µs = 1500ms = 150% ❌ OVERLOAD!
└── Reality: Need more threads OR processing is faster
```

**PROBLEM:** My 3µs estimate might be too high!

Let me recalculate with realistic QUIC processing time...

### Realistic QUIC Processing Time

```rust
// QUIC recv() does:
1. Decrypt packet header          ~500ns (AES-GCM fast path)
2. Parse QUIC frames              ~200ns (memcpy, simple parsing)
3. Update connection state        ~300ns (sequence numbers, ACKs)
4. Crypto verification            ~500ns (packet auth tag)
5. Congestion control update      ~200ns (arithmetic)
Total:                            ~1.7µs (not 3µs!)

At 500K pps per thread:
├── 500K × 1.7µs = 850ms = 85% CPU
└── Still high, but feasible
```

**With 85% usage:** Sharing CPUs becomes problematic!

### Final Decision: It Depends on Processing Time

#### If QUIC Processing < 1µs per packet:
```
500K × 1µs = 500ms = 50% CPU per thread
├── I/O: 30% CPU
├── QUIC: 50% CPU
├── Total: 80% of 2 cores = 1.6 cores
└── Strategy: SHARE CPUs with Tokio ✅
```

#### If QUIC Processing > 1.5µs per packet:
```
500K × 1.5µs = 750ms = 75% CPU per thread
├── I/O: 30% CPU
├── QUIC: 75% CPU
├── Total: 105% of 2 cores = 2.1 cores
└── Strategy: DEDICATE CPUs (avoid contention) ✅
```

---

## 🎯 Final Recommendation: HYBRID Approach

### Start Conservative, Optimize Later

```rust
// Configuration with tuning knob
struct Config {
    io_threads: usize,
    quic_handlers: usize,
    
    // Key decision: Share or dedicate CPUs for Tokio
    #[arg(long, default_value = "dedicated")]
    tokio_cpu_mode: TokioCpuMode,  // "dedicated" or "shared"
}

enum TokioCpuMode {
    Dedicated,  // tokio_workers = num_cpus - (io + quic)
    Shared,     // tokio_workers = num_cpus (shares all)
}
```

### Default: **DEDICATED** (Safe)
```
8-core:  2 I/O + 2 QUIC + 4 Tokio (dedicated)
16-core: 4 I/O + 4 QUIC + 8 Tokio (dedicated)

Rationale:
├── Conservative: Guaranteed no contention
├── Predictable: Easy to reason about performance
├── Safe: Works even if QUIC processing is slow
└── Can switch to "shared" mode after profiling
```

### Alternative: **SHARED** (Experimental)
```
8-core:  1 I/O + 1 QUIC + 8 Tokio (shared)
16-core: 2 I/O + 2 QUIC + 16 Tokio (shared)

Rationale:
├── Efficient: Uses idle CPU cycles
├── Requires: Profiling to confirm <50% QUIC usage
├── Risky: If QUIC >75% CPU, contention degrades performance
└── Enable after benchmarking proves it's safe
```

---

## Terminology Change: QUIC Protocol Handler ✅

**OLD:** Packet Processing Thread (too generic)  
**NEW:** QUIC Protocol Handler (clear and specific)

---

## Recommended Final Strategy

### Phase 1: Ship with DEDICATED CPUs (Now)
```rust
let io_threads = match cpu_count {
    1 => 1,
    2..=8 => 2,      // 25% on 8-core
    9..=16 => 4,     // 25% on 16-core
    _ => 8,          // Cap at 8
}.min(8);

let quic_handlers = io_threads;
let tokio_workers = cpu_count - (io_threads + quic_handlers);

// Pin I/O and QUIC to specific CPUs
// Tokio uses ONLY remaining CPUs
```

**Benefit:** Safe, predictable, proven by production systems

### Phase 2: Profile and Tune (After Deployment)
```bash
# Run with monitoring
superd --tokio-cpu-mode=dedicated

# Profile CPU usage
perf stat -e cycles,instructions,cache-misses superd

# If I/O+QUIC < 50% CPU:
#   Switch to --tokio-cpu-mode=shared
#   Gain 66% more Tokio capacity

# If I/O+QUIC > 75% CPU:
#   Keep dedicated mode
#   Consider adding more I/O threads
```

### Phase 3: Adaptive (Future)
```rust
// Auto-detect CPU usage and adjust runtime
if avg_io_cpu < 30% && avg_quic_cpu < 50% {
    tokio_cpu_mode = Shared;  // Use idle cycles
} else {
    tokio_cpu_mode = Dedicated;  // Avoid contention
}
```

---

## Summary

### Q: Does I/O + QUIC really need 50% of CPU?

**A: Probably NOT (25-35% actual usage), BUT we should start CONSERVATIVE.**

### Q: Should Tokio share CPUs or use dedicated?

**A: Start DEDICATED (safe), then profile and switch to SHARED if CPU usage is low.**

### Q: Better name for "Packet Processing"?

**A: "QUIC Protocol Handler" ✅**

### Thread Count Formula (Revised, Conservative)
```
8-core:  2 I/O + 2 QUIC + 4 Tokio (dedicated)
16-core: 4 I/O + 4 QUIC + 8 Tokio (dedicated)
32-core: 8 I/O + 8 QUIC + 16 Tokio (dedicated)

After profiling, can reduce I/O+QUIC to:
8-core:  1 I/O + 1 QUIC + 8 Tokio (shared) if usage < 50%
```

**Ship conservative, optimize with data!** 🚀📊
