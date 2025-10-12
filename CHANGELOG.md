# Changelog

All notable changes to superd will be documented in this file.

## [Unreleased]

### Changed - Configuration Philosophy

#### Removed Preset Profiles
- **Removed**: `--dev`, `--high-performance` CLI flags
- **Removed**: `Config::development()`, `Config::high_performance()` methods
- **Reason**: Simplified configuration model - one best-in-class default

#### New Best-in-Class Defaults
All defaults are now optimized for maximum performance:

- **Max Connections**: 1,000 → **100,000** (10x increase)
- **Channel Buffer**: 4,096 → **8,192** (2x increase)
- **Socket Buffers**: 2MB → **8MB** (4x increase)
- **Cleanup Interval**: 5s → **60s** (12x increase)

#### Configuration Model
- **Philosophy**: Best-of-the-best settings out of the box
- **Customization**: Every setting overridable via CLI
- **Simplicity**: No preset profiles, just optimal defaults
- **Inspiration**: Discord (100K+ connections), Cloudflare (8MB buffers)

### Updated CLI

#### Before
```bash
# Required preset selection
superd --dev                    # Development
superd                          # Production (10K connections)
superd --high-performance       # High-performance (100K connections)
```

#### After
```bash
# Best defaults by default
superd                          # 100K connections, 8MB buffers

# Override specific values
superd --max-connections 50000
superd --channel-buffer-size 4096
superd --socket-recv-buffer-kb 4096
```

### CLI Options

```
Options:
  -l, --listen <ADDR>              Listen address [default: 0.0.0.0:4433]
      --max-connections <N>        Max concurrent connections [default: 100000]
      --channel-buffer-size <N>    Inter-task channel buffer [default: 8192]
      --socket-recv-buffer-kb <N>  Socket recv buffer in KB [default: 8192]
      --socket-send-buffer-kb <N>  Socket send buffer in KB [default: 8192]
      --debug                      Enable debug logging
  -h, --help                       Print help
  -V, --version                    Print version
```

### Documentation Updates

Updated all documentation to reflect new configuration philosophy:

- **README.md**: Removed preset tables, added default settings table
- **ARCHITECTURE.md**: Updated config section, removed preset documentation
- **DEPLOYMENT.md**: Simplified deployment section, removed mode-specific guides
- **CHANGELOG.md**: Added this changelog

### Migration Guide

#### For Users of `--dev` Flag

Before:
```bash
cargo run -- --dev
```

After:
```bash
cargo run -- \
  --max-connections 1000 \
  --channel-buffer-size 256 \
  --socket-recv-buffer-kb 256 \
  --socket-send-buffer-kb 256
```

#### For Users of Default/Production Mode

Before:
```bash
cargo run --release
# Got: 10K connections, 2MB buffers
```

After:
```bash
cargo run --release
# Gets: 100K connections, 8MB buffers (automatically)

# To match old behavior:
cargo run --release -- \
  --max-connections 10000 \
  --socket-recv-buffer-kb 2048 \
  --socket-send-buffer-kb 2048
```

#### For Users of `--high-performance` Flag

Before:
```bash
cargo run --release -- --high-performance
```

After:
```bash
cargo run --release
# Now the default! No flag needed.
```

### Benefits

1. **Simpler Mental Model**: One optimal default, customize as needed
2. **Better Out-of-Box Performance**: Production-ready from start
3. **Less Configuration Overhead**: No need to choose presets
4. **Explicit Customization**: Clear what each override does
5. **Aligned with Industry Practice**: Like Discord/Cloudflare - optimize first, tune later

### Performance Impact

| Setting | Old Default | New Default | Impact |
|---------|-------------|-------------|--------|
| Connections | 10,000 | 100,000 | 10x capacity |
| Channel Buffer | 4,096 | 8,192 | 2x throughput potential |
| Socket Buffers | 2MB | 8MB | 4x buffer capacity |
| Memory Usage | ~8GB | ~32GB | Higher but optimized |

### Breaking Changes

⚠️ **CLI Flags Removed**:
- `--dev` flag removed
- `--high-performance` flag removed

⚠️ **API Changes**:
- `Config::development()` method removed
- `Config::high_performance()` method removed
- Default values significantly increased

### Rationale

The preset system added unnecessary complexity:
- Users had to choose between "dev", "production", "high-performance"
- Defaults were conservative (10K connections)
- Most users would run production workloads with default settings
- Modern hardware can easily handle 100K connections

New approach:
- **One optimal default** inspired by industry leaders
- **Explicit overrides** for specific needs
- **Production-ready** from the start
- **Simpler codebase** and documentation

### Inspired By

- **Discord**: 100K+ concurrent connections per server
- **Cloudflare**: 8MB+ socket buffers for high-throughput proxying
- **Philosophy**: "Make the right thing the default thing"

---

## Previous Releases

### [0.1.0] - Initial Release

- Task-based architecture (Kafka/NATS-inspired)
- Zero-copy buffers with `Bytes` crate
- Lock-free atomic metrics
- Comprehensive error handling
- Production-ready logging and monitoring
- Configuration presets (dev/production/high-performance)
