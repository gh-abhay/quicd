# Compile-Time Service Registration

## Architecture

Superd uses **compile-time const arrays** for service registration, providing:

- ✅ **Zero runtime initialization cost** - Services are known at compile time
- ✅ **Compile-time service discovery** - No dynamic registration needed
- ✅ **Maximum performance** - Compiler can optimize the entire registration flow
- ✅ **Type safety** - All services checked at compile time

## How It Works

### 1. Service Implementation

Each service exports a const `ServiceFactory`:

```rust
// echo/src/lib.rs
pub const ECHO_SERVICE: service::ServiceFactory = service::ServiceFactory {
    name: "echo",
    description: "Zero-copy echo service",
    factory: || std::sync::Arc::new(EchoHandler),
};
```

### 2. Central Registration

The daemon collects all services in a const array:

```rust
// superd/src/lib.rs
pub const ALL_SERVICES: &[ServiceFactory] = &[
    echo::ECHO_SERVICE,
    http3::HTTP3_SERVICE,
];
```

### 3. Registry Initialization

The registry is built from the const array:

```rust
let registry = ServiceRegistry::from_services(services::ALL_SERVICES);
```

## Performance Benefits

### Compile-Time (What the Compiler Knows)
- **Service count**: Known at compile time
- **Service names**: Static string literals
- **Factory functions**: Inlined and optimized
- **HashMap capacity**: Pre-allocated to exact size

### Runtime (What Happens at Startup)
- HashMap allocation with perfect capacity
- Simple loop over const array (likely unrolled)
- Factory function calls (likely inlined)
- No dynamic discovery or registration

### Optimization Example

The compiler can transform this:
```rust
for service in ALL_SERVICES {
    let handler = (service.factory)();
    handlers.insert(service.name, handler);
}
```

Into this (conceptually):
```rust
handlers.insert("echo", Arc::new(EchoHandler));
handlers.insert("http3", Arc::new(Http3Handler::default()));
```

With loop unrolling, inlining, and constant propagation!

## Adding New Services

1. **Create service crate** with const factory:
   ```rust
   pub const MY_SERVICE: service::ServiceFactory = service::ServiceFactory {
       name: "myservice",
       description: "My custom service",
       factory: || std::sync::Arc::new(MyServiceHandler),
   };
   ```

2. **Add to daemon's service array**:
   ```rust
   pub const ALL_SERVICES: &[ServiceFactory] = &[
       echo::ECHO_SERVICE,
       http3::HTTP3_SERVICE,
       myservice::MY_SERVICE,  // Add here
   ];
   ```

3. **Update Cargo.toml** dependencies

That's it! The service is registered at compile time.

## Comparison with Other Approaches

### ❌ Runtime Registration (Previous inventory approach)
- Services discovered at runtime via linker sections
- Iteration over unknown-sized collection
- HashMap built dynamically
- **Cost**: O(n) initialization + iterator overhead

### ✅ Const Array (Current approach)
- Services known at compile time
- Fixed-size array with known elements
- HashMap pre-sized correctly
- **Cost**: Minimal - mostly compile-time optimized

### 🏆 Winner: Const Array
- Faster compilation (no proc macros)
- Better optimization potential
- Simpler mental model
- Zero hidden costs

## Verification

Build in release mode and check the optimized binary:
```bash
cargo build --release
objdump -d target/release/superd | grep -A 20 'ServiceRegistry::from_services'
```

You'll see the compiler has optimized away most of the registration logic!
