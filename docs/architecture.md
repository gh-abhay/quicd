# Architecture

## Overview

superd is designed as a high-performance edge daemon using Sans-IO methodology to achieve maximum throughput and non-blocking operations.

## Sans-IO Methodology

Sans-IO separates protocol logic from I/O operations. Each service is implemented as a state machine that:

1. Receives inputs (events, messages)
2. Processes them without blocking
3. Produces outputs (actions, responses)

The Tokio runtime handles the actual I/O asynchronously.

## Transport Layer

- HTTP3/QUIC as the sole transport protocol
- Uses quiche for QUIC implementation
- Provides Sans-IO abstractions for connections and streams

## Service Architecture

Each service crate implements a Sans-IO event loop:

```rust
impl EventLoop for MyService {
    type Input = MyInput;
    type Output = MyOutput;

    fn handle_input(&mut self, input: Self::Input) -> Vec<Self::Output> {
        // Process input, update state, return outputs
    }
}
```

## Daemon Orchestration

The main daemon:

- Initializes all services
- Sets up QUIC listeners
- Routes incoming streams to appropriate services
- Handles service outputs asynchronously