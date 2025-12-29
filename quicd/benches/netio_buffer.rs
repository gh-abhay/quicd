//! Benchmarks for netio buffer pool operations.
//!
//! These benchmarks measure the hot path performance of:
//! - Buffer pool allocation (LIFO take)
//! - Buffer pool return (LIFO put)  
//! - WorkerBuffer I/O preparation
//! - ConsumeBuffer zero-copy operations
//!
//! Run with: cargo bench -p quicd --bench netio_buffer

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};

// We need to import from quicd - but since this is a binary crate,
// we need to structure imports carefully
use quicd::netio::buffer::{
    create_worker_pool, ConsumeBuffer, Reuse, WorkerBuffer,
};
use quicd::netio::config::BufferPoolConfig;

/// Benchmark buffer pool allocation (take from pool)
fn bench_buffer_pool_alloc(c: &mut Criterion) {
    let config = BufferPoolConfig {
        max_buffers_per_worker: 1000,
        datagram_size: 1350, // RFC 9000 default
    };
    let pool = create_worker_pool(&config);

    // Pre-populate the pool with buffers
    {
        let bufs: Vec<_> = (0..100)
            .map(|_| WorkerBuffer::new_from_pool(pool.clone()))
            .collect();
        drop(bufs); // Return all to pool
    }

    c.bench_function("buffer_pool_alloc", |b| {
        b.iter(|| {
            let buf = WorkerBuffer::new_from_pool(black_box(pool.clone()));
            black_box(buf)
        })
    });
}

/// Benchmark buffer pool alloc/free cycle (typical hot path)
fn bench_buffer_pool_alloc_free_cycle(c: &mut Criterion) {
    let config = BufferPoolConfig {
        max_buffers_per_worker: 1000,
        datagram_size: 1350,
    };
    let pool = create_worker_pool(&config);

    c.bench_function("buffer_pool_alloc_free_cycle", |b| {
        b.iter(|| {
            let buf = WorkerBuffer::new_from_pool(pool.clone());
            black_box(&buf);
            drop(buf); // Returns to pool
        })
    });
}

/// Benchmark WorkerBuffer I/O preparation (as_mut_slice_for_io)
fn bench_worker_buffer_io_prep(c: &mut Criterion) {
    let config = BufferPoolConfig::default();
    let pool = create_worker_pool(&config);

    c.bench_function("worker_buffer_io_prep", |b| {
        let mut buf = WorkerBuffer::new_from_pool(pool.clone());
        b.iter(|| {
            let slice = buf.as_mut_slice_for_io();
            black_box(slice.len());
            buf.set_received_len(1200); // Reset for next iteration
            buf.clear();
        })
    });
}

/// Benchmark ConsumeBuffer pop_front (zero-copy consume)
fn bench_consume_buffer_pop_front(c: &mut Criterion) {
    let mut group = c.benchmark_group("consume_buffer_pop_front");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            b.iter(|| {
                let mut buf = ConsumeBuffer::from_vec(data.clone());
                // Consume 10 bytes at a time
                while buf.len() >= 10 {
                    buf.pop_front(10);
                }
                black_box(buf.len())
            })
        });
    }
    group.finish();
}

/// Benchmark ConsumeBuffer add_prefix (zero-copy prepend)
fn bench_consume_buffer_add_prefix(c: &mut Criterion) {
    c.bench_function("consume_buffer_add_prefix", |b| {
        let prefix = [0u8; 20]; // QUIC connection ID size
        b.iter(|| {
            let data = vec![0u8; 1200]; // Typical packet size
            let mut buf = ConsumeBuffer::from_vec(data);
            buf.pop_front(20); // Make room for prefix
            let result = buf.add_prefix(&prefix);
            black_box(result)
        })
    });
}

/// Benchmark Vec<u8> Reuse trait implementation
fn bench_vec_reuse(c: &mut Criterion) {
    c.bench_function("vec_reuse_1350_bytes", |b| {
        b.iter(|| {
            let mut vec: Vec<u8> = Vec::with_capacity(4096);
            vec.extend_from_slice(&[0u8; 1350]); // Typical QUIC packet
            let should_pool = vec.reuse(1350);
            black_box(should_pool)
        })
    });
}

/// Benchmark high-throughput buffer cycling (simulates packet processing)
fn bench_high_throughput_buffer_cycle(c: &mut Criterion) {
    let config = BufferPoolConfig {
        max_buffers_per_worker: 1000,
        datagram_size: 1350,
    };
    let pool = create_worker_pool(&config);

    let mut group = c.benchmark_group("high_throughput");
    group.throughput(Throughput::Elements(1000)); // 1000 packets

    group.bench_function("1000_packet_cycle", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let mut buf = WorkerBuffer::new_from_pool(pool.clone());
                let slice = buf.as_mut_slice_for_io();
                // Simulate kernel writing 1200 bytes (minimum QUIC Initial)
                black_box(slice.len());
                buf.set_received_len(1200);
                // Simulate reading packet
                black_box(buf.as_slice());
                // Buffer returned to pool on drop
            }
        })
    });

    group.finish();
}

/// Benchmark to verify no heap allocations in steady state
fn bench_steady_state_no_alloc(c: &mut Criterion) {
    let config = BufferPoolConfig {
        max_buffers_per_worker: 100,
        datagram_size: 1350,
    };
    let pool = create_worker_pool(&config);

    // Warm up: fill the pool
    {
        let bufs: Vec<_> = (0..50)
            .map(|_| WorkerBuffer::new_from_pool(pool.clone()))
            .collect();
        drop(bufs);
    }

    // In steady state, this should NOT allocate (reuses pooled buffers)
    c.bench_function("steady_state_reuse", |b| {
        b.iter(|| {
            let buf = WorkerBuffer::new_from_pool(pool.clone());
            black_box(buf.capacity());
            // buf dropped, returns to pool
        })
    });
}

criterion_group!(
    benches,
    bench_buffer_pool_alloc,
    bench_buffer_pool_alloc_free_cycle,
    bench_worker_buffer_io_prep,
    bench_consume_buffer_pop_front,
    bench_consume_buffer_add_prefix,
    bench_vec_reuse,
    bench_high_throughput_buffer_cycle,
    bench_steady_state_no_alloc,
);

criterion_main!(benches);
