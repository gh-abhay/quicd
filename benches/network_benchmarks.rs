/// Performance benchmarks for SuperD network layer
/// Measures throughput, latency, and resource usage
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use superd::network::zerocopy_buffer::{get_buffer_pool, init_buffer_pool};

fn bench_buffer_pool_get_empty(c: &mut Criterion) {
    init_buffer_pool(1000);

    c.bench_function("buffer_pool_get_empty", |b| {
        b.iter(|| {
            let pool = get_buffer_pool();
            let buffer = pool.get_empty();
            // Simulate some work
            let _len = buffer.len();
            // Buffer is automatically returned when dropped
        });
    });
}

fn bench_buffer_operations(c: &mut Criterion) {
    init_buffer_pool(100);

    c.bench_function("buffer_operations", |b| {
        b.iter(|| {
            let pool = get_buffer_pool();
            let mut buffer = pool.get_empty();
            buffer.expand(512);
            buffer[..512].copy_from_slice(&[1u8; 512]);
            let len = black_box(buffer.len());
            let data = black_box(&buffer[..len]);
            black_box(data[0]);
        });
    });
}

fn bench_buffer_clone(c: &mut Criterion) {
    init_buffer_pool(100);
    let pool = get_buffer_pool();
    let mut buffer = pool.get_empty();
    buffer.expand(1024);
    buffer[..1024].copy_from_slice(&[0u8; 1024]);

    c.bench_function("buffer_clone", |b| {
        b.iter(|| {
            // Skip clone for now - focus on core operations
            black_box(buffer.len());
        });
    });
}

fn bench_buffer_data_access(c: &mut Criterion) {
    init_buffer_pool(100);
    let pool = get_buffer_pool();
    let mut buffer = pool.get_empty();
    buffer.expand(1024);
    buffer[..1024].copy_from_slice(&[42u8; 1024]);

    c.bench_function("buffer_data_access", |b| {
        b.iter(|| {
            let data_slice = black_box(&buffer[..]);
            black_box(data_slice.len());
            black_box(data_slice[0]);
        });
    });
}

criterion_group!(
    benches,
    bench_buffer_pool_get_empty,
    bench_buffer_operations,
    bench_buffer_clone,
    bench_buffer_data_access
);
criterion_main!(benches);
