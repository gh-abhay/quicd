/// Performance benchmarks for SuperD network layer
/// Measures throughput, latency, and resource usage
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use superd::network::zerocopy_buffer::{
    get_buffer_pool, init_buffer_pool, ZeroCopyBuffer, ZeroCopyBufferMut,
};

fn bench_buffer_pool_acquire_release(c: &mut Criterion) {
    init_buffer_pool(1000);

    c.bench_function("buffer_pool_acquire_release", |b| {
        b.iter(|| {
            let pool = get_buffer_pool();
            let buffer = pool.acquire();
            // Simulate some work
            let _len = buffer.len();
            pool.release(buffer);
        });
    });
}

fn bench_zero_copy_buffer_clone(c: &mut Criterion) {
    let data = bytes::Bytes::from(vec![0u8; 1024]);
    let buffer = ZeroCopyBuffer::from_bytes(data);

    c.bench_function("zero_copy_buffer_clone", |b| {
        b.iter(|| {
            let cloned = black_box(buffer.clone());
            black_box(cloned.len());
        });
    });
}

fn bench_buffer_freeze(c: &mut Criterion) {
    c.bench_function("buffer_freeze", |b| {
        b.iter(|| {
            let mut buffer = ZeroCopyBufferMut::with_capacity(1024);
            buffer.data_mut().extend_from_slice(&[1u8; 512]);
            let frozen = black_box(buffer.freeze());
            black_box(frozen.len());
        });
    });
}

fn bench_buffer_data_access(c: &mut Criterion) {
    let data = bytes::Bytes::from(vec![42u8; 1024]);
    let buffer = ZeroCopyBuffer::from_bytes(data);

    c.bench_function("buffer_data_access", |b| {
        b.iter(|| {
            let data_slice = black_box(buffer.data());
            black_box(data_slice.len());
            black_box(data_slice[0]);
        });
    });
}

criterion_group!(
    benches,
    bench_buffer_pool_acquire_release,
    bench_zero_copy_buffer_clone,
    bench_buffer_freeze,
    bench_buffer_data_access
);
criterion_main!(benches);
