//! Zero-allocation Huffman encoding/decoding benchmarks
//! 
//! These benchmarks demonstrate the performance improvements from
//! the zero-allocation decode_into() API compared to the Vec-based decode() API.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use quicd_qpack::wire::huffman;

/// Benchmark decode_into (zero allocation) vs decode (Vec-based)
fn bench_huffman_decode_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("huffman_decode_comparison");

    let large_data = vec![b'a'; 4096];
    let test_cases = vec![
        ("small", b"www.example.com" as &[u8]),
        ("medium", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" as &[u8]),
        ("large", &large_data[..]),
    ];

    for (name, input) in test_cases {
        // Encode first
        let mut encoded = Vec::new();
        huffman::encode(input, &mut encoded);

        group.throughput(Throughput::Bytes(input.len() as u64));

        // Benchmark decode_into (zero-allocation)
        group.bench_with_input(
            BenchmarkId::new("decode_into_zero_alloc", name),
            &encoded,
            |b, encoded| {
                let mut output_buf = vec![0u8; input.len() * 2];
                b.iter(|| {
                    let written = huffman::decode_into(black_box(encoded), &mut output_buf).unwrap();
                    black_box(written);
                });
            },
        );

        // Benchmark decode (Vec-based, allocates)
        group.bench_with_input(
            BenchmarkId::new("decode_vec_alloc", name),
            &encoded,
            |b, encoded| {
                b.iter(|| {
                    let mut output = Vec::new();
                    let written = huffman::decode(black_box(encoded), &mut output).unwrap();
                    black_box(written);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark real-world header compression scenarios
fn bench_realistic_headers(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_header_huffman");

    // Typical HTTP/3 header values
    let headers = vec![
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-language", "en-US,en;q=0.9"),
        ("cookie", "session_id=abc123def456; user_pref=dark_mode; analytics_token=xyz789"),
    ];

    for (name, value) in headers {
        let value_bytes = value.as_bytes();
        let mut encoded = Vec::new();
        huffman::encode(value_bytes, &mut encoded);

        group.throughput(Throughput::Bytes(value_bytes.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("header", name),
            &encoded,
            |b, encoded| {
                let mut output_buf = vec![0u8; value_bytes.len() * 2];
                b.iter(|| {
                    let written = huffman::decode_into(black_box(encoded), &mut output_buf).unwrap();
                    black_box(written);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark encode_into vs encode
fn bench_huffman_encode_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("huffman_encode_comparison");

    let large_data = vec![b'x'; 4096];
    let test_cases = vec![
        ("small", b"www.example.com" as &[u8]),
        ("medium", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" as &[u8]),
        ("large", &large_data[..]),
    ];

    for (name, input) in test_cases {
        group.throughput(Throughput::Bytes(input.len() as u64));

        // Benchmark encode_into (pre-allocated buffer)
        group.bench_with_input(
            BenchmarkId::new("encode_into_prealloc", name),
            &input,
            |b, input| {
                let size = huffman::encoded_size(input);
                let mut output_buf = vec![0u8; size];
                b.iter(|| {
                    let written = huffman::encode_into(black_box(input), &mut output_buf).unwrap();
                    black_box(written);
                });
            },
        );

        // Benchmark encode (Vec-based)
        group.bench_with_input(
            BenchmarkId::new("encode_vec", name),
            &input,
            |b, input| {
                b.iter(|| {
                    let mut output = Vec::new();
                    huffman::encode(black_box(input), &mut output);
                    black_box(&output);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark full roundtrip (encode + decode)
fn bench_huffman_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("huffman_roundtrip");

    let test_data = b"www.example.com";
    group.throughput(Throughput::Bytes(test_data.len() as u64));

    // Zero-allocation roundtrip
    group.bench_function("zero_alloc_roundtrip", |b| {
        let encoded_size = huffman::encoded_size(test_data);
        let mut encode_buf = vec![0u8; encoded_size];
        let mut decode_buf = vec![0u8; test_data.len() * 2];

        b.iter(|| {
            let enc_len = huffman::encode_into(black_box(test_data), &mut encode_buf).unwrap();
            let dec_len = huffman::decode_into(black_box(&encode_buf[..enc_len]), &mut decode_buf).unwrap();
            black_box(dec_len);
        });
    });

    // Vec-based roundtrip
    group.bench_function("vec_alloc_roundtrip", |b| {
        b.iter(|| {
            let mut encoded = Vec::new();
            huffman::encode(black_box(test_data), &mut encoded);
            let mut decoded = Vec::new();
            let dec_len = huffman::decode(black_box(&encoded), &mut decoded).unwrap();
            black_box(dec_len);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_huffman_decode_methods,
    bench_realistic_headers,
    bench_huffman_encode_methods,
    bench_huffman_roundtrip
);
criterion_main!(benches);
