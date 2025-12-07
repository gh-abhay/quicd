//! Performance benchmarks for QPACK encoder/decoder

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use quicd_qpack::{Decoder, Encoder};

fn bench_encode_static_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_static_only");

    let headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":path".as_slice(), b"/".as_slice()),
        (b":authority".as_slice(), b"example.com".as_slice()),
    ];

    group.throughput(Throughput::Elements(1));
    group.bench_function("4_headers", |b| {
        let mut encoder = Encoder::new(0, 0);
        b.iter(|| {
            black_box(encoder.encode(0, &headers).unwrap());
        });
    });

    group.finish();
}

fn bench_encode_with_dynamic(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_with_dynamic");

    let headers = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b":path".as_slice(), b"/api/data".as_slice()),
        (b"content-type".as_slice(), b"application/json".as_slice()),
        (b"x-custom-1".as_slice(), b"value1".as_slice()),
        (b"x-custom-2".as_slice(), b"value2".as_slice()),
    ];

    group.throughput(Throughput::Elements(1));
    group.bench_function("5_headers_mixed", |b| {
        let mut encoder = Encoder::new(4096, 100);
        let mut stream_id = 0u64;
        b.iter(|| {
            black_box(encoder.encode(stream_id, &headers).unwrap());
            stream_id = stream_id.wrapping_add(4);
        });
    });

    group.finish();
}

fn bench_decode_static_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_static_only");

    let headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":path".as_slice(), b"/".as_slice()),
    ];

    let mut encoder = Encoder::new(0, 0);
    let encoded = encoder.encode(0, &headers).unwrap();

    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("3_headers", |b| {
        let mut decoder = Decoder::new(0, 0);
        b.iter(|| {
            black_box(decoder.decode(0, encoded.clone()).unwrap());
        });
    });

    group.finish();
}

fn bench_decode_with_dynamic(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_with_dynamic");

    // Prepare encoder and decoder with some dynamic table state
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Prime the dynamic table
    for i in 0..10 {
        let name = format!("x-header-{}", i);
        let prep_headers = vec![(name.as_bytes(), b"value".as_slice())];
        let _ = encoder.encode(i, &prep_headers);
    }

    for inst in encoder.drain_encoder_stream() {
        let _ = decoder.process_encoder_instruction(&inst);
    }

    // Now benchmark actual decoding
    let headers = vec![
        (b"x-header-5".as_slice(), b"value".as_slice()),
        (b":method".as_slice(), b"POST".as_slice()),
    ];

    let encoded = encoder.encode(100, &headers).unwrap();

    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("with_dynamic_refs", |b| {
        b.iter(|| {
            black_box(decoder.decode(100, encoded.clone()).unwrap());
        });
    });

    group.finish();
}

fn bench_table_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("table_insert");

    group.throughput(Throughput::Elements(1));
    group.bench_function("single_insert", |b| {
        b.iter(|| {
            let mut encoder = Encoder::new(1024 * 1024, 100000);
            let headers = vec![(b"header".as_slice(), b"test-value".as_slice())];
            black_box(encoder.encode(0, &headers).unwrap());
        });
    });

    group.finish();
}

fn bench_table_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("table_lookup");

    // Prepare table with entries
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();
    for i in 0..100 {
        let name = format!("header-{}", i);
        let headers = vec![(name.as_bytes(), b"value".as_slice())];
        let _ = encoder.encode(i, &headers);
    }

    group.throughput(Throughput::Elements(1));
    group.bench_function("find_exact_100_entries", |b| {
        b.iter(|| {
            black_box(encoder.table().find_exact(b"header-50", b"value"));
        });
    });

    group.bench_function("find_name_100_entries", |b| {
        b.iter(|| {
            black_box(encoder.table().find_name(b"header-75"));
        });
    });

    group.finish();
}

fn bench_prefix_integer(c: &mut Criterion) {
    use quicd_qpack::wire::prefix_int::{decode_int, encode_int};

    let mut group = c.benchmark_group("prefix_integer");

    for value in [10u64, 127, 1337, 65535].iter() {
        group.bench_with_input(BenchmarkId::new("encode", value), value, |b, &v| {
            b.iter(|| {
                black_box(encode_int(v, 7));
            });
        });

        let encoded = encode_int(*value, 7);
        group.bench_with_input(BenchmarkId::new("decode", value), &encoded, |b, enc| {
            b.iter(|| {
                black_box(decode_int(enc, 7).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_huffman_encode(c: &mut Criterion) {
    use quicd_qpack::wire::huffman;

    let mut group = c.benchmark_group("huffman_encode");

    let inputs = vec![
        ("short", b"www.example.com" as &[u8]),
        ("medium", b"application/json; charset=utf-8"),
        (
            "long",
            b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ),
    ];

    for (name, input) in inputs {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, inp| {
            b.iter(|| {
                let mut output = Vec::new();
                huffman::encode(inp, &mut output);
                black_box(output);
            });
        });
    }

    group.finish();
}

fn bench_huffman_decode(c: &mut Criterion) {
    use quicd_qpack::wire::huffman;

    let mut group = c.benchmark_group("huffman_decode");

    let input = b"www.example.com";
    let mut encoded = Vec::new();
    huffman::encode(input, &mut encoded);

    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("decode_encoded_string", |b| {
        b.iter(|| {
            let mut output = Vec::new();
            huffman::decode(&encoded, &mut output).unwrap();
            black_box(output);
        });
    });

    group.finish();
}

fn bench_full_request_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_request_cycle");

    // Typical HTTP/3 request headers
    let request_headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":authority".as_slice(), b"www.example.com".as_slice()),
        (b":path".as_slice(), b"/index.html".as_slice()),
        (b"user-agent".as_slice(), b"quicd/1.0".as_slice()),
        (b"accept".as_slice(), b"text/html".as_slice()),
        (b"accept-encoding".as_slice(), b"gzip, br".as_slice()),
    ];

    group.throughput(Throughput::Elements(1));
    group.bench_function("encode_decode_request", |b| {
        let mut encoder = Encoder::new(4096, 100);
        let mut decoder = Decoder::new(4096, 100);
        let mut stream_id = 0u64;

        b.iter(|| {
            let encoded = encoder.encode(stream_id, &request_headers).unwrap();

            // Process encoder instructions
            while let Some(inst) = encoder.poll_encoder_stream() {
                let _ = decoder.process_encoder_instruction(&inst);
            }

            let decoded = decoder.decode(stream_id, encoded).unwrap();

            // Process decoder instructions
            while let Some(inst) = decoder.poll_decoder_stream() {
                let _ = encoder.process_decoder_instruction(&inst);
            }

            black_box(decoded);
            stream_id = stream_id.wrapping_add(4);
        });
    });

    group.finish();
}

fn bench_high_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("high_throughput");

    // Realistic HTTP/3 headers
    let headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":authority".as_slice(), b"api.example.com".as_slice()),
        (b":path".as_slice(), b"/v1/users/123".as_slice()),
        (b"user-agent".as_slice(), b"quicd/1.0".as_slice()),
        (b"accept".as_slice(), b"application/json".as_slice()),
        (b"authorization".as_slice(), b"Bearer token123".as_slice()),
    ];

    // Single operation throughput
    group.throughput(Throughput::Elements(1));
    group.bench_function("encode_single", |b| {
        let mut encoder = Encoder::new(4096, 100);
        let mut stream_id = 0u64;

        b.iter(|| {
            let encoded = encoder.encode(stream_id, &headers).unwrap();
            stream_id = stream_id.wrapping_add(4);
            black_box(encoded);
        });
    });

    group.bench_function("decode_single", |b| {
        let mut encoder = Encoder::new(4096, 100);
        let mut decoder = Decoder::new(4096, 100);

        // Prime the tables
        for i in 0..10 {
            let _ = encoder.encode(i, &headers);
        }
        for inst in encoder.drain_encoder_stream() {
            let _ = decoder.process_encoder_instruction(&inst);
        }

        let encoded = encoder.encode(100, &headers).unwrap();

        b.iter(|| {
            let decoded = decoder.decode(100, encoded.clone()).unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

fn bench_concurrent_streams(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_streams");

    // Simulate multiple concurrent streams with different header sets
    let stream_headers = vec![
        vec![
            (b":method".as_slice(), b"GET".as_slice()),
            (b":path".as_slice(), b"/page1".as_slice()),
        ],
        vec![
            (b":method".as_slice(), b"POST".as_slice()),
            (b":path".as_slice(), b"/api/create".as_slice()),
            (b"content-type".as_slice(), b"application/json".as_slice()),
        ],
        vec![
            (b":method".as_slice(), b"GET".as_slice()),
            (b":path".as_slice(), b"/static/image.jpg".as_slice()),
            (b"accept".as_slice(), b"image/*".as_slice()),
        ],
    ];

    group.throughput(Throughput::Elements(3));
    group.bench_function("3_streams_roundtrip", |b| {
        let mut encoder = Encoder::new(4096, 100);
        let mut decoder = Decoder::new(4096, 100);
        let mut stream_id = 0u64;

        b.iter(|| {
            for headers in &stream_headers {
                let encoded = encoder.encode(stream_id, headers).unwrap();

                while let Some(inst) = encoder.poll_encoder_stream() {
                    let _ = decoder.process_encoder_instruction(&inst);
                }

                let _ = decoder.decode(stream_id, encoded).unwrap();

                while let Some(inst) = decoder.poll_decoder_stream() {
                    let _ = encoder.process_decoder_instruction(&inst);
                }

                stream_id = stream_id.wrapping_add(4);
            }
        });
    });

    group.finish();
}

/// Benchmark HashMap optimization for table lookups
fn bench_hashmap_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashmap_lookup");

    // Create encoder with populated dynamic table
    let mut encoder = Encoder::new(16384, 100);
    encoder.set_capacity(16384).unwrap();

    // Insert 100 different headers
    for i in 0..100 {
        let name = format!("x-header-{:03}", i);
        let value = format!("value-{}", i);
        let headers = vec![(name.as_bytes(), value.as_bytes())];
        let _ = encoder.encode(i, &headers);
        let _ = encoder.drain_encoder_stream();
    }

    group.throughput(Throughput::Elements(1));

    // Benchmark finding existing entry (best case - should be O(1) with HashMap)
    group.bench_function("find_exact_existing", |b| {
        b.iter(|| {
            let found = encoder.table().find_exact(b"x-header-050", b"value-50");
            black_box(found);
        });
    });

    // Benchmark finding by name only
    group.bench_function("find_name_existing", |b| {
        b.iter(|| {
            let found = encoder.table().find_name(b"x-header-050");
            black_box(found);
        });
    });

    // Benchmark miss case
    group.bench_function("find_exact_missing", |b| {
        b.iter(|| {
            let found = encoder.table().find_exact(b"x-nonexistent", b"value");
            black_box(found);
        });
    });

    group.finish();
}

/// Benchmark encoder instruction batching
fn bench_instruction_batching(c: &mut Criterion) {
    let mut group = c.benchmark_group("instruction_batching");

    // Create encoder that will generate many instructions
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();

    // Generate 50 instructions
    for i in 0..50 {
        let name = format!("x-batch-{}", i);
        let value = format!("v{}", i);
        let headers = vec![(name.as_bytes(), value.as_bytes())];
        let _ = encoder.encode(i, &headers);
    }

    group.throughput(Throughput::Elements(50));

    // Benchmark individual polling
    group.bench_function("poll_individual", |b| {
        b.iter(|| {
            // Create fresh encoder with instructions
            let mut enc = Encoder::new(4096, 100);
            enc.set_capacity(4096).unwrap();
            for i in 0..50 {
                let name = format!("x-b-{}", i);
                let value = format!("v{}", i);
                let h = vec![(name.as_bytes(), value.as_bytes())];
                let _ = enc.encode(i, &h);
            }

            let mut count = 0;
            while enc.poll_encoder_stream().is_some() {
                count += 1;
            }
            black_box(count);
        });
    });

    // Benchmark batched polling
    group.bench_function("poll_batch_8", |b| {
        b.iter(|| {
            // Create fresh encoder with instructions
            let mut enc = Encoder::new(4096, 100);
            enc.set_capacity(4096).unwrap();
            for i in 0..50 {
                let name = format!("x-b-{}", i);
                let value = format!("v{}", i);
                let h = vec![(name.as_bytes(), value.as_bytes())];
                let _ = enc.encode(i, &h);
            }

            let mut count = 0;
            while let Some(batch) = enc.poll_encoder_stream_batch(8) {
                count += 1;
                black_box(batch);
            }
            black_box(count);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_encode_static_only,
    bench_encode_with_dynamic,
    bench_decode_static_only,
    bench_decode_with_dynamic,
    bench_table_insert,
    bench_table_lookup,
    bench_prefix_integer,
    bench_huffman_encode,
    bench_huffman_decode,
    bench_full_request_cycle,
    bench_high_throughput,
    bench_concurrent_streams,
    bench_hashmap_optimization,
    bench_instruction_batching,
);

criterion_main!(benches);
