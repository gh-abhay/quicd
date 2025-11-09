use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quicd_h3::qpack::QpackCodec;

fn benchmark_huffman_encoding(c: &mut Criterion) {
    let codec = QpackCodec::new();

    let test_data = vec![
        "content-type: application/json",
        "cache-control: no-cache, no-store",
        "accept-encoding: gzip, deflate, br, zstd",
        "user-agent: Mozilla/5.0 (compatible; Test/1.0)",
        "x-forwarded-for: 192.168.1.1, 10.0.0.1",
    ];

    c.bench_function("huffman_encode", |b| {
        b.iter(|| {
            for data in &test_data {
                let _encoded = codec.encode_huffman(black_box(data.as_bytes()));
            }
        })
    });
}

fn benchmark_huffman_decoding(c: &mut Criterion) {
    let codec = QpackCodec::new();

    let test_data = vec![
        "content-type: application/json",
        "cache-control: no-cache, no-store",
        "accept-encoding: gzip, deflate, br, zstd",
        "user-agent: Mozilla/5.0 (compatible; Test/1.0)",
        "x-forwarded-for: 192.168.1.1, 10.0.0.1",
    ];

    // Pre-encode the data
    let encoded_data: Vec<Vec<u8>> = test_data
        .iter()
        .map(|data| codec.encode_huffman(data.as_bytes()).unwrap())
        .collect();

    c.bench_function("huffman_decode", |b| {
        b.iter(|| {
            for encoded in &encoded_data {
                let _decoded = codec.decode_huffman(black_box(encoded));
            }
        })
    });
}

fn benchmark_string_encoding(c: &mut Criterion) {
    let codec = QpackCodec::new();

    let test_strings = vec![
        "content-type",
        "application/json",
        "cache-control",
        "no-cache",
        "accept-encoding",
        "gzip, deflate, br",
    ];

    c.bench_function("string_encode", |b| {
        b.iter(|| {
            for s in &test_strings {
                let mut buf = bytes::BytesMut::new();
                codec.encode_string(&mut buf, black_box(s));
            }
        })
    });
}

fn benchmark_qpack_header_encoding(c: &mut Criterion) {
    let codec = QpackCodec::new();

    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("cache-control".to_string(), "no-cache".to_string()),
        ("accept-encoding".to_string(), "gzip, deflate, br".to_string()),
        ("user-agent".to_string(), "Test/1.0".to_string()),
    ];

    c.bench_function("qpack_header_encode", |b| {
        b.iter(|| {
            let _encoded = codec.encode_headers(black_box(&headers));
        })
    });
}

fn benchmark_qpack_header_decoding(c: &mut Criterion) {
    let codec = QpackCodec::new();

    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("cache-control".to_string(), "no-cache".to_string()),
        ("accept-encoding".to_string(), "gzip, deflate, br".to_string()),
        ("user-agent".to_string(), "Test/1.0".to_string()),
    ];

    // Pre-encode headers
    let encoded = codec.encode_headers(&headers).unwrap();

    c.bench_function("qpack_header_decode", |b| {
        b.iter(|| {
            let _decoded = codec.decode_headers(black_box(&encoded));
        })
    });
}

criterion_group!(
    benches,
    benchmark_huffman_encoding,
    benchmark_huffman_decoding,
    benchmark_string_encoding,
    benchmark_qpack_header_encoding,
    benchmark_qpack_header_decoding
);
criterion_main!(benches);