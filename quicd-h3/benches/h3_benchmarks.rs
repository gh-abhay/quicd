use criterion::{black_box, criterion_group, criterion_main, Criterion};
use bytes::{Bytes, BytesMut};
use quicd_h3::frames::{H3Frame, Setting};
use quicd_h3::qpack::QpackCodec;

fn benchmark_frame_encoding(c: &mut Criterion) {
    let frames = vec![
        H3Frame::Data { data: Bytes::from(vec![1, 2, 3, 4, 5]) },
        H3Frame::Headers { encoded_headers: Bytes::from(vec![1, 2, 3, 4, 5]) },
        H3Frame::CancelPush { push_id: 123 },
        H3Frame::Settings {
            settings: vec![
                Setting { identifier: 0x1, value: 100 },
                Setting { identifier: 0x6, value: 1 },
            ]
        },
        H3Frame::PushPromise {
            push_id: 456,
            encoded_headers: Bytes::from(vec![1, 2, 3, 4, 5]),
        },
        H3Frame::GoAway { stream_id: 789 },
        H3Frame::MaxPushId { push_id: 1000 },
        H3Frame::DuplicatePush { push_id: 2000 },
    ];

    c.bench_function("frame_encoding", |b| {
        b.iter(|| {
            for frame in &frames {
                let _encoded = frame.encode();
            }
        })
    });
}

fn benchmark_frame_decoding(c: &mut Criterion) {
    let frames = vec![
        H3Frame::Data { data: Bytes::from(vec![1, 2, 3, 4, 5]) },
        H3Frame::Headers { encoded_headers: Bytes::from(vec![1, 2, 3, 4, 5]) },
        H3Frame::CancelPush { push_id: 123 },
        H3Frame::Settings {
            settings: vec![
                Setting { identifier: 0x1, value: 100 },
                Setting { identifier: 0x6, value: 1 },
            ]
        },
        H3Frame::PushPromise {
            push_id: 456,
            encoded_headers: Bytes::from(vec![1, 2, 3, 4, 5]),
        },
        H3Frame::GoAway { stream_id: 789 },
        H3Frame::MaxPushId { push_id: 1000 },
        H3Frame::DuplicatePush { push_id: 2000 },
    ];

    // Pre-encode frames
    let encoded_frames: Vec<Bytes> = frames.iter().map(|f| f.encode()).collect();

    c.bench_function("frame_decoding", |b| {
        b.iter(|| {
            for encoded in &encoded_frames {
                let _decoded = H3Frame::parse(encoded).unwrap();
            }
        })
    });
}

fn benchmark_qpack_operations(c: &mut Criterion) {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(1024);

    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("cache-control".to_string(), "no-cache".to_string()),
        ("accept-encoding".to_string(), "gzip, deflate, br".to_string()),
        ("user-agent".to_string(), "Test/1.0".to_string()),
        ("x-custom-header".to_string(), "custom-value".to_string()),
    ];

    c.bench_function("qpack_header_encoding", |b| {
        b.iter(|| {
            let _encoded = codec.encode_headers(black_box(&headers));
        })
    });

    // Pre-encode for decoding benchmark
    let encoded = codec.encode_headers(&headers).unwrap();

    c.bench_function("qpack_header_decoding", |b| {
        b.iter(|| {
            let _decoded = codec.decode_headers(black_box(&encoded));
        })
    });
}

fn benchmark_huffman_operations(c: &mut Criterion) {
    let codec = QpackCodec::new();

    let test_strings = vec![
        "content-type: application/json",
        "cache-control: no-cache, no-store",
        "accept-encoding: gzip, deflate, br, zstd",
        "user-agent: Mozilla/5.0 (compatible; Test/1.0)",
        "x-forwarded-for: 192.168.1.1, 10.0.0.1",
        "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ];

    c.bench_function("huffman_encoding", |b| {
        b.iter(|| {
            for s in &test_strings {
                let _encoded = codec.encode_huffman(black_box(s.as_bytes()));
            }
        })
    });

    // Pre-encode for decoding benchmark
    let encoded_strings: Vec<Vec<u8>> = test_strings
        .iter()
        .map(|s| codec.encode_huffman(s.as_bytes()).unwrap())
        .collect();

    c.bench_function("huffman_decoding", |b| {
        b.iter(|| {
            for encoded in &encoded_strings {
                let _decoded = codec.decode_huffman(black_box(encoded));
            }
        })
    });
}

fn benchmark_string_operations(c: &mut Criterion) {
    let codec = QpackCodec::new();

    let test_strings = vec![
        "content-type",
        "application/json",
        "cache-control",
        "no-cache",
        "accept-encoding",
        "gzip, deflate, br",
        "x-long-header-name-that-should-benefit-from-huffman-encoding",
        "x-long-header-value-that-should-benefit-from-huffman-encoding-and-compression",
    ];

    c.bench_function("string_encoding", |b| {
        b.iter(|| {
            for s in &test_strings {
                let mut buf = BytesMut::new();
                codec.encode_string(&mut buf, black_box(s));
            }
        })
    });

    // Pre-encode for decoding benchmark
    let mut encoded_strings = Vec::new();
    for s in &test_strings {
        let mut buf = BytesMut::new();
        codec.encode_string(&mut buf, s);
        encoded_strings.push(buf.freeze());
    }

    c.bench_function("string_decoding", |b| {
        b.iter(|| {
            for encoded in &encoded_strings {
                let _decoded = codec.decode_string(black_box(encoded));
            }
        })
    });
}

fn benchmark_large_headers(c: &mut Criterion) {
    let codec = QpackCodec::new();

    // Create large headers to test performance with bigger data
    let large_value = "x".repeat(1000);
    let large_headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("x-large-header".to_string(), large_value.clone()),
        ("x-another-large-header".to_string(), large_value.clone()),
        ("cache-control".to_string(), "no-cache".to_string()),
    ];

    c.bench_function("large_header_encoding", |b| {
        b.iter(|| {
            let _encoded = codec.encode_headers(black_box(&large_headers));
        })
    });

    // Pre-encode for decoding benchmark
    let encoded = codec.encode_headers(&large_headers).unwrap();

    c.bench_function("large_header_decoding", |b| {
        b.iter(|| {
            let _decoded = codec.decode_headers(black_box(&encoded));
        })
    });
}

fn benchmark_settings_operations(c: &mut Criterion) {
    let settings_list = vec![
        vec![
            Setting { identifier: 0x1, value: 100 },
            Setting { identifier: 0x6, value: 1 },
        ],
        vec![
            Setting { identifier: 0x1, value: 256 },
            Setting { identifier: 0x3, value: 1000 },
            Setting { identifier: 0x4, value: 1 },
            Setting { identifier: 0x6, value: 1 },
        ],
        vec![
            Setting { identifier: 0x1, value: 4096 },
            Setting { identifier: 0x2, value: 0 },
            Setting { identifier: 0x3, value: 100 },
            Setting { identifier: 0x4, value: 1 },
            Setting { identifier: 0x5, value: 1 },
            Setting { identifier: 0x6, value: 1 },
        ],
    ];

    c.bench_function("settings_encoding", |b| {
        b.iter(|| {
            for settings in &settings_list {
                let frame = H3Frame::Settings { settings: settings.clone() };
                let _encoded = frame.encode();
            }
        })
    });

    // Pre-encode for decoding benchmark
    let encoded_settings: Vec<Bytes> = settings_list
        .iter()
        .map(|settings| H3Frame::Settings { settings: settings.clone() }.encode())
        .collect();

    c.bench_function("settings_decoding", |b| {
        b.iter(|| {
            for encoded in &encoded_settings {
                let _decoded = H3Frame::parse(encoded).unwrap();
            }
        })
    });
}

criterion_group!(
    benches,
    benchmark_frame_encoding,
    benchmark_frame_decoding,
    benchmark_qpack_operations,
    benchmark_huffman_operations,
    benchmark_string_operations,
    benchmark_large_headers,
    benchmark_settings_operations
);
criterion_main!(benches);