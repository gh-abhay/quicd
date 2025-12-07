use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use quicd_qpack::Encoder;
use bytes::BytesMut;

fn bench_encode_into(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_into");

    let headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":path".as_slice(), b"/".as_slice()),
        (b":authority".as_slice(), b"example.com".as_slice()),
    ];

    group.throughput(Throughput::Elements(1));
    group.bench_function("4_headers_reused_buffer", |b| {
        let mut encoder = Encoder::new(0, 0);
        let mut buf = BytesMut::with_capacity(1024);
        b.iter(|| {
            buf.clear();
            encoder.encode_into(0, &headers, &mut buf).unwrap();
            black_box(&buf);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_encode_into);
criterion_main!(benches);
