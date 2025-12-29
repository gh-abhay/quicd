//! Benchmarks for routing module hot paths.
//!
//! These benchmarks measure performance of:
//! - Cookie generation and validation
//! - Connection ID generation
//! - SipHash protection verification
//!
//! Run with: cargo bench -p quicd --bench routing_benchmark

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use quicd::routing::router::{ConnectionId, Cookie, CID_LENGTH};

/// Benchmark cookie generation (per-connection hot path)
fn bench_cookie_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cookie_generation");
    group.throughput(Throughput::Elements(1));
    
    group.bench_function("generate", |b| {
        let mut gen: u8 = 0;
        let mut worker: u8 = 0;
        b.iter(|| {
            let cookie = Cookie::generate(black_box(gen), black_box(worker));
            gen = gen.wrapping_add(1) & 0x1F;
            worker = worker.wrapping_add(1);
            cookie
        })
    });
    
    group.finish();
}

/// Benchmark cookie validation (per-packet hot path)
fn bench_cookie_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cookie_validation");
    group.throughput(Throughput::Elements(1));
    
    // Pre-generate valid cookies
    let valid_cookies: Vec<u16> = (0..256)
        .map(|i| Cookie::generate((i % 32) as u8, i as u8))
        .collect();
    
    group.bench_function("validate_valid", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cookie = valid_cookies[idx];
            idx = (idx + 1) % valid_cookies.len();
            Cookie::validate(black_box(cookie))
        })
    });
    
    // Invalid cookies (corrupted checksum)
    let invalid_cookies: Vec<u16> = valid_cookies.iter().map(|c| c ^ 0x07).collect();
    
    group.bench_function("validate_invalid", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cookie = invalid_cookies[idx];
            idx = (idx + 1) % invalid_cookies.len();
            Cookie::validate(black_box(cookie))
        })
    });
    
    group.finish();
}

/// Benchmark cookie field extraction (per-packet hot path)
fn bench_cookie_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cookie_extraction");
    group.throughput(Throughput::Elements(1));
    
    let cookies: Vec<u16> = (0..256)
        .map(|i| Cookie::generate((i % 32) as u8, i as u8))
        .collect();
    
    group.bench_function("get_generation", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cookie = cookies[idx];
            idx = (idx + 1) % cookies.len();
            Cookie::get_generation(black_box(cookie))
        })
    });
    
    group.bench_function("get_worker_idx", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cookie = cookies[idx];
            idx = (idx + 1) % cookies.len();
            Cookie::get_worker_idx(black_box(cookie))
        })
    });
    
    group.finish();
}

/// Benchmark CID generation (per-connection hot path)
fn bench_cid_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cid_generation");
    group.throughput(Throughput::Bytes(CID_LENGTH as u64));
    
    // Benchmark with real randomness (production path)
    group.bench_function("generate_random", |b| {
        let mut gen: u8 = 0;
        let mut worker: u8 = 0;
        b.iter(|| {
            let cid = ConnectionId::generate(black_box(gen), black_box(worker))
                .expect("CID generation should succeed");
            gen = gen.wrapping_add(1) & 0x1F;
            worker = worker.wrapping_add(1);
            cid
        })
    });
    
    // Benchmark with seeded generation (for comparison)
    group.bench_function("generate_seeded", |b| {
        let mut gen: u8 = 0;
        let mut worker: u8 = 0;
        let mut seed: u32 = 0x12345678;
        b.iter(|| {
            let cid = ConnectionId::generate_with_seed(
                black_box(gen),
                black_box(worker),
                black_box(seed),
            );
            gen = gen.wrapping_add(1) & 0x1F;
            worker = worker.wrapping_add(1);
            seed = seed.wrapping_add(1);
            cid
        })
    });
    
    // Benchmark with provided entropy
    group.bench_function("generate_with_entropy", |b| {
        let entropy = [0xAAu8; 17];
        let mut gen: u8 = 0;
        let mut worker: u8 = 0;
        b.iter(|| {
            let cid = ConnectionId::generate_with_entropy(
                black_box(gen),
                black_box(worker),
                black_box(entropy),
            );
            gen = gen.wrapping_add(1) & 0x1F;
            worker = worker.wrapping_add(1);
            cid
        })
    });
    
    group.finish();
}

/// Benchmark SipHash protection verification (per-packet hot path)
fn bench_siphash_protection(c: &mut Criterion) {
    let mut group = c.benchmark_group("siphash_protection");
    group.throughput(Throughput::Bytes(CID_LENGTH as u64));
    
    // Pre-generate valid CIDs
    let valid_cids: Vec<[u8; 20]> = (0..256)
        .map(|i| ConnectionId::generate_with_seed((i % 32) as u8, i as u8, 0x12345678 + i as u32))
        .collect();
    
    group.bench_function("verify_valid", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cid = &valid_cids[idx];
            idx = (idx + 1) % valid_cids.len();
            ConnectionId::verify_protection(black_box(cid))
        })
    });
    
    // Invalid CIDs (corrupted byte)
    let invalid_cids: Vec<[u8; 20]> = valid_cids
        .iter()
        .map(|cid| {
            let mut corrupted = *cid;
            corrupted[10] ^= 0xFF;
            corrupted
        })
        .collect();
    
    group.bench_function("verify_invalid", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cid = &invalid_cids[idx];
            idx = (idx + 1) % invalid_cids.len();
            ConnectionId::verify_protection(black_box(cid))
        })
    });
    
    group.finish();
}

/// Benchmark cookie extraction from CID (per-packet hot path)
fn bench_cid_cookie_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cid_cookie_extraction");
    group.throughput(Throughput::Bytes(CID_LENGTH as u64));
    
    let cids: Vec<[u8; 20]> = (0..256)
        .map(|i| ConnectionId::generate_with_seed((i % 32) as u8, i as u8, 0xDEADBEEF + i as u32))
        .collect();
    
    group.bench_function("extract_cookie", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cid = &cids[idx];
            idx = (idx + 1) % cids.len();
            ConnectionId::extract_cookie(black_box(cid))
        })
    });
    
    group.bench_function("validate_cookie", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cid = &cids[idx];
            idx = (idx + 1) % cids.len();
            ConnectionId::validate_cookie(black_box(cid))
        })
    });
    
    group.bench_function("get_worker_idx", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cid = &cids[idx];
            idx = (idx + 1) % cids.len();
            ConnectionId::get_worker_idx(black_box(cid))
        })
    });
    
    group.bench_function("get_generation", |b| {
        let mut idx = 0;
        b.iter(|| {
            let cid = &cids[idx];
            idx = (idx + 1) % cids.len();
            ConnectionId::get_generation(black_box(cid))
        })
    });
    
    group.finish();
}

/// Benchmark complete packet routing simulation
fn bench_packet_routing_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_routing_simulation");
    
    // Simulate short header packet: 1 byte header + 20 byte DCID
    let short_packets: Vec<Vec<u8>> = (0..256)
        .map(|i| {
            let cid = ConnectionId::generate_with_seed((i % 32) as u8, i as u8, 0xCAFE0000 + i as u32);
            let mut packet = vec![0x40]; // Short header
            packet.extend_from_slice(&cid);
            packet
        })
        .collect();
    
    group.bench_function("short_header_extract_and_validate", |b| {
        let mut idx = 0;
        b.iter(|| {
            let packet = &short_packets[idx];
            idx = (idx + 1) % short_packets.len();
            
            // Simulate eBPF extraction logic
            let cookie = u16::from_be_bytes([packet[7], packet[8]]);
            let valid = Cookie::validate(cookie);
            let worker = Cookie::get_worker_idx(cookie);
            (valid, worker)
        })
    });
    
    // Simulate long header packet: 1 byte + 4 bytes version + 1 byte DCID len + 20 byte DCID
    let long_packets: Vec<Vec<u8>> = (0..256)
        .map(|i| {
            let cid = ConnectionId::generate_with_seed((i % 32) as u8, i as u8, 0xBEEF0000 + i as u32);
            let mut packet = vec![
                0xC0,       // Long header
                0x00, 0x00, 0x00, 0x01, // Version 1
                20,         // DCID length
            ];
            packet.extend_from_slice(&cid);
            packet
        })
        .collect();
    
    group.bench_function("long_header_extract_and_validate", |b| {
        let mut idx = 0;
        b.iter(|| {
            let packet = &long_packets[idx];
            idx = (idx + 1) % long_packets.len();
            
            // Simulate eBPF extraction logic
            let dcid_len = packet[5] as usize;
            if dcid_len < 8 {
                return (false, 0u8);
            }
            // Cookie is at offset 6 + 6 = 12
            let cookie = u16::from_be_bytes([packet[12], packet[13]]);
            let valid = Cookie::validate(cookie);
            let worker = Cookie::get_worker_idx(cookie);
            (valid, worker)
        })
    });
    
    group.finish();
}

/// Benchmark RoutingConnectionIdGenerator (the actual interface used)
fn bench_routing_cid_generator(c: &mut Criterion) {
    use quicd::routing::cid_generator::RoutingConnectionIdGenerator;
    use quicd_quic::cid::ConnectionIdGenerator;
    
    let mut group = c.benchmark_group("routing_cid_generator");
    group.throughput(Throughput::Bytes(CID_LENGTH as u64));
    
    group.bench_function("generate_via_trait", |b| {
        let generator = RoutingConnectionIdGenerator::new(42, 0);
        b.iter(|| {
            generator.generate(black_box(20))
        })
    });
    
    group.bench_function("generation_update", |b| {
        let generator = RoutingConnectionIdGenerator::new(42, 0);
        let mut gen: u8 = 0;
        b.iter(|| {
            generator.set_generation(black_box(gen));
            gen = gen.wrapping_add(1) & 0x1F;
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_cookie_generation,
    bench_cookie_validation,
    bench_cookie_extraction,
    bench_cid_generation,
    bench_siphash_protection,
    bench_cid_cookie_extraction,
    bench_packet_routing_simulation,
    bench_routing_cid_generator,
);

criterion_main!(benches);
