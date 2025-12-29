//! RFC-Compliant Tests for quicd/src/routing module.
//!
//! These tests validate compliance with:
//! - RFC 9000: QUIC Transport Protocol (Section 5.1 - Connection IDs)
//! - RFC 9000: Section 17.2 (Long Header Packet Format)
//! - RFC 9000: Section 17.3 (Short Header Packet Format)
//! - RFC 8999: Version-Independent Properties (Section 5.3)
//!
//! Tests are designed to FAIL if the implementation violates RFC requirements.

use super::router::{ConnectionId, Cookie, CID_LENGTH};

// ============================================================================
// RFC 9000 Section 5.1 - Connection ID Requirements
// ============================================================================

/// RFC 9000 Section 17.2: "In QUIC version 1, this value MUST NOT exceed 20 bytes"
#[test]
fn test_rfc9000_cid_length_constant_must_not_exceed_20() {
    assert!(
        CID_LENGTH <= 20,
        "RFC 9000 Section 17.2 VIOLATION: CID_LENGTH {} exceeds 20 bytes",
        CID_LENGTH
    );
}

/// RFC 9000 Section 5.1: Connection IDs can be 0-20 bytes
#[test]
fn test_rfc9000_cid_generation_produces_valid_length() {
    let cid = ConnectionId::generate(0, 0).expect("CID generation should succeed");
    assert!(
        cid.len() <= 20,
        "RFC 9000 Section 17.2 VIOLATION: Generated CID length {} exceeds 20",
        cid.len()
    );
}

/// RFC 9000 Section 5.1: "Connection IDs MUST NOT contain any information
/// that can be used by an external observer to correlate them with other
/// connection IDs for the same connection."
/// 
/// This test verifies that different CIDs for the same worker have different
/// random prefixes (statistically - not a guarantee, but high probability).
#[test]
fn test_rfc9000_cid_unpredictability_different_random_prefix() {
    let cid1 = ConnectionId::generate(0, 42).expect("CID generation should succeed");
    let cid2 = ConnectionId::generate(0, 42).expect("CID generation should succeed");
    
    // The random prefix (bytes 0-5) should differ with high probability
    // Note: This is probabilistic - 1 in 2^48 chance of collision
    assert_ne!(
        &cid1[0..6],
        &cid2[0..6],
        "CIDs for same worker should have different random prefixes"
    );
}

/// RFC 9000 Section 5.1: "the same connection ID MUST NOT be issued more than
/// once on the same connection"
#[test]
fn test_rfc9000_cid_uniqueness_across_generations() {
    // Generate CIDs with same worker but different generations
    let cid_gen0 = ConnectionId::generate_with_seed(0, 42, 0x12345678);
    let cid_gen1 = ConnectionId::generate_with_seed(1, 42, 0x12345678);
    
    // Same seed but different generation should produce different CIDs
    // (due to different cookie values in bytes 6-7)
    assert_ne!(
        cid_gen0, cid_gen1,
        "CIDs with different generations must differ"
    );
}

// ============================================================================
// Cookie Format Tests (Bits 11-15: gen, Bits 3-10: worker, Bits 0-2: checksum)
// ============================================================================

/// Test cookie generation format: 5-bit generation, 8-bit worker, 3-bit checksum
#[test]
fn test_cookie_format_generation_bits() {
    // Generation occupies bits 11-15 (5 bits, max value 31)
    for gen in 0..=31u8 {
        let cookie = Cookie::generate(gen, 0);
        let extracted_gen = Cookie::get_generation(cookie);
        assert_eq!(
            extracted_gen, gen,
            "Cookie generation mismatch: expected {}, got {}",
            gen, extracted_gen
        );
    }
}

/// Test cookie generation: generation wraps at 5 bits (only lower 5 bits used)
#[test]
fn test_cookie_generation_wraps_at_5_bits() {
    // Generation 32 should wrap to 0 (only lower 5 bits used)
    let cookie_32 = Cookie::generate(32, 0);
    let cookie_0 = Cookie::generate(0, 0);
    assert_eq!(
        cookie_32, cookie_0,
        "Generation 32 should wrap to 0 (5-bit field)"
    );
}

/// Test cookie format: 8-bit worker index (0-255)
#[test]
fn test_cookie_format_worker_bits() {
    for worker in [0u8, 1, 127, 128, 254, 255] {
        let cookie = Cookie::generate(0, worker);
        let extracted_worker = Cookie::get_worker_idx(cookie);
        assert_eq!(
            extracted_worker, worker,
            "Cookie worker mismatch: expected {}, got {}",
            worker, extracted_worker
        );
    }
}

/// Test cookie checksum: (generation + worker_idx) & 0x7
#[test]
fn test_cookie_checksum_calculation() {
    let test_cases = [
        (0u8, 0u8),   // checksum = 0
        (1, 2),       // checksum = 3
        (7, 0),       // checksum = 7
        (8, 0),       // checksum = 0 (wraps)
        (31, 255),    // checksum = (31 + 255) & 0x7 = 286 & 7 = 6
    ];
    
    for (gen, worker) in test_cases {
        let cookie = Cookie::generate(gen, worker);
        assert!(
            Cookie::validate(cookie),
            "Cookie validation failed for gen={}, worker={}",
            gen, worker
        );
    }
}

/// Test cookie validation rejects corrupted checksums
#[test]
fn test_cookie_validation_rejects_corrupt_checksum() {
    let cookie = Cookie::generate(0, 42);
    
    // Corrupt the checksum bits (lowest 3 bits)
    let corrupted = cookie ^ 0x07; // Flip all checksum bits
    
    assert!(
        !Cookie::validate(corrupted),
        "Corrupted cookie should fail validation"
    );
}

/// Test all valid generation/worker combinations produce valid cookies
#[test]
fn test_cookie_all_valid_combinations() {
    // Test a sample of all combinations
    for gen in [0u8, 1, 15, 16, 30, 31] {
        for worker in [0u8, 1, 127, 128, 254, 255] {
            let cookie = Cookie::generate(gen, worker);
            assert!(
                Cookie::validate(cookie),
                "Valid cookie should pass validation: gen={}, worker={}",
                gen, worker
            );
            assert_eq!(
                Cookie::get_generation(cookie),
                gen,
                "Generation extraction failed"
            );
            assert_eq!(
                Cookie::get_worker_idx(cookie),
                worker,
                "Worker extraction failed"
            );
        }
    }
}

// ============================================================================
// Connection ID Cookie Embedding Tests
// ============================================================================

/// Test CID format: cookie at bytes 6-7 (big-endian)
#[test]
fn test_cid_cookie_position() {
    let gen = 5u8;
    let worker = 42u8;
    let expected_cookie = Cookie::generate(gen, worker);
    
    let cid = ConnectionId::generate_with_seed(gen, worker, 0xDEADBEEF);
    
    // Extract cookie from bytes 6-7
    let extracted_cookie = u16::from_be_bytes([cid[6], cid[7]]);
    
    assert_eq!(
        extracted_cookie, expected_cookie,
        "Cookie at bytes 6-7 mismatch: expected {:#06x}, got {:#06x}",
        expected_cookie, extracted_cookie
    );
}

/// Test CID cookie extraction function
#[test]
fn test_cid_extract_cookie() {
    let gen = 10u8;
    let worker = 100u8;
    let expected_cookie = Cookie::generate(gen, worker);
    
    let cid = ConnectionId::generate_with_seed(gen, worker, 0xCAFEBABE);
    
    let extracted = ConnectionId::extract_cookie(&cid);
    assert_eq!(
        extracted,
        Some(expected_cookie),
        "extract_cookie() returned wrong value"
    );
}

/// Test CID extraction fails for short buffers
#[test]
fn test_cid_extract_cookie_short_buffer() {
    let short_cid = [0u8; 7]; // Less than 8 bytes
    assert_eq!(
        ConnectionId::extract_cookie(&short_cid),
        None,
        "extract_cookie should return None for buffers < 8 bytes"
    );
}

/// Test CID get_worker_idx function
#[test]
fn test_cid_get_worker_idx() {
    for worker in [0u8, 42, 127, 255] {
        let cid = ConnectionId::generate_with_seed(0, worker, 0x12345678);
        let extracted = ConnectionId::get_worker_idx(&cid);
        assert_eq!(
            extracted,
            Some(worker),
            "get_worker_idx() mismatch for worker {}",
            worker
        );
    }
}

/// Test CID get_generation function
#[test]
fn test_cid_get_generation() {
    for gen in [0u8, 15, 31] {
        let cid = ConnectionId::generate_with_seed(gen, 0, 0x12345678);
        let extracted = ConnectionId::get_generation(&cid);
        assert_eq!(
            extracted,
            Some(gen),
            "get_generation() mismatch for generation {}",
            gen
        );
    }
}

// ============================================================================
// SipHash Protection Tests
// ============================================================================

/// Test CID protection byte (SipHash-1-3 over bytes 0-18)
#[test]
fn test_cid_siphash_protection_verification() {
    let cid = ConnectionId::generate(0, 42).expect("CID generation should succeed");
    
    assert!(
        ConnectionId::verify_protection(&cid),
        "Freshly generated CID should pass protection verification"
    );
}

/// Test CID protection rejects corrupted CIDs
#[test]
fn test_cid_siphash_protection_rejects_corruption() {
    let mut cid = ConnectionId::generate(0, 42).expect("CID generation should succeed");
    
    // Corrupt a byte in the middle
    cid[10] ^= 0xFF;
    
    assert!(
        !ConnectionId::verify_protection(&cid),
        "Corrupted CID should fail protection verification"
    );
}

/// Test CID protection rejects wrong-length CIDs
#[test]
fn test_cid_siphash_protection_rejects_wrong_length() {
    let short_cid = [0u8; 19]; // Not 20 bytes
    assert!(
        !ConnectionId::verify_protection(&short_cid),
        "Wrong-length CID should fail protection verification"
    );
    
    let long_cid = [0u8; 21];
    assert!(
        !ConnectionId::verify_protection(&long_cid),
        "Wrong-length CID should fail protection verification"
    );
}

/// Test seeded CID generation is deterministic
#[test]
fn test_cid_seeded_generation_deterministic() {
    let seed = 0xDEADBEEFu32;
    let gen = 5u8;
    let worker = 42u8;
    
    let cid1 = ConnectionId::generate_with_seed(gen, worker, seed);
    let cid2 = ConnectionId::generate_with_seed(gen, worker, seed);
    
    assert_eq!(
        cid1, cid2,
        "Seeded CID generation should be deterministic"
    );
}

/// Test entropy-based CID generation
#[test]
fn test_cid_entropy_generation() {
    let entropy = [0xAAu8; 17];
    let gen = 3u8;
    let worker = 77u8;
    
    let cid = ConnectionId::generate_with_entropy(gen, worker, entropy);
    
    // Verify prefix from entropy
    assert_eq!(&cid[0..6], &entropy[0..6], "Prefix should match entropy");
    
    // Verify suffix from entropy
    assert_eq!(&cid[8..19], &entropy[6..17], "Suffix should match entropy");
    
    // Verify cookie
    let expected_cookie = Cookie::generate(gen, worker);
    let embedded_cookie = u16::from_be_bytes([cid[6], cid[7]]);
    assert_eq!(embedded_cookie, expected_cookie, "Cookie should be embedded");
    
    // Verify protection byte
    assert!(
        ConnectionId::verify_protection(&cid),
        "CID with provided entropy should pass protection"
    );
}

// ============================================================================
// Cookie Validation Tests
// ============================================================================

/// Test validate_cookie function
#[test]
fn test_cid_validate_cookie() {
    let cid = ConnectionId::generate(0, 42).expect("CID generation should succeed");
    
    assert!(
        ConnectionId::validate_cookie(&cid),
        "Valid CID should pass cookie validation"
    );
}

/// Test validate_cookie rejects corrupted cookies
#[test]
fn test_cid_validate_cookie_rejects_corruption() {
    let mut cid = ConnectionId::generate(0, 42).expect("CID generation should succeed");
    
    // Corrupt the cookie bytes
    cid[6] ^= 0xFF;
    
    assert!(
        !ConnectionId::validate_cookie(&cid),
        "Corrupted cookie should fail validation"
    );
}

// ============================================================================
// RoutingConnectionIdGenerator Tests
// ============================================================================

#[test]
fn test_routing_cid_generator_basic() {
    use super::cid_generator::RoutingConnectionIdGenerator;
    use quicd_quic::cid::ConnectionIdGenerator;
    
    let generator = RoutingConnectionIdGenerator::new(5, 0);
    
    // Generate a CID using the trait interface
    let cid = generator.generate(0); // requested_len is ignored
    
    // Verify it's the expected length
    assert_eq!(cid.len(), 20, "Generated CID should be 20 bytes");
    
    // Verify worker index is embedded
    let cid_bytes = cid.as_bytes();
    let worker = ConnectionId::get_worker_idx(cid_bytes);
    assert_eq!(worker, Some(5), "Worker index should be embedded in CID");
}

#[test]
fn test_routing_cid_generator_generation_update() {
    use super::cid_generator::RoutingConnectionIdGenerator;
    
    let generator = RoutingConnectionIdGenerator::new(10, 0);
    assert_eq!(generator.generation(), 0);
    
    generator.set_generation(15);
    assert_eq!(generator.generation(), 15);
    
    // Verify CIDs now use new generation
    use quicd_quic::cid::ConnectionIdGenerator;
    let cid = generator.generate(0);
    let gen = ConnectionId::get_generation(cid.as_bytes());
    assert_eq!(gen, Some(15), "CID should use updated generation");
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

/// Test maximum generation value (31)
#[test]
fn test_cookie_max_generation() {
    let cookie = Cookie::generate(31, 0);
    assert!(Cookie::validate(cookie), "Max generation should be valid");
    assert_eq!(Cookie::get_generation(cookie), 31);
}

/// Test maximum worker index (255)
#[test]
fn test_cookie_max_worker() {
    let cookie = Cookie::generate(0, 255);
    assert!(Cookie::validate(cookie), "Max worker should be valid");
    assert_eq!(Cookie::get_worker_idx(cookie), 255);
}

/// Test combined maximum values
#[test]
fn test_cookie_max_combined() {
    let cookie = Cookie::generate(31, 255);
    assert!(Cookie::validate(cookie), "Max gen+worker should be valid");
    assert_eq!(Cookie::get_generation(cookie), 31);
    assert_eq!(Cookie::get_worker_idx(cookie), 255);
}

/// Test zero values
#[test]
fn test_cookie_zero_values() {
    let cookie = Cookie::generate(0, 0);
    assert!(Cookie::validate(cookie), "Zero values should be valid");
    assert_eq!(Cookie::get_generation(cookie), 0);
    assert_eq!(Cookie::get_worker_idx(cookie), 0);
    // Checksum should be 0 too
    assert_eq!(cookie & 0x7, 0);
}

// ============================================================================
// Stress Tests
// ============================================================================

/// Stress test: generate many CIDs and verify all are valid
#[test]
fn test_cid_generation_stress() {
    const ITERATIONS: usize = 1000;
    
    for i in 0..ITERATIONS {
        let gen = (i % 32) as u8;
        let worker = (i % 256) as u8;
        
        let cid = ConnectionId::generate(gen, worker)
            .expect("CID generation should succeed");
        
        assert!(
            ConnectionId::verify_protection(&cid),
            "CID {} should pass protection",
            i
        );
        assert!(
            ConnectionId::validate_cookie(&cid),
            "CID {} should pass cookie validation",
            i
        );
        assert_eq!(
            ConnectionId::get_generation(&cid),
            Some(gen),
            "CID {} generation mismatch",
            i
        );
        assert_eq!(
            ConnectionId::get_worker_idx(&cid),
            Some(worker),
            "CID {} worker mismatch",
            i
        );
    }
}

/// Test cookie validation for all possible cookie values
#[test]
fn test_cookie_validation_exhaustive() {
    let mut valid_count = 0u32;
    let mut invalid_count = 0u32;
    
    for cookie in 0u16..=u16::MAX {
        if Cookie::validate(cookie) {
            valid_count += 1;
            
            // Verify roundtrip
            let gen = Cookie::get_generation(cookie);
            let worker = Cookie::get_worker_idx(cookie);
            let regenerated = Cookie::generate(gen, worker);
            assert_eq!(
                cookie, regenerated,
                "Cookie roundtrip failed: {} != {}",
                cookie, regenerated
            );
        } else {
            invalid_count += 1;
        }
    }
    
    // With 32 generations × 256 workers = 8192 valid cookies
    assert_eq!(valid_count, 32 * 256, "Should have exactly 8192 valid cookies");
    assert_eq!(
        invalid_count,
        65536 - 8192,
        "Should have 57344 invalid cookies"
    );
}

// ============================================================================
// CRITICAL: eBPF Compatibility Tests
// ============================================================================

/// CRITICAL BUG TEST: Verify eBPF DCID length assumption
/// 
/// The eBPF code in ebpf/src/main.rs expects 8-byte DCIDs but router.rs
/// generates 20-byte CIDs. This test documents the mismatch.
#[test]
fn test_ebpf_dcid_length_mismatch_documentation() {
    // The router uses 20-byte CIDs
    assert_eq!(CID_LENGTH, 20, "Router CID length is 20 bytes");
    
    // The eBPF code expects 8-byte DCIDs (see ebpf/src/main.rs line 82)
    // This is a configuration/integration issue that needs to be addressed
    // by ensuring the eBPF code extracts cookies from 20-byte CIDs correctly.
    
    // For now, we document that the cookie is at bytes 6-7 regardless of CID length
    let cid = ConnectionId::generate_with_seed(0, 42, 0x12345678);
    let cookie = u16::from_be_bytes([cid[6], cid[7]]);
    
    // The eBPF short header extraction assumes:
    // - 1 byte header
    // - Cookie at offset 1 + 6 = 7 (bytes 6-7 of DCID starting at offset 1)
    // This only works if DCID length is at least 8 bytes
    
    // The eBPF long header extraction checks dcid_len == 8, which will FAIL
    // for 20-byte CIDs!
    
    // This test passes but documents the integration issue
    assert!(Cookie::validate(cookie), "Cookie should be valid");
}

/// Test that cookie position (bytes 6-7) is accessible in short headers
#[test]
fn test_cookie_accessible_in_short_header() {
    // Short header: 1 byte flags + DCID (variable length, no explicit length)
    // For cookie at bytes 6-7 of DCID, we need DCID length >= 8
    
    let cid = ConnectionId::generate_with_seed(0, 42, 0x12345678);
    
    // Simulate short header packet
    let mut packet = vec![0x40]; // Short header flag (bit 7 = 0)
    packet.extend_from_slice(&cid);
    
    // Cookie should be at offset 1 + 6 = 7
    let cookie = u16::from_be_bytes([packet[7], packet[8]]);
    
    assert!(Cookie::validate(cookie), "Cookie from short header should be valid");
    assert_eq!(
        Cookie::get_worker_idx(cookie),
        42,
        "Worker should be extractable"
    );
}

/// Test that cookie position is accessible in long headers
#[test]
fn test_cookie_accessible_in_long_header() {
    // Long header: 1 byte flags + 4 bytes version + 1 byte DCID len + DCID + ...
    // Cookie at bytes 6-7 of DCID = offset 6 + 6 = 12
    
    let cid = ConnectionId::generate_with_seed(0, 42, 0x12345678);
    
    // Simulate long header packet
    let mut packet = vec![
        0xC0, // Long header flag (bit 7 = 1)
        0x00, 0x00, 0x00, 0x01, // Version 1
        20,   // DCID length = 20 bytes
    ];
    packet.extend_from_slice(&cid);
    
    // Cookie should be at offset 6 + 6 = 12
    let cookie = u16::from_be_bytes([packet[12], packet[13]]);
    
    assert!(Cookie::validate(cookie), "Cookie from long header should be valid");
    assert_eq!(
        Cookie::get_worker_idx(cookie),
        42,
        "Worker should be extractable"
    );
}
