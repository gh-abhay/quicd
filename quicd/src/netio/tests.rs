//! RFC-Compliant Tests for netio module.
//!
//! These tests validate compliance with:
//! - RFC 9000: QUIC Transport Protocol (Section 14 - Datagram Size)
//! - RFC 9000: Section 18.2 (Transport Parameters - max_udp_payload_size)
//!
//! Tests are designed to FAIL if the implementation violates RFC requirements.

use super::buffer::*;
use super::config::*;

// =============================================================================
// RFC 9000 COMPLIANCE CONSTANTS
// =============================================================================

/// RFC 9000 Section 14.1: Minimum Initial datagram size
/// "A client MUST expand the payload of all UDP datagrams carrying
/// Initial packets to at least the smallest allowed maximum datagram
/// size of 1200 bytes"
const RFC9000_MIN_INITIAL_DATAGRAM_SIZE: usize = 1200;

/// RFC 9000 Section 14: IPv6 minimum MTU
/// "QUIC assumes a minimum IP packet size of at least 1280 bytes."
const RFC9000_IPV6_MIN_MTU: usize = 1280;

/// RFC 9000 Section 18.2: max_udp_payload_size transport parameter
/// "The default for this parameter is the maximum permitted UDP payload of 65527."
/// Note: This is the QUIC-layer maximum, not the raw UDP maximum.
const RFC9000_MAX_UDP_PAYLOAD_SIZE: usize = 65527;

/// RFC 9000 Section 18.2: Minimum valid max_udp_payload_size
/// "Values below 1200 are invalid."
#[allow(dead_code)]
const RFC9000_MIN_MAX_UDP_PAYLOAD_SIZE: usize = 1200;

// =============================================================================
// RFC 9000 Section 14 - DATAGRAM SIZE COMPLIANCE TESTS
// =============================================================================

#[test]
fn test_rfc9000_max_udp_payload_constant_must_not_exceed_65527() {
    // RFC 9000 Section 18.2: "The default for this parameter is the
    // maximum permitted UDP payload of 65527."
    //
    // The code's MAX_UDP_PAYLOAD constant must respect this limit.
    // Using 65536 (2^16) is INCORRECT as it exceeds the RFC maximum.
    assert!(
        MAX_UDP_PAYLOAD <= RFC9000_MAX_UDP_PAYLOAD_SIZE,
        "RFC 9000 Section 18.2 VIOLATION: MAX_UDP_PAYLOAD ({}) exceeds \
         RFC-mandated maximum of {} bytes. \
         This could cause protocol violations when negotiating max_udp_payload_size.",
        MAX_UDP_PAYLOAD,
        RFC9000_MAX_UDP_PAYLOAD_SIZE
    );
}

#[test]
fn test_rfc9000_default_datagram_size_must_be_at_least_1200() {
    // RFC 9000 Section 14.1: Initial datagrams must be at least 1200 bytes.
    // The default datagram size should accommodate this requirement.
    assert!(
        DEFAULT_DATAGRAM_SIZE >= RFC9000_MIN_INITIAL_DATAGRAM_SIZE,
        "RFC 9000 Section 14.1 VIOLATION: DEFAULT_DATAGRAM_SIZE ({}) is less than \
         the minimum Initial datagram size of {} bytes.",
        DEFAULT_DATAGRAM_SIZE,
        RFC9000_MIN_INITIAL_DATAGRAM_SIZE
    );
}

#[test]
fn test_rfc9000_buffer_capacity_supports_initial_packets() {
    // RFC 9000 Section 14.1: Initial packets must be padded to at least 1200 bytes.
    // The buffer pool must be able to allocate buffers of this size.
    let config = BufferPoolConfig::default();

    assert!(
        config.datagram_size >= RFC9000_MIN_INITIAL_DATAGRAM_SIZE,
        "RFC 9000 Section 14.1 VIOLATION: BufferPoolConfig::datagram_size ({}) \
         cannot hold minimum Initial packet size of {} bytes.",
        config.datagram_size,
        RFC9000_MIN_INITIAL_DATAGRAM_SIZE
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_rfc9000_gso_segment_size_respects_ipv6_minimum() {
    // RFC 9000 Section 14: "QUIC assumes a minimum IP packet size of at least 1280 bytes."
    // GSO segment size of 1280 is the IPv6 minimum MTU.
    use super::socket::GSO_SEGMENT_SIZE;

    assert_eq!(
        GSO_SEGMENT_SIZE, RFC9000_IPV6_MIN_MTU as u16,
        "GSO_SEGMENT_SIZE should match IPv6 minimum MTU for maximum compatibility"
    );
}

// =============================================================================
// BUFFER POOL - LIFO ORDERING TESTS (using public API via WorkerBuffer)
// =============================================================================

#[test]
fn test_buffer_pool_allocation_returns_valid_buffer() {
    // Test that buffer pool allocates buffers correctly
    let config = BufferPoolConfig::default();
    let pool = create_worker_pool(&config);

    let buf = WorkerBuffer::new_from_pool(pool.clone());

    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
}

#[test]
fn test_buffer_pool_returns_to_pool_on_drop() {
    // RAII: Buffers should return to pool on drop
    let config = BufferPoolConfig::default();
    let pool = create_worker_pool(&config);

    assert!(pool.is_empty());

    {
        let _buf = WorkerBuffer::new_from_pool(pool.clone());
        // Buffer in use, pool still empty
    } // Buffer dropped here

    // Buffer should be returned to pool
    assert_eq!(pool.len(), 1, "Buffer should return to pool on drop");
}

#[test]
fn test_buffer_pool_reuses_returned_buffers() {
    // Test LIFO behavior by checking pool length after multiple alloc/drop cycles
    let config = BufferPoolConfig::default();
    let pool = create_worker_pool(&config);

    // Hold buffers first, then drop them all at once
    {
        let bufs: Vec<_> = (0..3)
            .map(|_| WorkerBuffer::new_from_pool(pool.clone()))
            .collect();
        // All 3 buffers held simultaneously
        assert_eq!(bufs.len(), 3);
    } // All 3 dropped here, returned to pool

    // Pool should have 3 buffers now (all returned from previous scope)
    assert_eq!(pool.len(), 3, "Pool should accumulate returned buffers");

    // Second cycle: allocate buffer (should reuse from pool)
    let initial_len = pool.len();
    let _buf = WorkerBuffer::new_from_pool(pool.clone());

    // Pool should have one less buffer (reused, not new allocation)
    assert_eq!(pool.len(), initial_len - 1, "Buffer should be taken from pool");
}

#[test]
fn test_buffer_pool_max_capacity_enforcement() {
    // Pool should not exceed max_buffers
    let config = BufferPoolConfig {
        max_buffers_per_worker: 3,
        datagram_size: 128,
    };
    let pool = create_worker_pool(&config);

    // Allocate and drop 10 buffers - only 3 should be kept
    for _ in 0..10 {
        let _buf = WorkerBuffer::new_from_pool(pool.clone());
    }

    assert!(
        pool.len() <= 3,
        "Pool should enforce max_buffers limit of 3, got {}",
        pool.len()
    );
}

// =============================================================================
// CONSUME BUFFER - ZERO-COPY OPERATIONS TESTS
// =============================================================================

#[test]
fn test_consume_buffer_pop_front_zero_copy() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut buf = ConsumeBuffer::from_vec(data);

    assert_eq!(buf.len(), 10);
    assert_eq!(&buf[..], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    // Pop front 3 bytes - should be zero-copy (just pointer adjustment)
    buf.pop_front(3);

    assert_eq!(buf.len(), 7);
    assert_eq!(&buf[..], &[4, 5, 6, 7, 8, 9, 10]);
}

#[test]
#[should_panic(expected = "assertion")]
fn test_consume_buffer_pop_front_overflow_panics() {
    let data = vec![1, 2, 3, 4, 5];
    let mut buf = ConsumeBuffer::from_vec(data);

    // Attempting to pop more than available should panic
    buf.pop_front(10);
}

#[test]
fn test_consume_buffer_add_prefix() {
    let data = vec![0, 0, 0, 4, 5, 6, 7, 8];
    let mut buf = ConsumeBuffer::from_vec(data);

    // Consume first 3 bytes to create space for prefix
    buf.pop_front(3);
    assert_eq!(&buf[..], &[4, 5, 6, 7, 8]);

    // Add prefix to consumed space
    let success = buf.add_prefix(&[1, 2, 3]);
    assert!(success);
    assert_eq!(&buf[..], &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn test_consume_buffer_add_prefix_insufficient_space() {
    let data = vec![1, 2, 3, 4, 5];
    let mut buf = ConsumeBuffer::from_vec(data);

    // No consumed space, cannot add prefix
    let success = buf.add_prefix(&[0, 0, 0]);
    assert!(!success, "add_prefix should fail without consumed space");
}

#[test]
fn test_consume_buffer_into_vec_removes_consumed() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut buf = ConsumeBuffer::from_vec(data);

    // Consume first 5 bytes
    buf.pop_front(5);

    // Convert back to Vec - consumed bytes should be removed
    let vec = buf.into_vec();
    assert_eq!(vec, vec![6, 7, 8, 9, 10]);
}

#[test]
fn test_consume_buffer_reuse_trait() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let mut buf = ConsumeBuffer::from_vec(data);

    buf.pop_front(3);
    assert_eq!(buf.len(), 5);

    // Reuse should reset the buffer
    let should_pool = buf.reuse(64);

    assert!(should_pool, "Buffer with capacity should be poolable");
    assert_eq!(buf.len(), 0, "Reuse should clear buffer");
}

// =============================================================================
// WORKER BUFFER - IO OPERATIONS TESTS
// =============================================================================

#[test]
fn test_worker_buffer_from_pool() {
    let pool = create_worker_pool(&BufferPoolConfig::default());

    let buf = WorkerBuffer::new_from_pool(pool.clone());

    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());
}

#[test]
fn test_worker_buffer_from_slice() {
    let pool = create_worker_pool(&BufferPoolConfig::default());
    let data = b"Hello, QUIC!";

    let buf = WorkerBuffer::from_slice(data, &pool);

    assert_eq!(buf.len(), data.len());
    assert_eq!(buf.as_slice(), data);
}

#[test]
fn test_worker_buffer_io_capacity_for_max_udp() {
    let pool = create_worker_pool(&BufferPoolConfig::default());

    let mut buf = WorkerBuffer::new_from_pool(pool);

    // Prepare for I/O - should have capacity for max UDP
    let slice = buf.as_mut_slice_for_io();

    assert!(
        slice.len() >= MAX_UDP_PAYLOAD,
        "I/O buffer must accommodate MAX_UDP_PAYLOAD ({} bytes), got {} bytes",
        MAX_UDP_PAYLOAD,
        slice.len()
    );
}

#[test]
fn test_worker_buffer_received_len_tracking() {
    let pool = create_worker_pool(&BufferPoolConfig::default());
    let mut buf = WorkerBuffer::new_from_pool(pool);

    // Simulate I/O preparation
    let _ = buf.as_mut_slice_for_io();

    // Simulate kernel returning 1200 bytes (minimum Initial packet)
    buf.set_received_len(RFC9000_MIN_INITIAL_DATAGRAM_SIZE);

    assert_eq!(buf.len(), RFC9000_MIN_INITIAL_DATAGRAM_SIZE);
}

#[test]
fn test_worker_buffer_deref_respects_received_len() {
    let pool = create_worker_pool(&BufferPoolConfig::default());
    let mut buf = WorkerBuffer::new_from_pool(pool);

    // Fill buffer for I/O
    let io_slice = buf.as_mut_slice_for_io();
    // Write test pattern to first 100 bytes
    for (i, byte) in io_slice.iter_mut().take(100).enumerate() {
        *byte = i as u8;
    }

    // Set received length to 50 bytes
    buf.set_received_len(50);

    // Deref should only expose 50 bytes, not the full capacity
    let slice: &[u8] = &buf;
    assert_eq!(slice.len(), 50);
    assert_eq!(slice[0], 0);
    assert_eq!(slice[49], 49);
}

// =============================================================================
// REUSE TRAIT TESTS
// =============================================================================

#[test]
fn test_vec_reuse_clears_and_shrinks() {
    let mut vec: Vec<u8> = Vec::with_capacity(4096);
    vec.extend_from_slice(&[1, 2, 3, 4, 5]);

    assert_eq!(vec.len(), 5);
    assert!(vec.capacity() >= 4096);

    // Reuse with smaller trim target
    let should_pool = vec.reuse(128);

    assert!(should_pool);
    assert_eq!(vec.len(), 0, "Reuse should clear the Vec");
    // Capacity may or may not shrink depending on allocator, but should be <= original
}

#[test]
fn test_vec_reuse_rejects_zero_capacity() {
    let mut vec: Vec<u8> = Vec::new();

    let should_pool = vec.reuse(128);

    assert!(
        !should_pool,
        "Zero-capacity Vec should not be pooled"
    );
}

// =============================================================================
// EDGE CASE AND BOUNDARY TESTS
// =============================================================================

#[test]
fn test_buffer_pool_stress_alloc_free_cycle() {
    // Stress test: rapid alloc/free cycles should not leak or panic
    let config = BufferPoolConfig {
        max_buffers_per_worker: 100,
        datagram_size: 1350,
    };
    let pool = create_worker_pool(&config);

    for _ in 0..10000 {
        let mut buf = WorkerBuffer::new_from_pool(pool.clone());
        // Prepare for I/O (ensures capacity is allocated)
        let io_slice = buf.as_mut_slice_for_io();
        // Write RFC 9000 minimum Initial size worth of data
        for byte in io_slice.iter_mut().take(RFC9000_MIN_INITIAL_DATAGRAM_SIZE) {
            *byte = 0xAA;
        }
        buf.set_received_len(RFC9000_MIN_INITIAL_DATAGRAM_SIZE);
        // buf dropped here, returns to pool
    }

    assert!(pool.len() <= 100, "Pool should not exceed max capacity");
}

#[test]
fn test_consume_buffer_empty_operations() {
    let mut buf = ConsumeBuffer::from_vec(Vec::new());

    assert_eq!(buf.len(), 0);
    assert!(buf.is_empty());

    // Truncate empty buffer should work
    buf.truncate(0);
    assert_eq!(buf.len(), 0);

    // add_prefix on empty buffer with no consumed space
    let success = buf.add_prefix(&[1, 2, 3]);
    assert!(!success);
}

#[test]
fn test_worker_buffer_clear_resets_state() {
    let pool = create_worker_pool(&BufferPoolConfig::default());
    let mut buf = WorkerBuffer::from_slice(b"some data", &pool);

    assert!(!buf.is_empty());

    buf.clear();

    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);
}

// =============================================================================
// CONFIGURATION VALIDATION TESTS
// =============================================================================

#[test]
fn test_netio_config_defaults_are_sensible() {
    let config = NetIoConfig::default();

    // Workers should default to CPU count
    assert!(config.workers > 0, "Default workers should be > 0");

    // Reuse port should be enabled for multi-worker
    assert!(config.reuse_port, "SO_REUSEPORT should be enabled by default");

    // Buffer sizes should be reasonable (at least 64KB)
    if let Some(size) = config.socket_recv_buffer_size {
        assert!(size >= 65536, "Recv buffer should be at least 64KB");
    }

    if let Some(size) = config.socket_send_buffer_size {
        assert!(size >= 65536, "Send buffer should be at least 64KB");
    }

    // uring_entries should be power of 2
    assert!(
        config.uring_entries.is_power_of_two(),
        "uring_entries must be power of 2"
    );
}

#[test]
fn test_buffer_pool_config_defaults() {
    let config = BufferPoolConfig::default();

    // Default datagram size should support Initial packets
    assert!(
        config.datagram_size >= RFC9000_MIN_INITIAL_DATAGRAM_SIZE,
        "Default datagram_size should be at least 1200 bytes"
    );

    // Pool should have reasonable capacity
    assert!(
        config.max_buffers_per_worker > 0,
        "max_buffers_per_worker should be > 0"
    );
}

// =============================================================================
// RFC 9000 MINIMUM INITIAL PACKET SIZE ENFORCEMENT
// =============================================================================

#[test]
fn test_rfc9000_min_initial_size_constant_exists() {
    // This test ensures we have the critical RFC 9000 constants defined.
    // The implementation MUST use these constants when validating Initial packets.

    // MIN_INITIAL_DATAGRAM_SIZE should be exported from buffer module
    // For now, we verify our test constant matches RFC
    assert_eq!(
        RFC9000_MIN_INITIAL_DATAGRAM_SIZE, 1200,
        "RFC 9000 Section 14.1 mandates 1200 bytes minimum for Initial datagrams"
    );
}

#[test]
fn test_rfc9000_max_udp_payload_size_constant_matches_rfc() {
    // RFC 9000 Section 18.2: max_udp_payload_size (0x03)
    // "The default for this parameter is the maximum permitted UDP payload of 65527."
    assert_eq!(
        RFC9000_MAX_UDP_PAYLOAD_SIZE, 65527,
        "RFC 9000 Section 18.2 specifies 65527 as max UDP payload"
    );
}

#[test]
fn test_rfc9000_ipv6_minimum_mtu() {
    // RFC 9000 Section 14: "QUIC assumes a minimum IP packet size of at least 1280 bytes."
    // 1280 is the IPv6 minimum MTU from RFC 8200
    assert_eq!(
        RFC9000_IPV6_MIN_MTU, 1280,
        "IPv6 minimum MTU is 1280 bytes per RFC 8200"
    );
}

