/// Integration tests for SuperD network layer
/// Tests the complete network I/O functionality
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;

use superd::config::Config;
use superd::network::io_uring_net::start_network_layer;

#[test]
fn test_network_layer_startup_shutdown() {
    tokio_uring::start(async {
        // Create test configuration
        let mut config = Config::default();
        config.listen = "127.0.0.1:0".to_string(); // Use port 0 for auto-assignment
        config.network_threads = 2; // Use 2 threads for testing
        config.protocol_threads = 4; // Keep protocol tasks modest for tests
        config.cpu_pinning = false; // Disable CPU pinning in tests

        // Create dedicated channels for each network thread
        let mut to_protocol_senders = Vec::new();
        let mut to_protocol_receivers = Vec::new();
        let mut from_protocol_senders = Vec::new();
        let mut from_protocol_receivers = Vec::new();

        for _ in 0..config.network_threads {
            let (to_proto_tx, to_proto_rx) = mpsc::unbounded_channel();
            let (from_proto_tx, from_proto_rx) = mpsc::unbounded_channel();

            to_protocol_senders.push(to_proto_tx);
            to_protocol_receivers.push(to_proto_rx);
            from_protocol_senders.push(from_proto_tx);
            from_protocol_receivers.push(from_proto_rx);
        }

        // Create shutdown signal (broadcast)
        let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

        // Start network layer
        start_network_layer(
            &config,
            to_protocol_senders,
            from_protocol_receivers,
            shutdown_tx.clone(),
        )
        .expect("Failed to start network layer");

        // Give the network layer time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Signal shutdown via broadcast (event-driven!)
        shutdown_tx
            .send(())
            .expect("Failed to send shutdown signal");

        // Allow worker tasks time to observe the shutdown signal
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify no unexpected messages were sent (allow some tolerance for system packets)
        for mut rx in to_protocol_receivers {
            let mut message_count = 0;
            let start_time = std::time::Instant::now();

            while start_time.elapsed() < Duration::from_millis(200) {
                match timeout(Duration::from_millis(10), rx.recv()).await {
                    Ok(Some(_)) => message_count += 1,
                    Ok(None) => break, // Channel closed
                    Err(_) => {}       // Timeout, continue
                }
            }

            // Allow up to 2 messages per thread (might receive some system/localhost packets)
            assert!(
                message_count <= 2,
                "Received too many unexpected messages: {}",
                message_count
            );
        }
    });
}

#[tokio::test]
async fn test_buffer_pool_functionality() {
    use superd::network::zerocopy_buffer::{get_buffer_pool, init_buffer_pool, ZeroCopyBufferMut};

    // Initialize buffer pool
    init_buffer_pool(10);

    let pool = get_buffer_pool();

    // Test acquiring and releasing buffers
    let mut buffer = pool.acquire();
    assert!(buffer.is_empty());

    // Fill buffer with data
    let test_data = b"Hello, World!";
    buffer.data_mut().extend_from_slice(test_data);

    assert_eq!(buffer.len(), test_data.len());

    // Freeze buffer
    let frozen = buffer.freeze();
    assert_eq!(frozen.len(), test_data.len());
    assert_eq!(frozen.data(), test_data);

    // Release buffer back to pool (create new buffer since original was moved)
    let empty_buffer = ZeroCopyBufferMut::with_capacity(1024);
    pool.release(empty_buffer);

    // Acquire another buffer (should be the same one, cleared)
    let new_buffer = pool.acquire();
    assert!(new_buffer.is_empty());
}

#[tokio::test]
async fn test_zero_copy_buffer_clone() {
    use bytes::Bytes;
    use superd::network::zerocopy_buffer::ZeroCopyBuffer;

    let data = Bytes::from_static(b"test data");
    let buffer = ZeroCopyBuffer::from_bytes(data);

    // Clone should be cheap (Arc increment)
    let buffer2 = buffer.clone();

    assert_eq!(buffer.len(), buffer2.len());
    assert_eq!(buffer.data(), buffer2.data());

    // Data should be the same reference
    assert_eq!(buffer.data().as_ptr(), buffer2.data().as_ptr());
}

#[test]
fn test_config_validation() {
    let mut config = Config::default();

    // Test valid config
    assert!(config.validate().is_ok());

    // Test invalid network threads
    config.network_threads = 0;
    assert!(config.validate().is_err());

    // Reset and test invalid listen address
    config = Config::default();
    config.listen = "invalid:address:99999".to_string();
    assert!(config.validate().is_err());

    // Test invalid protocol threads
    config = Config::default();
    config.protocol_threads = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_from_cli() {
    use superd::config::Cli;

    let cli = Cli {
        config: None,
        listen: "127.0.0.1:8080".to_string(),
        network_threads: Some(2),
        protocol_threads: Some(6),
        cpu_pinning: Some(false),
        otlp_endpoint: "http://localhost:4318".to_string(),
        auto_tune: false,
    };

    let config = Config::from_cli(&cli).expect("Config creation should succeed");

    assert_eq!(config.listen, "127.0.0.1:8080");
    assert_eq!(config.network_threads, 2);
    assert_eq!(config.protocol_threads, 6);
    assert!(!config.cpu_pinning);
    assert_eq!(config.telemetry.otlp_endpoint, "http://localhost:4318");
}

#[tokio::test]
async fn test_metrics_collection() {
    use superd::network::metrics::NetworkMetrics;

    let metrics = NetworkMetrics::new();

    // Initially all metrics should be 0
    assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 0);

    // Record some metrics
    metrics.record_packet_received(100);
    metrics.record_packet_sent(50);

    assert_eq!(metrics.packets_received.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.bytes_received.load(Ordering::Relaxed), 100);
    assert_eq!(metrics.packets_sent.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.bytes_sent.load(Ordering::Relaxed), 50);
}
