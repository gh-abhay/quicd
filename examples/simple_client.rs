//! Simple QUIC client for testing SuperD server
//!
//! This example demonstrates basic connection to the SuperD server
//! and sends a simple request.

use std::net::SocketAddr;
use std::time::Duration;

fn main() {
    // Configure client
    let server_addr = "127.0.0.1:4433".parse::<SocketAddr>().unwrap();

    println!("Connecting to SuperD server at {}", server_addr);

    // Create QUIC configuration
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // Set application protocols (must match server)
    config.set_application_protos(&[b"superd/0.1"]).unwrap();

    // Disable certificate verification for self-signed certs
    config.verify_peer(false);

    // Set timeouts and limits
    config.set_max_idle_timeout(5000);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);

    // Generate random connection ID
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create socket
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(server_addr).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let local_addr = socket.local_addr().unwrap();
    println!("Local address: {}", local_addr);

    // Create QUIC connection
    let mut conn = quiche::connect(None, &scid, local_addr, server_addr, &mut config).unwrap();

    println!("Initial connection created, sending handshake...");

    // Buffer for sending and receiving
    let mut out = [0u8; 65535];
    let mut buf = [0u8; 65535];

    // Main connection loop
    let mut connected = false;
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > Duration::from_secs(10) {
            eprintln!("Connection timeout");
            break;
        }

        // Send pending packets
        loop {
            let (write, _send_info) = match conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    eprintln!("Send failed: {:?}", e);
                    return;
                }
            };

            match socket.send(&out[..write]) {
                Ok(_) => {
                    println!("Sent {} bytes", write);
                }
                Err(e) => {
                    eprintln!("Socket send failed: {:?}", e);
                    return;
                }
            }
        }

        // Check if established
        if conn.is_established() && !connected {
            connected = true;
            println!("✓ Connection established!");
            println!(
                "  ALPN: {:?}",
                std::str::from_utf8(conn.application_proto()).unwrap()
            );

            // Open a stream and send data
            match conn.stream_send(0, b"Hello SuperD!", true) {
                Ok(_) => {
                    println!("✓ Sent data on stream 0");
                }
                Err(e) => {
                    eprintln!("Failed to send on stream: {:?}", e);
                    return;
                }
            };

            // Continue to send the data
            continue;
        }

        // Receive packets
        match socket.recv(&mut buf) {
            Ok(len) => {
                println!("Received {} bytes", len);

                let recv_info = quiche::RecvInfo {
                    from: server_addr,
                    to: local_addr,
                };

                match conn.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Receive processing failed: {:?}", e);
                        continue;
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout, check connection timeout
                conn.on_timeout();
            }
            Err(e) => {
                eprintln!("Socket receive failed: {:?}", e);
                break;
            }
        }

        // Check for incoming stream data
        if conn.is_established() {
            for stream_id in conn.readable() {
                let mut stream_buf = [0u8; 65535];
                match conn.stream_recv(stream_id, &mut stream_buf) {
                    Ok((read, fin)) => {
                        println!(
                            "✓ Received {} bytes on stream {}, fin={}",
                            read, stream_id, fin
                        );
                        if read > 0 {
                            println!("  Data: {:?}", std::str::from_utf8(&stream_buf[..read]));
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        eprintln!("Stream read failed: {:?}", e);
                        break;
                    }
                }
            }
        }

        // Check if connection is closed
        if conn.is_closed() {
            println!("Connection closed");
            if let Some(err) = conn.peer_error() {
                println!("  Peer error: {:?}", err);
            }
            break;
        }
    }

    println!("\nClient exiting");
}
