//! Simple QUIC client example for testing the quicd server.
//!
//! This client demonstrates:
//! - Connecting to a QUIC server
//! - Performing TLS handshake with ALPN negotiation
//! - Opening a bidirectional stream
//! - Sending data and receiving echo response
//!
//! ## Usage
//!
//! Start the quicd server first:
//! ```bash
//! cargo run --release
//! ```
//!
//! Then run this client:
//! ```bash
//! cargo run --example simple_client
//! ```
//!
//! ## Expected Output
//!
//! ```text
//! Connected to 127.0.0.1:8080
//! Initiating QUIC handshake...
//! ✓ Handshake completed!
//!   ALPN: h3
//!
//! Opening bidirectional stream...
//! ✓ Sent 23 bytes on stream 0
//!
//! Waiting for echo response...
//! ✓ Received echo: "Hello from test client!"
//! ✓ Stream closed gracefully
//! ```

use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "127.0.0.1:8080";

    // Create a UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server_addr)?;

    println!("Connected to {}", server_addr);

    // Create QUIC config
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(&[b"h3"])?;
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    let rng = ring::rand::SystemRandom::new();
    ring::rand::SecureRandom::fill(&rng, &mut scid)
        .map_err(|_| "Failed to generate random SCID")?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr()?;
    let peer_addr = socket.peer_addr()?;

    // Create a new connection
    let mut conn = quiche::connect(None, &scid, local_addr, peer_addr, &mut config)?;

    println!("Initiating QUIC handshake...");

    let mut out = [0; 1350];
    let (write, _) = conn.send(&mut out)?;
    socket.send(&out[..write])?;

    let mut buf = [0; 65535];

    // Handshake loop
    loop {
        let len = match socket.recv(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("recv() failed: {}", e);
                break;
            }
        };

        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from: peer_addr,
        };

        match conn.recv(&mut buf[..len], recv_info) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("recv failed: {:?}", e);
                break;
            }
        }

        if conn.is_established() {
            println!("✓ Handshake completed!");
            let alpn = conn.application_proto();
            println!(
                "  ALPN: {}",
                String::from_utf8_lossy(alpn)
            );
            break;
        }

        loop {
            let (write, _) = match conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    eprintln!("send failed: {:?}", e);
                    return Err(e.into());
                }
            };

            socket.send(&out[..write])?;
        }
    }

    if !conn.is_established() {
        eprintln!("✗ Handshake failed - connection not established");
        return Ok(());
    }

    // Open a bidirectional stream and send data
    println!("\nOpening bidirectional stream...");
    let stream_id = conn.stream_send(0, b"Hello from test client!", true)?;
    println!("✓ Sent 23 bytes on stream {}", stream_id);

    // Send the data
    loop {
        let (write, _) = match conn.send(&mut out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => break,
            Err(e) => {
                eprintln!("send failed: {:?}", e);
                return Err(e.into());
            }
        };

        socket.send(&out[..write])?;
    }

    // Receive response
    println!("\nWaiting for echo response...");
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    loop {
        let len = match socket.recv(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                eprintln!("✗ Timeout waiting for response (5s)");
                break;
            }
            Err(e) => {
                eprintln!("recv() failed: {}", e);
                break;
            }
        };

        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from: peer_addr,
        };

        match conn.recv(&mut buf[..len], recv_info) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("recv failed: {:?}", e);
                break;
            }
        }

        // Check for readable streams
        for stream_id in conn.readable() {
            let mut response = vec![0; 1000];
            match conn.stream_recv(stream_id, &mut response) {
                Ok((read, fin)) => {
                    if read > 0 {
                        println!(
                            "✓ Received echo: {:?}",
                            String::from_utf8_lossy(&response[..read])
                        );
                    }
                    if fin {
                        println!("✓ Stream closed gracefully");
                        return Ok(());
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    eprintln!("✗ Stream recv error: {:?}", e);
                    break;
                }
            }
        }

        loop {
            let (write, _) = match conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    eprintln!("send failed: {:?}", e);
                    return Err(e.into());
                }
            };

            socket.send(&out[..write])?;
        }
    }

    Ok(())
}
