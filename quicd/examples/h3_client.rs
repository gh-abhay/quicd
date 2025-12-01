//! Simple HTTP/3 client example for testing the quicd server.
//!
//! This client demonstrates:
//! - Connecting to a QUIC server with HTTP/3
//! - Performing TLS handshake with ALPN negotiation
//! - Sending a simple GET request
//! - Receiving and displaying the response
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
//! cargo run --example h3_client
//! ```
//!
//! ## Expected Output
//!
//! ```text
//! Connected to 127.0.0.1:443
//! Initiating QUIC handshake...
//! ✓ Handshake completed!
//!   ALPN: h3
//!
//! Sending HTTP/3 request...
//! ✓ Sent GET / request
//!
//! Waiting for response...
//! ✓ Received response
//! ```

use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "127.0.0.1:443";

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
            println!("  ALPN: {}", String::from_utf8_lossy(alpn));
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

    // Send HTTP/3 control streams with stream type markers
    const CONTROL_STREAM_TYPE: &[u8] = &[0x00]; // Control stream type = 0x00
    const QPACK_ENCODER_TYPE: &[u8] = &[0x02]; // QPACK encoder stream type = 0x02
    const QPACK_DECODER_TYPE: &[u8] = &[0x03]; // QPACK decoder stream type = 0x03
    const SETTINGS_FRAME: &[u8] = &[0x04, 0x00]; // SETTINGS frame: type 0x04, length 0
    
    // Control stream: type marker + SETTINGS frame
    let mut control_data = Vec::new();
    control_data.extend_from_slice(CONTROL_STREAM_TYPE);
    control_data.extend_from_slice(SETTINGS_FRAME);
    conn.stream_send(2, &control_data, false)?; // Control stream (client uni)
    
    // QPACK encoder stream: type marker only
    conn.stream_send(6, QPACK_ENCODER_TYPE, false)?; // QPACK encoder stream (client uni)
    
    // QPACK decoder stream: type marker only
    conn.stream_send(10, QPACK_DECODER_TYPE, false)?; // QPACK decoder stream (client uni)

    // Send HTTP/3 GET request on stream 0
    println!("\nSending HTTP/3 request...");
    // QPACK encoded headers with required prefix
    // Format: Required Insert Count (varint) | Sign bit (1) + Delta Base (varint) | Header fields
    let mut headers_qpack = vec![
        0x00, 0x00, // Required Insert Count = 0, Delta Base = 0
        // Indexed Field Line with Static Reference
        // Pattern: 1T (T=1 for static), followed by index (varint with 6-bit prefix)
        0xd1,       // 11 010001 = static ref, index 17 (:method GET)
        0xd7,       // 11 010111 = static ref, index 23 (:scheme https)
        0xc1,       // 11 000001 = static ref, index 1 (:path /)
        // Literal Field Line with Name Reference (for :authority with custom value)
        // Pattern: 01NT (N=0 no huffman, T=1 static), name index, value length, value
        0x50,       // 01 01 0000 = literal with static name ref, index 0 (:authority)
        0x09,       // value length = 9
        b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't'
    ];
    
    let mut headers_frame = vec![0x01]; // HEADERS frame type
    // Length as varint
    headers_frame.push(headers_qpack.len() as u8);
    headers_frame.extend_from_slice(&headers_qpack);
    conn.stream_send(0, &headers_frame, true)?; // Send headers and fin
    println!("✓ Sent GET / request");

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
    println!("\nWaiting for response...");
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
                        println!("✓ Received {} bytes on stream {}", read, stream_id);
                        // Simple check: if contains "200", assume success
                        let data = &response[..read];
                        if data.windows(3).any(|w| w == b"200") {
                            println!("✓ HTTP/3 response indicates success");
                        } else {
                            println!("Response data: {:?}", String::from_utf8_lossy(data));
                        }
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
