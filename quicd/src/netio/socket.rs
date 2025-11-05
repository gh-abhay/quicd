//! UDP socket creation with SO_REUSEPORT for io_uring.
//!
//! This module provides socket creation and configuration optimized for:
//! - Multi-worker binding with SO_REUSEPORT (kernel load distribution)
//! - Large kernel buffers for high-throughput UDP
//! - UDP GSO (Generic Segmentation Offload) for batch sending
//! - UDP GRO (Generic Receive Offload) for batch receiving
//! - io_uring compatibility
//! - Future integration with Quiche's datagram-socket

use crate::netio::config::NetIoConfig;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket as Socket2, Type};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

// UDP GSO/GRO socket options (Linux-specific)
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Will be used when GSO send batching is implemented
const UDP_SEGMENT: libc::c_int = 103; // UDP_SEGMENT for GSO

#[cfg(target_os = "linux")]
const UDP_GRO: libc::c_int = 104; // UDP_GRO for receive offload

/// GSO (Generic Segmentation Offload) segment size.
///
/// This is the maximum size of each segment when using UDP_SEGMENT.
/// Should match the path MTU for optimal performance.
///
/// For QUIC over UDP:
/// - IPv4: Typically 1472 bytes (1500 MTU - 20 IP - 8 UDP)
/// - IPv6: Typically 1452 bytes (1500 MTU - 40 IP - 8 UDP)
///
/// Using 1280 (IPv6 minimum MTU) ensures compatibility across all paths.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Will be used when GSO send batching is implemented
pub const GSO_SEGMENT_SIZE: u16 = 1280;

/// Create and configure a UDP socket for use with io_uring.
///
/// This function:
/// 1. Creates a UDP socket using socket2
/// 2. Configures SO_REUSEPORT for multi-worker binding
/// 3. Sets large kernel buffers (SO_RCVBUF/SO_SNDBUF)
/// 4. Binds to the specified address
/// 5. Returns std::net::UdpSocket ready for io_uring operations
///
/// # Arguments
///
/// * `bind_addr` - Address to bind the socket to
/// * `config` - Network I/O configuration
///
/// # Returns
///
/// A configured UdpSocket ready for io_uring operations
///
/// # SO_REUSEPORT
///
/// With SO_REUSEPORT enabled, the kernel distributes incoming UDP packets
/// across all sockets bound to the same port. This provides:
/// - Hardware-level load balancing (RSS/RPS)
/// - No user-space synchronization needed
/// - Linear scaling with number of workers
///
/// # Note
///
/// Socket is left in blocking mode initially. The io_uring operations
/// will handle async I/O without needing non-blocking mode.
pub fn create_udp_socket(bind_addr: SocketAddr, config: &NetIoConfig) -> Result<UdpSocket> {
    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    // Create socket with socket2 for fine-grained control
    let socket =
        Socket2::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("creating UDP socket")?;

    // Enable SO_REUSEADDR (standard practice for server sockets)
    socket
        .set_reuse_address(true)
        .context("setting SO_REUSEADDR")?;

    // Enable SO_REUSEPORT for multi-worker binding (critical for our architecture)
    if config.reuse_port {
        configure_reuse_port(&socket).context("setting SO_REUSEPORT")?;
    }

    // Configure large kernel buffers for high-throughput operation
    if let Some(size) = config.socket_recv_buffer_size {
        socket
            .set_recv_buffer_size(size)
            .with_context(|| format!("setting SO_RCVBUF to {}", size))?;
    }

    if let Some(size) = config.socket_send_buffer_size {
        socket
            .set_send_buffer_size(size)
            .with_context(|| format!("setting SO_SNDBUF to {}", size))?;
    }

    // For IPv6, configure v6-only based on bind address
    if let SocketAddr::V6(addr) = bind_addr {
        socket
            .set_only_v6(!addr.ip().is_unspecified())
            .context("setting IPV6_V6ONLY")?;
    }

    // Bind socket to address
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("binding UDP socket to {}", bind_addr))?;

    // Enable UDP GRO for receive offload (Linux-specific optimization)
    // This allows the kernel to coalesce multiple UDP packets into a single buffer
    if config.enable_gro {
        if let Err(e) = configure_udp_gro(&socket) {
            tracing::warn!("Failed to enable UDP GRO (not critical): {}", e);
        }
    }

    // Convert to std::net::UdpSocket
    let udp_socket: UdpSocket = socket.into();

    Ok(udp_socket)
}

/// Configure SO_REUSEPORT on supported platforms.
///
/// SO_REUSEPORT allows multiple sockets to bind to the same port and provides
/// kernel-level load distribution of incoming packets.
///
/// # Platform Support
///
/// - Linux: Full support (since kernel 3.9)
/// - BSD/macOS: Supported
/// - Windows: Not supported (gracefully ignored)
#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn configure_reuse_port(socket: &Socket2) -> std::io::Result<()> {
    use std::mem::size_of_val;

    let value: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &value as *const _ as *const libc::c_void,
            size_of_val(&value) as libc::socklen_t,
        )
    };

    if ret == -1 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // Gracefully handle if SO_REUSEPORT is not supported
            Some(libc::ENOPROTOOPT) | Some(libc::EINVAL) => {
                tracing::warn!("SO_REUSEPORT not supported on this platform");
                Ok(())
            }
            _ => Err(err),
        }
    } else {
        Ok(())
    }
}

/// Stub for platforms that don't support SO_REUSEPORT
#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
)))]
fn configure_reuse_port(_socket: &Socket2) -> std::io::Result<()> {
    tracing::warn!("SO_REUSEPORT not available on this platform");
    Ok(())
}

/// Configure UDP GRO (Generic Receive Offload) on Linux.
///
/// UDP GRO allows the kernel to coalesce multiple incoming UDP packets into a
/// single large buffer before passing them to userspace. This dramatically reduces
/// per-packet overhead at high packet rates.
///
/// # Benefits
///
/// - **Throughput**: 2-3x improvement in receive throughput
/// - **CPU**: Reduces per-packet processing overhead
/// - **Latency**: Lower variance due to batch processing
///
/// # Requirements
///
/// - Linux kernel 5.0+
/// - GRO-capable NIC driver
///
/// # Usage in Industry
///
/// - Cloudflare: Uses GRO for QUIC servers handling millions of connections
/// - Google: QUIC implementation uses GRO for high-throughput scenarios
/// - Discord: Voice/video servers leverage GRO for UDP optimization
#[cfg(target_os = "linux")]
fn configure_udp_gro(socket: &Socket2) -> std::io::Result<()> {
    use std::mem::size_of_val;

    let value: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRO,
            &value as *const _ as *const libc::c_void,
            size_of_val(&value) as libc::socklen_t,
        )
    };

    if ret == -1 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // Gracefully handle if UDP_GRO is not supported (kernel < 5.0)
            Some(libc::ENOPROTOOPT) | Some(libc::EINVAL) => {
                tracing::debug!("UDP_GRO not supported on this kernel (requires Linux 5.0+)");
                Ok(())
            }
            _ => Err(err),
        }
    } else {
        tracing::info!("UDP GRO enabled for batch packet receiving");
        Ok(())
    }
}

/// Stub for non-Linux platforms
#[cfg(not(target_os = "linux"))]
fn configure_udp_gro(_socket: &Socket2) -> std::io::Result<()> {
    tracing::debug!("UDP GRO not available on this platform (Linux-only feature)");
    Ok(())
}

/// Get the maximum GSO segment size supported by the socket.
///
/// This is used to determine how many packets can be batched in a single sendmsg call.
/// Typical values are 1280-1500 bytes (standard MTU sizes).
///
/// # Returns
///
/// Maximum segment size in bytes, or None if GSO is not supported.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Will be used when GSO send batching is implemented
pub fn get_max_gso_segment_size(socket_fd: i32) -> Option<usize> {
    // Query the socket for max GSO segment size
    // For UDP, this is typically limited by the interface MTU
    // Most NICs support up to 64KB of GSO data (about 45 packets @ 1500 bytes each)

    // For now, use a conservative default based on typical MTU
    // This can be enhanced with actual socket queries if needed
    const DEFAULT_MAX_GSO_SIZE: usize = 65536; // 64 KB
    const DEFAULT_SEGMENT_SIZE: usize = 1280; // IPv6 min MTU

    // Conservative: allow batching up to 48 packets (64KB / 1280 bytes)
    // This works with most modern NICs
    let _ = socket_fd; // Suppress unused warning
    Some(DEFAULT_MAX_GSO_SIZE)
}

/// Stub for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn get_max_gso_segment_size(_socket_fd: i32) -> Option<usize> {
    None
}
