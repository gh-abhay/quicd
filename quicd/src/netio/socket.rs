//! UDP socket creation with SO_REUSEPORT for io_uring.
//!
//! This module provides socket creation and configuration optimized for:
//! - Multi-worker binding with SO_REUSEPORT (kernel load distribution)
//! - Large kernel buffers for high-throughput UDP
//! - io_uring compatibility
//! - Future integration with Quiche's datagram-socket

use crate::netio::config::NetIoConfig;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket as Socket2, Type};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

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
