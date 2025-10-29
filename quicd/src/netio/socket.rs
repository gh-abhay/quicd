use crate::netio::config::NetIoConfig;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, UdpSocket};

pub fn bind_udp_socket(bind_addr: SocketAddr, config: &NetIoConfig) -> Result<UdpSocket> {
    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("creating UDP socket")?;

    socket
        .set_reuse_address(true)
        .context("setting SO_REUSEADDR")?;

    if config.reuse_port {
        configure_reuse_port(&socket).context("setting SO_REUSEPORT")?;
    }

    if let Some(size) = config.socket_recv_buffer_size {
        socket
            .set_recv_buffer_size(size)
            .context("setting SO_RCVBUF")?;
    }

    if let Some(size) = config.socket_send_buffer_size {
        socket
            .set_send_buffer_size(size)
            .context("setting SO_SNDBUF")?;
    }

    if let SocketAddr::V6(addr) = bind_addr {
        socket
            .set_only_v6(!addr.ip().is_unspecified())
            .context("setting IPV6_V6ONLY")?;
    }

    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("binding UDP socket to {bind_addr}"))?;

    socket
        .set_nonblocking(true)
        .context("setting non-blocking mode")?;

    Ok(socket.into())
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn configure_reuse_port(socket: &Socket) -> std::io::Result<()> {
    use std::mem::size_of_val;
    use std::os::fd::AsRawFd;

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
            Some(libc::ENOPROTOOPT) | Some(libc::EINVAL) => Ok(()),
            _ => Err(err),
        }
    } else {
        Ok(())
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
)))]
fn configure_reuse_port(_socket: &Socket) -> std::io::Result<()> {
    Ok(())
}
