//! System resource interrogation for heuristic configuration defaults.
//!
//! This module provides functions to query the host system's hardware and OS
//! resources, enabling intelligent default configuration values that adapt
//! to the deployment environment.
//!
//! # Caching
//!
//! The `SystemResources::query()` method performs system calls and file I/O.
//! It's recommended to call it once during initialization and cache the result,
//! rather than calling it repeatedly for each configuration default.

use std::fs;

/// System resource information used for calculating optimal defaults.
///
/// This struct encapsulates all the system information needed to make
/// intelligent configuration decisions.
#[derive(Debug, Clone)]
pub struct SystemResources {
    /// Number of physical CPU cores (not hyperthreads)
    pub physical_cores: usize,
    /// Total available RAM in bytes
    pub total_memory_bytes: u64,
    /// Maximum file descriptor limit (soft limit)
    pub max_fds: u64,
    /// Maximum UDP receive buffer size allowed by OS
    pub max_udp_recv_buf: usize,
    /// Maximum UDP send buffer size allowed by OS
    pub max_udp_send_buf: usize,
    /// System page size in bytes
    pub page_size: usize,
}

impl SystemResources {
    /// Query the system for resource information.
    ///
    /// This performs various system calls and file reads to gather
    /// hardware and OS configuration data.
    pub fn query() -> Self {
        Self {
            physical_cores: get_physical_cores(),
            total_memory_bytes: get_total_memory(),
            max_fds: get_max_fds(),
            max_udp_recv_buf: get_max_udp_buffer_size(true),
            max_udp_send_buf: get_max_udp_buffer_size(false),
            page_size: get_page_size(),
        }
    }

    /// Calculate optimal worker thread count based on physical cores.
    ///
    /// Maps directly to physical cores for optimal cache locality and
    /// NUMA awareness. Hyperthreads are not counted as they don't provide
    /// significant benefit for network I/O workloads.
    pub fn optimal_worker_threads(&self) -> usize {
        self.physical_cores.max(1)
    }

    /// Calculate optimal network I/O worker count.
    ///
    /// For network I/O, we want one worker per physical core to maximize
    /// throughput and minimize context switching.
    pub fn optimal_netio_workers(&self) -> usize {
        self.physical_cores.max(1)
    }

    /// Calculate maximum concurrent connections based on available memory.
    ///
    /// Uses a conservative estimate of 64KB per connection (including QUIC,
    /// HTTP/3, and application overhead). Applies a safety factor to leave
    /// headroom for the OS and other processes.
    pub fn max_connections_from_memory(&self) -> usize {
        const BYTES_PER_CONNECTION: u64 = 64 * 1024; // 64KB estimate
        const SAFETY_FACTOR: f64 = 0.7; // Use only 70% of available RAM

        let available_bytes = (self.total_memory_bytes as f64 * SAFETY_FACTOR) as u64;
        let max_connections = available_bytes / BYTES_PER_CONNECTION;

        // Clamp to reasonable bounds
        max_connections.clamp(100, 10_000_000) as usize
    }

    /// Calculate optimal UDP buffer sizes.
    ///
    /// Requests the maximum OS-allowed buffer size for high-throughput
    /// UDP operations. Falls back to conservative defaults if the OS
    /// doesn't allow large buffers.
    pub fn optimal_udp_recv_buf(&self) -> usize {
        self.max_udp_recv_buf.max(2 * 1024 * 1024) // At least 2MB
    }

    pub fn optimal_udp_send_buf(&self) -> usize {
        self.max_udp_send_buf.max(2 * 1024 * 1024) // At least 2MB
    }

    /// Calculate optimal io_uring entries based on memory and cores.
    ///
    /// Higher values allow more in-flight operations but consume more memory.
    /// Scales with available RAM and core count.
    pub fn optimal_io_uring_entries(&self) -> u32 {
        const BASE_ENTRIES: u32 = 1024;
        const ENTRIES_PER_CORE: u32 = 512;
        const MAX_ENTRIES: u32 = 8192;

        let entries = BASE_ENTRIES + (self.physical_cores as u32 * ENTRIES_PER_CORE);
        entries.min(MAX_ENTRIES).next_power_of_two()
    }

    /// Calculate optimal buffer pool size per worker.
    ///
    /// Based on expected connection density and memory availability.
    /// Each buffer is ~1.5KB, so this calculation ensures we don't
    /// exhaust memory while providing good performance.
    pub fn optimal_buffers_per_worker(&self) -> usize {
        const BYTES_PER_BUFFER: usize = 1536; // 1.5KB average
        const MEMORY_FRACTION: f64 = 0.1; // Use 10% of RAM for buffers

        let available_bytes = (self.total_memory_bytes as f64 * MEMORY_FRACTION) as usize;
        let buffers_total = available_bytes / BYTES_PER_BUFFER;
        let buffers_per_worker = buffers_total / self.physical_cores.max(1);

        buffers_per_worker.clamp(512, 8192)
    }

    /// Calculate optimal channel capacities based on connection density.
    ///
    /// Scales channel sizes with expected load to prevent deadlocks
    /// while avoiding excessive memory usage.
    pub fn optimal_worker_egress_capacity(&self) -> usize {
        let capacity = self.max_connections_from_memory() / self.physical_cores.max(1) / 4;
        capacity.clamp(512, 8192)
    }

    pub fn optimal_connection_ingress_capacity(&self) -> usize {
        let capacity = self.max_connections_from_memory() / 100;
        capacity.clamp(64, 512)
    }

    pub fn optimal_stream_channel_capacity(&self) -> usize {
        let capacity = self.max_connections_from_memory() / 1000;
        capacity.clamp(32, 128)
    }

    /// Calculate optimal QUIC flow control windows.
    ///
    /// Generous windows for high-bandwidth networks, scaled by available memory.
    pub fn optimal_quic_recv_window(&self) -> u64 {
        const BASE_WINDOW: u64 = 10 * 1024 * 1024; // 10MB base
        const MEMORY_SCALING: f64 = 0.05; // Scale with 5% of RAM
        const MAX_WINDOW: u64 = 100 * 1024 * 1024; // 100MB

        let memory_scaled = (self.total_memory_bytes as f64 * MEMORY_SCALING) as u64;
        memory_scaled.clamp(BASE_WINDOW, MAX_WINDOW)
    }

    pub fn optimal_quic_stream_recv_window(&self) -> u64 {
        self.optimal_quic_recv_window() / 10 // 10% of connection window
    }

    /// Calculate optimal idle timeout based on connection density.
    ///
    /// More aggressive timeouts when nearing capacity to free up slots.
    /// Conservative defaults otherwise.
    pub fn optimal_idle_timeout_ms(&self) -> u64 {
        const BASE_TIMEOUT_MS: u64 = 30_000; // 30 seconds
        const AGGRESSIVE_TIMEOUT_MS: u64 = 5_000; // 5 seconds when crowded

        // If we can support > 1M connections, be more aggressive with timeouts
        if self.max_connections_from_memory() > 1_000_000 {
            AGGRESSIVE_TIMEOUT_MS
        } else {
            BASE_TIMEOUT_MS
        }
    }

    /// Calculate optimal max UDP payload size.
    ///
    /// Returns a conservative default that works on standard Ethernet.
    /// PMTUD (Path MTU Discovery) will probe for larger sizes at runtime.
    ///
    /// Conservative default: 1350 bytes
    /// - Accounts for IPv6 (40 bytes) + UDP (8 bytes) + QUIC overhead
    /// - Safe for standard MTU of 1500 bytes
    /// - Avoids fragmentation on most networks
    pub fn optimal_max_udp_payload(&self) -> usize {
        // Conservative default, PMTUD will discover optimal size
        1350
    }

    /// Validate that the system can support the calculated defaults.
    ///
    /// Performs pre-flight checks to ensure the OS configuration
    /// won't prevent the server from achieving its performance goals.
    pub fn validate_system_limits(&self) -> Result<(), Vec<String>> {
        let mut warnings = Vec::new();

        // Check file descriptor limits
        let required_fds = self.max_connections_from_memory() as u64 * 2; // Conservative estimate
        if self.max_fds < required_fds {
            warnings.push(format!(
                "File descriptor limit ({}) may be too low for target connections ({} required)",
                self.max_fds, required_fds
            ));
        }

        // Check UDP buffer sizes
        if self.max_udp_recv_buf < 1_048_576 {
            // 1MB
            warnings.push(format!(
                "UDP receive buffer limit ({}) may limit throughput",
                self.max_udp_recv_buf
            ));
        }

        if self.max_udp_send_buf < 1_048_576 {
            // 1MB
            warnings.push(format!(
                "UDP send buffer limit ({}) may limit throughput",
                self.max_udp_send_buf
            ));
        }

        // Check memory
        if self.total_memory_bytes < 1_073_741_824 {
            // 1GB
            warnings.push("System has less than 1GB RAM, performance may be limited".to_string());
        }

        // Check cores
        if self.physical_cores < 2 {
            warnings.push(
                "Single-core system detected, consider upgrading for better performance"
                    .to_string(),
            );
        }

        if warnings.is_empty() {
            Ok(())
        } else {
            Err(warnings)
        }
    }
}

/// Get the number of physical CPU cores.
///
/// On Linux, this reads /proc/cpuinfo to determine physical cores.
/// Falls back to num_cpus crate for cross-platform support.
fn get_physical_cores() -> usize {
    // Try to read from /proc/cpuinfo first (Linux)
    #[cfg(target_os = "linux")]
    if let Ok(contents) = fs::read_to_string("/proc/cpuinfo") {
        let mut physical_id_set = std::collections::HashSet::new();
        let mut current_physical_id = None;
        let mut cpu_cores_per_physical = 1;

        for line in contents.lines() {
            if line.starts_with("physical id") {
                if let Some(value) = line.split(':').nth(1) {
                    current_physical_id = value.trim().parse::<usize>().ok();
                }
            } else if line.starts_with("cpu cores") {
                if let Some(value) = line.split(':').nth(1) {
                    cpu_cores_per_physical = value.trim().parse().unwrap_or(1);
                }
            }

            // End of processor block
            if line.is_empty() {
                if let Some(id) = current_physical_id {
                    physical_id_set.insert(id);
                }
                current_physical_id = None;
            }
        }

        // If we found physical IDs, use that count * cores per socket
        if !physical_id_set.is_empty() {
            return physical_id_set.len() * cpu_cores_per_physical;
        }
    }

    // Fallback to num_cpus crate
    num_cpus::get_physical().max(1)
}

/// Get total system memory in bytes.
///
/// Queries system memory from /proc/meminfo on Linux,
/// falls back to sys-info crate for cross-platform support.
fn get_total_memory() -> u64 {
    // Try /proc/meminfo (Linux)
    #[cfg(target_os = "linux")]
    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb * 1024; // Convert KB to bytes
                    }
                }
            }
        }
    }

    // Fallback to sys-info crate
    sys_info::mem_info()
        .map(|info| info.total * 1024) // sys-info returns KB, convert to bytes
        .unwrap_or(1_073_741_824) // 1GB fallback
}

/// Get maximum file descriptor limit.
fn get_max_fds() -> u64 {
    // Try getrlimit (Unix)
    #[cfg(unix)]
    {
        use libc::{getrlimit, rlimit, RLIMIT_NOFILE};
        use std::mem;

        let mut rlim = unsafe { mem::zeroed::<rlimit>() };
        if unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) } == 0 {
            return rlim.rlim_cur;
        }
    }

    // Fallback
    1024
}

/// Get maximum UDP buffer size for receive or send.
fn get_max_udp_buffer_size(is_recv: bool) -> usize {
    #[cfg(unix)]
    {
        use std::mem;
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        // Create a test socket to query limits
        if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
            let opt = if is_recv {
                libc::SO_RCVBUF
            } else {
                libc::SO_SNDBUF
            };
            let mut buf_size: libc::socklen_t = mem::size_of::<usize>() as libc::socklen_t;
            let mut value: usize = 0;

            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    opt,
                    &mut value as *mut usize as *mut libc::c_void,
                    &mut buf_size,
                )
            } == 0
            {
                // Try to set maximum possible
                let max_sizes = [4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024, 512 * 1024];
                for &size in &max_sizes {
                    if unsafe {
                        libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::SOL_SOCKET,
                            opt,
                            &size as *const usize as *const libc::c_void,
                            mem::size_of::<usize>() as libc::socklen_t,
                        )
                    } == 0
                    {
                        return size;
                    }
                }
                return value; // Return original size if we can't set larger
            }
        }
    }

    // Fallback
    212_992 // 208KB, common Linux default
}

/// Get system page size.
fn get_page_size() -> usize {
    #[cfg(unix)]
    {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    #[cfg(not(unix))]
    {
        4096 // Common default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_resources_query() {
        let resources = SystemResources::query();
        assert!(resources.physical_cores > 0);
        assert!(resources.total_memory_bytes > 0);
        assert!(resources.page_size > 0);
        assert!(resources.max_fds > 0);
    }

    #[test]
    fn test_calculated_defaults() {
        let resources = SystemResources::query();

        assert!(resources.optimal_worker_threads() > 0);
        assert!(resources.max_connections_from_memory() >= 100);
        assert!(resources.optimal_udp_recv_buf() >= 2 * 1024 * 1024);
        assert!(resources.optimal_io_uring_entries() >= 1024);

        // Ensure calculations are reasonable
        assert!(resources.optimal_worker_threads() <= 1024);
        assert!(resources.optimal_netio_workers() <= 1024);
        assert!(resources.optimal_buffers_per_worker() >= 512);
        assert!(resources.optimal_buffers_per_worker() <= 8192);
    }

    #[test]
    fn test_channel_capacity_scaling() {
        let resources = SystemResources::query();

        let egress = resources.optimal_worker_egress_capacity();
        let ingress = resources.optimal_connection_ingress_capacity();
        let stream = resources.optimal_stream_channel_capacity();

        // Verify bounds
        assert!(egress >= 512 && egress <= 8192);
        assert!(ingress >= 64 && ingress <= 512);
        assert!(stream >= 32 && stream <= 128);
    }

    #[test]
    fn test_flow_control_windows() {
        let resources = SystemResources::query();

        let conn_window = resources.optimal_quic_recv_window();
        let stream_window = resources.optimal_quic_stream_recv_window();

        // Connection window should be at least 10MB
        assert!(conn_window >= 10 * 1024 * 1024);
        // Connection window should not exceed 100MB
        assert!(conn_window <= 100 * 1024 * 1024);
        // Stream window should be 10% of connection window
        assert_eq!(stream_window, conn_window / 10);
    }

    #[test]
    fn test_idle_timeout_logic() {
        let resources = SystemResources::query();
        let timeout = resources.optimal_idle_timeout_ms();

        // Should be either base (30s) or aggressive (5s)
        assert!(timeout == 30_000 || timeout == 5_000);
    }

    #[test]
    fn test_udp_payload_size() {
        let resources = SystemResources::query();
        let payload_size = resources.optimal_max_udp_payload();

        // Should be conservative default
        assert_eq!(payload_size, 1350);
    }

    #[test]
    fn test_validation_warnings() {
        let resources = SystemResources::query();

        // Validation should not panic
        let result = resources.validate_system_limits();

        // Either passes or returns warnings
        match result {
            Ok(()) => {
                // System is well-configured
            }
            Err(warnings) => {
                // Warnings should be non-empty and informative
                assert!(!warnings.is_empty());
                for warning in warnings {
                    assert!(!warning.is_empty());
                }
            }
        }
    }
}
