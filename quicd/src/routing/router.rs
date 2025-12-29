use aya::{
    maps::{MapData, SockHash},
    programs::SkMsg,
};
use ebpf::SockKey;
#[rustfmt::skip]
use log::debug;
use siphasher::sip::SipHasher13;
use std::hash::Hasher;
use std::os::fd::AsRawFd;

// Re-export Cookie utilities for applications
pub use ebpf::Cookie;

/// Standard Connection ID length used by this router (20 bytes)
pub const CID_LENGTH: usize = 20;

const WORKER_MAP_NAME: &str = "QUICD_WORKERS";
const ROUTER_PROGRAM_NAME: &str = "quicd_ebpf_router";

/// High-level interface for managing the QUIC router eBPF program and worker sockets
///
/// This type wraps the lifecycle of the userspace eBPF loader, exposes helpers for
/// registering sockets, and allows applications to interact with the underlying
/// worker map if they need custom behaviour.
///
/// # Example
///
/// ```no_run
/// use std::net::UdpSocket;
/// use quicd_ebpf_router::{Router, ConnectionId};
///
/// fn main() -> anyhow::Result<()> {
///     // Initialise logging/rlimits and load the eBPF router program
///     let mut router = Router::new()?;
///
///     // Prepare a worker socket which should receive QUIC packets
///     let socket = UdpSocket::bind("127.0.0.1:0")?;
///
///     // Register the socket by generation/worker index
///     let cookie = router.register_worker_socket(0, 1, &socket)?;
///
///     // Use the cookie when building 20-byte connection IDs for clients
///     let cid = ConnectionId::generate(0, 1)?; // Recommended: uses secure randomness
///     assert_eq!(ConnectionId::extract_cookie(&cid), Some(cookie));
///     assert!(ConnectionId::verify_protection(&cid));
///
///     Ok(())
/// }
/// ```
pub struct Router {
    ebpf: aya::Ebpf,
    sock_map: SockHash<MapData, SockKey>,
}

impl Router {
    /// Load the eBPF program, attach it, and return a router ready for socket registration
    pub fn new() -> anyhow::Result<Self> {
        setup_rlimit()?;
        let ebpf = load_ebpf()?;
        Self::from_loaded_ebpf(ebpf)
    }

    /// Build a router from a pre-loaded eBPF object
    pub fn from_loaded_ebpf(mut ebpf: aya::Ebpf) -> anyhow::Result<Self> {
        let sock_map: SockHash<_, SockKey> = ebpf
            .take_map(WORKER_MAP_NAME)
            .ok_or_else(|| anyhow::anyhow!("map '{}' not found", WORKER_MAP_NAME))?
            .try_into()?;

        let map_fd = sock_map.fd().try_clone()?;

        let prog: &mut SkMsg = ebpf
            .program_mut(ROUTER_PROGRAM_NAME)
            .ok_or_else(|| anyhow::anyhow!("program '{}' not found", ROUTER_PROGRAM_NAME))?
            .try_into()?;
        prog.load()?;
        prog.attach(&map_fd)?;

        Ok(Self { ebpf, sock_map })
    }

    /// Insert a socket file descriptor keyed by a precomputed cookie
    pub fn insert_socket<S: AsRawFd>(&mut self, cookie: SockKey, socket: &S) -> anyhow::Result<()> {
        let fd = socket.as_raw_fd();
        self.sock_map.insert(cookie, fd, 0)?;
        Ok(())
    }

    /// Convenience helper to compute the cookie and insert the socket in one step
    pub fn register_worker_socket<S: AsRawFd>(
        &mut self,
        generation: u8,
        worker_idx: u8,
        socket: &S,
    ) -> anyhow::Result<u16> {
        let cookie = Cookie::generate(generation, worker_idx);
        self.insert_socket(cookie, socket)?;
        Ok(cookie)
    }

    /// Remove a socket entry from the routing map
    pub fn remove_socket(&mut self, cookie: SockKey) -> anyhow::Result<()> {
        self.sock_map.remove(&cookie)?;
        Ok(())
    }

    /// Borrow the underlying socket map for advanced manipulations
    pub fn sock_map(&mut self) -> &mut SockHash<MapData, SockKey> {
        &mut self.sock_map
    }

    /// Access the underlying eBPF object for custom configuration
    pub fn ebpf(&mut self) -> &mut aya::Ebpf {
        &mut self.ebpf
    }
}

/// Helper struct for working with QUIC Connection IDs
///
/// # Overview
///
/// This module provides utilities to embed routing cookies into QUIC Connection IDs,
/// enabling eBPF-based routing of QUIC packets to specific worker sockets.
///
/// # QUIC Connection ID Flow
///
/// 1. **Client sends Initial packet** - Contains client-chosen DCID (no valid cookie)
/// 2. **Server generates SCID** - Server creates a new Connection ID with embedded cookie
/// 3. **Server responds** - Sends Initial/Handshake with the new CID as SCID
/// 4. **Client adopts SCID** - Client uses server's SCID as DCID in subsequent packets
/// 5. **eBPF routes packets** - eBPF extracts cookie from DCID and redirects to correct socket
///
/// # 20-byte Connection ID Format
///
/// - Bytes 0-5: Random prefix (6 bytes)
/// - Bytes 6-7: Routing cookie (u16 big-endian)
/// - Bytes 8-18: Random entropy (11 bytes)
/// - Byte 19: Protection byte (SipHash-1-3 LSB over bytes 0-18)
///
/// Total entropy: 136 bits → safe for >100M concurrent connections
///
/// # Cookie Format
///
/// The 16-bit cookie is embedded in bytes 6-7 of the 20-byte Connection ID:
/// - Bits 11-15 (5 bits): Generation counter (allows rotation)
/// - Bits 3-10 (8 bits): Worker/socket index (0-255)
/// - Bits 0-2 (3 bits): Checksum for validation
///
/// # Example Usage
///
/// ```no_run
/// use quicd_ebpf_router::{ConnectionId, Cookie};
///
/// // When receiving a client Initial packet without a valid cookie:
/// let worker_idx = 42u8; // This socket's worker index
/// let generation = 0u8;   // Current generation (can increment over time)
///
/// // Option 1: Fully automatic generation (recommended for production)
/// let server_cid = ConnectionId::generate(generation, worker_idx).unwrap();
///
/// // Option 2: Bring-your-own randomness (for testing or custom entropy)
/// let entropy = [0u8; 17]; // 6 bytes prefix + 11 bytes suffix
/// let server_cid = ConnectionId::generate_with_entropy(generation, worker_idx, entropy);
///
/// // Option 3: Seeded generation (for tests only)
/// let prefix_seed = 0x12345678u32;
/// let server_cid = ConnectionId::generate_with_seed(generation, worker_idx, prefix_seed);
///
/// // Use server_cid as SCID in the Server Initial packet
/// // The client will echo it back as DCID in subsequent packets
///
/// // Later, when receiving packets, validate the cookie:
/// if ConnectionId::validate_cookie(&server_cid) {
///     let worker = ConnectionId::get_worker_idx(&server_cid).unwrap();
///     println!("Valid cookie for worker {}", worker);
/// }
///
/// // The eBPF program will automatically extract and validate the cookie
/// // and redirect packets to the appropriate socket in the QUICD_WORKERS map
/// ```
pub struct ConnectionId;

// SipHash key for CID protection (can be rotated for additional security)
const SIPHASH_KEY: (u64, u64) = (0x0706050403020100, 0x0f0e0d0c0b0a0908);

impl ConnectionId {
    /// Generate a new 20-byte Connection ID with automatic randomness (recommended)
    ///
    /// This is the recommended method for production use. It:
    /// - Fills bytes 0-5 and 8-18 with cryptographically secure random data
    /// - Writes the routing cookie to bytes 6-7
    /// - Computes SipHash-1-3 over bytes 0-18 and writes LSB to byte 19
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    ///
    /// # Returns
    /// A 20-byte array representing the Connection ID, or an error if randomness fails
    ///
    /// # Example
    /// ```no_run
    /// use quicd_ebpf_router::ConnectionId;
    ///
    /// let cid = ConnectionId::generate(0, 42).unwrap();
    /// assert_eq!(cid.len(), 20);
    /// ```
    pub fn generate(generation: u8, worker_idx: u8) -> Result<[u8; CID_LENGTH], getrandom::Error> {
        let mut entropy = [0u8; 17];
        getrandom::getrandom(&mut entropy)?;
        Ok(Self::generate_with_entropy(generation, worker_idx, entropy))
    }

    /// Generate a new 20-byte Connection ID with provided entropy
    ///
    /// Use this method when you want to provide your own randomness source.
    /// The entropy is split into prefix (6 bytes) and suffix (11 bytes).
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `entropy` - 17 bytes of random data (6 for prefix, 11 for suffix)
    ///
    /// # Returns
    /// A 20-byte array representing the Connection ID
    ///
    /// # Example
    /// ```
    /// use quicd_ebpf_router::ConnectionId;
    ///
    /// let entropy = [0xAAu8; 17]; // In production, use real random data
    /// let cid = ConnectionId::generate_with_entropy(0, 42, entropy);
    /// assert_eq!(cid.len(), 20);
    /// ```
    pub fn generate_with_entropy(
        generation: u8,
        worker_idx: u8,
        entropy: [u8; 17],
    ) -> [u8; CID_LENGTH] {
        let cookie = Cookie::generate(generation, worker_idx);
        let cookie_bytes = cookie.to_be_bytes();

        let mut cid = [0u8; CID_LENGTH];

        // Bytes 0-5: Random prefix from entropy
        cid[0..6].copy_from_slice(&entropy[0..6]);

        // Bytes 6-7: Routing cookie
        cid[6..8].copy_from_slice(&cookie_bytes);

        // Bytes 8-18: Random entropy (11 bytes)
        cid[8..19].copy_from_slice(&entropy[6..17]);

        // Byte 19: SipHash-1-3 protection byte
        let mut hasher = SipHasher13::new_with_keys(SIPHASH_KEY.0, SIPHASH_KEY.1);
        hasher.write(&cid[0..19]);
        let hash = hasher.finish();
        cid[19] = (hash & 0xFF) as u8;

        cid
    }

    /// Generate a new Connection ID with seeded randomness (for testing only)
    ///
    /// This method uses a simple PRNG based on the seed for deterministic testing.
    /// DO NOT use this in production - use `generate()` instead.
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `seed` - A seed value to generate deterministic entropy
    ///
    /// # Returns
    /// A 20-byte array representing the Connection ID
    pub fn generate_with_seed(generation: u8, worker_idx: u8, seed: u32) -> [u8; CID_LENGTH] {
        // Simple PRNG for testing (NOT cryptographically secure)
        let mut entropy = [0u8; 17];
        let mut state = seed;

        for (i, entropy_byte) in entropy.iter_mut().enumerate() {
            // Simple LCG: state = (a * state + c) mod m
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *entropy_byte = (state >> (8 * (i % 4))) as u8;
        }

        Self::generate_with_entropy(generation, worker_idx, entropy)
    }

    /// Verify the SipHash protection byte of a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID to verify (must be exactly 20 bytes)
    ///
    /// # Returns
    /// `true` if the protection byte is valid, `false` otherwise
    pub fn verify_protection(cid: &[u8]) -> bool {
        if cid.len() != CID_LENGTH {
            return false;
        }

        let mut hasher = SipHasher13::new_with_keys(SIPHASH_KEY.0, SIPHASH_KEY.1);
        hasher.write(&cid[0..19]);
        let hash = hasher.finish();
        let expected = (hash & 0xFF) as u8;

        cid[19] == expected
    }

    /// Extract the cookie from a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID (must be at least 8 bytes)
    ///
    /// # Returns
    /// The extracted cookie value, or None if the CID is too short
    pub fn extract_cookie(cid: &[u8]) -> Option<u16> {
        if cid.len() < 8 {
            return None;
        }

        Some(u16::from_be_bytes([cid[6], cid[7]]))
    }

    /// Validate a Connection ID's cookie
    ///
    /// Note: This only validates the cookie checksum, not the SipHash protection byte.
    /// For full validation, also call `verify_protection()`.
    ///
    /// # Arguments
    /// * `cid` - The Connection ID to validate
    ///
    /// # Returns
    /// `true` if the cookie is valid, `false` otherwise
    pub fn validate_cookie(cid: &[u8]) -> bool {
        Self::extract_cookie(cid)
            .map(Cookie::validate)
            .unwrap_or(false)
    }

    /// Get the worker index from a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID
    ///
    /// # Returns
    /// The worker index, or None if extraction fails
    pub fn get_worker_idx(cid: &[u8]) -> Option<u8> {
        Self::extract_cookie(cid).map(Cookie::get_worker_idx)
    }

    /// Get the generation from a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID
    ///
    /// # Returns
    /// The generation, or None if extraction fails
    pub fn get_generation(cid: &[u8]) -> Option<u8> {
        Self::extract_cookie(cid).map(Cookie::get_generation)
    }
}

pub fn setup_rlimit() -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    Ok(())
}

pub fn load_ebpf() -> anyhow::Result<aya::Ebpf> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/quicd-ebpf-router"
    )))?)
}

/// Get the expected cookie for a worker
/// Useful for debugging and verification
pub fn get_worker_cookie(generation: u8, worker_idx: u8) -> u16 {
    Cookie::generate(generation, worker_idx)
}

/// Check if a cookie corresponds to a valid worker
/// This is a local check - doesn't query the eBPF map
pub fn is_valid_worker_cookie(cookie: u16, current_generation: u8) -> bool {
    Cookie::validate(cookie) && Cookie::get_generation(cookie) == current_generation
}

