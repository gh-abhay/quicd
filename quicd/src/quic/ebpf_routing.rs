//! eBPF-based routing for QUIC connection affinity.
//!
//! This module integrates with the `quicd-ebpf-router` crate to provide
//! connection-affinity routing for QUIC connections. Worker sockets are
//! registered with the eBPF program, and routing cookies are embedded into
//! QUIC Connection IDs so that packets are consistently delivered to the
//! correct worker thread.

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Mutex, OnceLock,
};

use anyhow::{anyhow, Context, Result};
use quicd_ebpf_router::{ConnectionId, Cookie, Router};
use tracing::{debug, info, warn};

/// Shared router state used by all workers.
struct RouterState {
    router: Mutex<Router>,
    worker_cookies: Mutex<HashMap<usize, u16>>,
}

impl RouterState {
    fn new(router: Router) -> Self {
        Self {
            router: Mutex::new(router),
            worker_cookies: Mutex::new(HashMap::new()),
        }
    }
}

/// Global router state initialised once at startup.
static ROUTER_STATE: OnceLock<Arc<RouterState>> = OnceLock::new();

/// Current cookie generation (shared by all workers).
static CURRENT_GENERATION: AtomicU8 = AtomicU8::new(0);

/// Initialise the eBPF router subsystem.
///
/// This loads the eBPF program, attaches it, and prepares the worker socket
/// map for registration. Must be called before spawning any workers.
pub fn initialize_router() -> Result<()> {
    let router = Router::new().context("failed to load eBPF router program")?;
    let state = Arc::new(RouterState::new(router));

    ROUTER_STATE
        .set(state)
        .map_err(|_| anyhow!("eBPF router already initialised"))?;

    CURRENT_GENERATION.store(0, Ordering::Relaxed);

    info!("eBPF router initialised and ready for worker registration");
    Ok(())
}

/// Check whether the router has been initialised.
#[allow(dead_code)]
pub fn is_router_initialised() -> bool {
    ROUTER_STATE.get().is_some()
}

fn router_state() -> Result<Arc<RouterState>> {
    ROUTER_STATE
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("eBPF router not initialised"))
}

/// Register a worker socket in the eBPF map.
///
/// Returns the routing cookie that was inserted for the socket.
pub fn register_worker_socket<S: AsRawFd>(worker_id: usize, socket: &S) -> Result<u16> {
    let state = router_state()?;
    let worker_idx: u8 = worker_id
        .try_into()
        .map_err(|_| anyhow!("worker_id {worker_id} exceeds 255"))?;
    let generation = CURRENT_GENERATION.load(Ordering::Relaxed);

    // Capture existing cookie (if any) so we can remove stale entries.
    let existing_cookie = {
        let cookies = state
            .worker_cookies
            .lock()
            .map_err(|_| anyhow!("worker cookie map poisoned"))?;
        cookies.get(&worker_id).copied()
    };

    let mut router = state
        .router
        .lock()
        .map_err(|_| anyhow!("router mutex poisoned"))?;

    if let Some(old_cookie) = existing_cookie {
        if old_cookie != Cookie::generate(generation, worker_idx) {
            if let Err(e) = router.remove_socket(old_cookie) {
                warn!(
                    worker_id,
                    old_cookie,
                    error = ?e,
                    "failed to remove stale cookie from eBPF map"
                );
            }
        }
    }

    let cookie = router
        .register_worker_socket(generation, worker_idx, socket)
        .with_context(|| format!("registering worker {worker_id} socket with eBPF router"))?;

    drop(router);

    state
        .worker_cookies
        .lock()
        .map_err(|_| anyhow!("worker cookie map poisoned"))?
        .insert(worker_id, cookie);

    info!(
        worker_id,
        generation, cookie, "Registered worker socket in eBPF worker map"
    );

    Ok(cookie)
}

/// Remove a worker socket from the eBPF map.
pub fn unregister_worker_socket(worker_id: usize) -> Result<()> {
    let state = router_state()?;

    let cookie = {
        let mut cookies = state
            .worker_cookies
            .lock()
            .map_err(|_| anyhow!("worker cookie map poisoned"))?;
        cookies.remove(&worker_id)
    };

    if let Some(cookie) = cookie {
        let mut router = state
            .router
            .lock()
            .map_err(|_| anyhow!("router mutex poisoned"))?;
        if let Err(e) = router.remove_socket(cookie) {
            warn!(worker_id, cookie, error = ?e, "failed to remove worker socket from eBPF map");
        } else {
            info!(
                worker_id,
                cookie, "Removed worker socket from eBPF worker map"
            );
        }
    } else {
        debug!(
            worker_id,
            "Worker socket not found in eBPF map during unregister"
        );
    }

    Ok(())
}

/// Get the current cookie generation counter.
pub fn current_generation() -> u8 {
    CURRENT_GENERATION.load(Ordering::Relaxed)
}

/// Rotate the cookie generation counter.
///
/// Returns the new generation value.
#[allow(dead_code)]
pub fn rotate_generation() -> u8 {
    let old_generation = CURRENT_GENERATION.load(Ordering::Relaxed);
    let new_generation = (old_generation.wrapping_add(1)) & 0x1F; // 5 bits
    CURRENT_GENERATION.store(new_generation, Ordering::Relaxed);
    debug!(
        old_generation,
        new_generation, "Rotated cookie generation for eBPF routing"
    );
    new_generation
}

/// Generate a connection ID with embedded routing cookie for a worker.
pub fn generate_connection_id(worker_idx: u8, prefix_seed: u32) -> [u8; 20] {
    let generation = current_generation();
    ConnectionId::generate_with_seed(generation, worker_idx, prefix_seed)
}

/// Validate a connection ID and return the worker index if valid.
#[allow(dead_code)]
pub fn validate_and_extract_worker(cid: &[u8]) -> Option<u8> {
    if !ConnectionId::validate_cookie(cid) {
        return None;
    }
    ConnectionId::get_worker_idx(cid)
}

/// Verify that a cookie is valid for the current generation.
#[allow(dead_code)]
pub fn is_valid_cookie(cookie: u16) -> bool {
    let generation = current_generation();
    quicd_ebpf_router::is_valid_worker_cookie(cookie, generation)
}

/// Get the expected cookie for a worker (for debugging/verification).
#[allow(dead_code)]
pub fn get_expected_cookie(worker_idx: u8) -> u16 {
    let generation = current_generation();
    quicd_ebpf_router::get_worker_cookie(generation, worker_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_generation() {
        let cid = generate_connection_id(42, 0x1234_5678);
        assert_eq!(cid.len(), 20);
        assert!(ConnectionId::validate_cookie(&cid));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(42));
    }

    #[test]
    fn test_generation_rotation() {
        CURRENT_GENERATION.store(0, Ordering::Relaxed);
        let gen1 = current_generation();
        let gen2 = rotate_generation();
        assert_ne!(gen1, gen2);
        for _ in 0..31 {
            rotate_generation();
        }
        assert_eq!(current_generation(), gen1);
    }

    #[test]
    fn test_validate_and_extract() {
        let cid = generate_connection_id(17, 0x00FF_AABB);
        assert_eq!(validate_and_extract_worker(&cid), Some(17));
    }

    #[test]
    fn test_invalid_cid() {
        let invalid = [0x01, 0x02, 0x03];
        assert_eq!(validate_and_extract_worker(&invalid), None);
    }
}
