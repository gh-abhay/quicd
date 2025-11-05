//! Memory prefetch hints for hot paths.
//!
//! Provides software prefetch hints to improve cache hit rates on critical
//! data structures. Particularly beneficial for:
//! - HashMap lookups before actual access
//! - Connection objects before processing
//! - Frequently accessed fields in hot structures

/// Prefetch mode for cache locality
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum PrefetchMode {
    /// Read-only prefetch (temporal locality - keep in cache)
    Read,
    /// Write prefetch (temporal locality)
    Write,
}

/// Prefetch a memory location into cache.
///
/// This is a hint to the CPU to begin loading the specified memory address
/// into cache before it's actually needed. On architectures that support
/// prefetching, this can significantly reduce cache miss latency in hot paths.
///
/// # Safety
/// The pointer must be valid (but not necessarily aligned or initialized).
/// This is a hint - incorrect usage won't cause UB, just inefficiency.
///
/// # Implementation
/// - On nightly Rust with intrinsics: uses `core::intrinsics::prefetch_*`
/// - On stable Rust: uses inline assembly (x86_64/aarch64) or no-op fallback
/// - Compiles away completely if architecture doesn't support prefetch
#[inline(always)]
pub fn prefetch<T>(ptr: *const T, _mode: PrefetchMode) {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    {
        // SAFETY: This is just a hint to the CPU. The pointer must be valid
        // but doesn't need to be aligned or initialized. On x86_64, prefetcht0
        // loads data into all cache levels with temporal locality hint.
        unsafe {
            core::arch::x86_64::_mm_prefetch::<_MM_HINT_T0>(ptr as *const i8);
        }
    }

    #[cfg(all(target_arch = "aarch64", not(miri)))]
    {
        // SAFETY: PRFM on ARM prefetches to L1 cache with temporal locality.
        // pldl1keep = prefetch for load into L1, keep (temporal)
        unsafe {
            core::arch::asm!(
                "prfm pldl1keep, [{ptr}]",
                ptr = in(reg) ptr,
                options(nostack, readonly, preserves_flags)
            );
        }
    }

    // On other architectures or during miri execution, this is a no-op
    #[cfg(not(any(
        all(target_arch = "x86_64", not(miri)),
        all(target_arch = "aarch64", not(miri))
    )))]
    {
        let _ = ptr;
    }
}

/// Prefetch a range of memory into cache.
///
/// Useful for prefetching larger structures or arrays. Prefetches at cache-line
/// boundaries (64 bytes on x86_64, 128 bytes on some ARM).
#[inline(always)]
pub fn prefetch_range<T>(ptr: *const T, count: usize, mode: PrefetchMode) {
    if count == 0 {
        return;
    }

    const CACHE_LINE_SIZE: usize = 64; // Conservative estimate (works for x86_64)

    let start = ptr as usize;
    let end = start + count * core::mem::size_of::<T>();
    let mut addr = start;

    // Prefetch at cache line boundaries
    while addr < end {
        prefetch(addr as *const u8, mode);
        addr += CACHE_LINE_SIZE;
    }
}

// Import the constant for x86_64 prefetch intrinsic
#[cfg(all(target_arch = "x86_64", not(miri)))]
use core::arch::x86_64::_MM_HINT_T0;
