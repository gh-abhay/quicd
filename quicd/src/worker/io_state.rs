//! I/O operation state management for io_uring.
//!
//! This module manages the lifecycle of in-flight I/O operations submitted to io_uring.
//! Each operation's state must be kept alive until the kernel completes the operation.
//!
//! # Safety
//!
//! io_uring operations reference memory (buffers, iovec, msghdr, sockaddr) that must
//! remain valid until the operation completes. This module ensures proper lifetime
//! management by heap-allocating all state and storing it until completion.

use crate::netio::buffer::WorkerBuffer;
use std::mem::MaybeUninit;
use std::net::SocketAddr;

/// State for a receive operation.
///
/// All fields must remain valid until the kernel completes the recvmsg operation.
/// This struct is heap-allocated and stored in the `in_flight_recv` map.
pub struct RecvOpState {
    /// Buffer to receive data into
    pub buffer: Option<WorkerBuffer>,

    /// Socket address storage for peer address
    pub addr_storage: Box<libc::sockaddr_storage>,

    /// iovec structure pointing to buffer
    /// SAFETY: Must outlive the io_uring operation
    pub iov: Box<libc::iovec>,

    /// msghdr structure for recvmsg
    /// SAFETY: Must outlive the io_uring operation
    pub msg: Box<libc::msghdr>,
}

impl RecvOpState {
    /// Create a new receive operation state.
    ///
    /// # Safety
    ///
    /// The returned structure contains pointers that reference other fields.
    /// It must not be moved after creation (hence we return it in a Box).
    pub fn new(mut buffer: WorkerBuffer) -> Box<Self> {
        // SAFETY: Zero-initialization is safe for sockaddr_storage as it's a C struct
        // designed to hold any socket address type and all-zeros is a valid initial state
        let addr_storage =
            Box::new(unsafe { MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() });

        // Get buffer slice for I/O
        let buf_slice = buffer.as_mut_slice_for_io();

        // Create iovec on heap
        let iov = Box::new(libc::iovec {
            iov_base: buf_slice.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf_slice.len(),
        });

        // SAFETY: Zero-initialization is safe for msghdr as we explicitly set all
        // required fields below before use
        let msg = Box::new(unsafe { MaybeUninit::<libc::msghdr>::zeroed().assume_init() });

        // SAFETY: We're creating a new Box, so we have stable addresses.
        // However, we need to be careful about the order of operations here.
        // We'll set up the pointers after boxing everything.

        let mut state = Box::new(Self {
            buffer: Some(buffer),
            addr_storage,
            iov,
            msg,
        });

        // Now set up the pointers in msghdr to point to the other boxed fields
        // SAFETY: The Box ensures stable addresses, and we control the lifetime
        state.msg.msg_name = &mut *state.addr_storage as *mut _ as *mut libc::c_void;
        state.msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        state.msg.msg_iov = &*state.iov as *const _ as *mut _;
        state.msg.msg_iovlen = 1;

        state
    }

    /// Get a pointer to the msghdr for io_uring submission.
    ///
    /// # Safety
    ///
    /// The returned pointer is only valid as long as this RecvOpState exists.
    /// Caller must ensure the state is not dropped until io_uring completes.
    pub fn msg_ptr(&mut self) -> *mut libc::msghdr {
        &mut *self.msg as *mut _
    }

    /// Extract the peer address from the sockaddr_storage after completion.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        unsafe {
            match (*self.addr_storage).ss_family as i32 {
                libc::AF_INET => {
                    let addr =
                        &*(self.addr_storage.as_ref() as *const _ as *const libc::sockaddr_in);
                    Some(SocketAddr::from((
                        std::net::Ipv4Addr::from(addr.sin_addr.s_addr.to_le_bytes()),
                        u16::from_be(addr.sin_port),
                    )))
                }
                libc::AF_INET6 => {
                    let addr =
                        &*(self.addr_storage.as_ref() as *const _ as *const libc::sockaddr_in6);
                    Some(SocketAddr::from((
                        std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
                        u16::from_be(addr.sin6_port),
                    )))
                }
                _ => None,
            }
        }
    }

    /// Reset the state for reuse with a new buffer.
    ///
    /// This allows reusing the heap-allocated structures (RecvOpState, sockaddr_storage,
    /// iovec, msghdr) without reallocating them.
    pub fn reset(&mut self, mut buffer: WorkerBuffer) {
        // Reset iovec to point to new buffer
        let buf_slice = buffer.as_mut_slice_for_io();
        self.iov.iov_base = buf_slice.as_mut_ptr() as *mut libc::c_void;
        self.iov.iov_len = buf_slice.len();
        
        self.buffer = Some(buffer);
        
        // Reset msghdr fields that might have been modified or need refresh
        // msg_name and msg_namelen should be preserved/reset
        self.msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        // msg_iov and msg_iovlen are stable
        // msg_control and msg_controllen are 0/null
        self.msg.msg_flags = 0;
    }
    
    /// Take the buffer from the state.
    pub fn take_buffer(&mut self) -> Option<WorkerBuffer> {
        self.buffer.take()
    }
}

/// State for a send operation.
///
/// All fields must remain valid until the kernel completes the sendmsg operation.
pub struct SendOpState {
    /// Packet data to send (multiple buffers for scatter/gather)
    pub data: Vec<WorkerBuffer>,

    /// Socket address storage for destination
    pub addr_storage: Box<libc::sockaddr_storage>,

    /// iovec structures pointing to data
    pub iovs: Vec<libc::iovec>,

    /// msghdr structure for sendmsg
    pub msg: Box<libc::msghdr>,
}

impl SendOpState {
    /// Create a new send operation state.
    pub fn new(data: Vec<WorkerBuffer>, to: SocketAddr) -> Box<Self> {
        use socket2::SockAddr;

        // Convert SocketAddr to SockAddr for libc compatibility
        let sock_addr = SockAddr::from(to);

        // SAFETY: Zero-initialization is safe for sockaddr_storage, then we copy
        // the actual address data into it
        let mut addr_storage =
            Box::new(unsafe { MaybeUninit::<libc::sockaddr_storage>::zeroed().assume_init() });
        unsafe {
            std::ptr::copy_nonoverlapping(
                sock_addr.as_ptr() as *const libc::sockaddr_storage,
                &mut *addr_storage as *mut libc::sockaddr_storage,
                1,
            );
        }

        // Create iovecs on heap (in Vec)
        let mut iovs: Vec<libc::iovec> = data.iter().map(|buf| libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        }).collect();

        // SAFETY: Zero-initialization is safe for msghdr as we set all required
        // fields below before use
        let msg = Box::new(unsafe { MaybeUninit::<libc::msghdr>::zeroed().assume_init() });

        let mut state = Box::new(Self {
            data,
            addr_storage,
            iovs,
            msg,
        });

        // Set up pointers in msghdr
        state.msg.msg_name = &*state.addr_storage as *const _ as *mut libc::c_void;
        state.msg.msg_namelen = sock_addr.len();
        state.msg.msg_iov = state.iovs.as_mut_ptr();
        state.msg.msg_iovlen = state.iovs.len();

        state
    }

    /// Reset the state for reuse with new data.
    pub fn reset(&mut self, data: Vec<WorkerBuffer>, to: SocketAddr) {
        use socket2::SockAddr;
        
        self.data = data;
        
        // Update address
        let sock_addr = SockAddr::from(to);
        unsafe {
            std::ptr::copy_nonoverlapping(
                sock_addr.as_ptr() as *const libc::sockaddr_storage,
                &mut *self.addr_storage as *mut libc::sockaddr_storage,
                1,
            );
        }
        
        // Update iovecs
        self.iovs.clear();
        for buf in &self.data {
            self.iovs.push(libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            });
        }
        
        // Update msghdr
        self.msg.msg_name = &*self.addr_storage as *const _ as *mut libc::c_void;
        self.msg.msg_namelen = sock_addr.len();
        self.msg.msg_iov = self.iovs.as_mut_ptr();
        self.msg.msg_iovlen = self.iovs.len();
        self.msg.msg_flags = 0;
    }

    /// Get a pointer to the msghdr for io_uring submission.
    pub fn msg_ptr(&self) -> *const libc::msghdr {
        &*self.msg as *const _
    }
}
