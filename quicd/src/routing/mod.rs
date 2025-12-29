pub mod cid_generator;
pub mod router;
pub mod routing;

#[cfg(test)]
mod tests;

pub use cid_generator::RoutingConnectionIdGenerator;
pub use router::{
    get_worker_cookie, is_valid_worker_cookie, load_ebpf, setup_rlimit, ConnectionId, Cookie,
    Router, CID_LENGTH,
};

pub use routing::{
    current_generation, generate_connection_id, get_expected_cookie, initialize_router,
    is_router_initialised, is_valid_cookie, register_worker_socket, rotate_generation,
    unregister_worker_socket, validate_and_extract_worker,
};
