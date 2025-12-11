pub mod router;
pub mod routing;

pub use router::{
    CID_LENGTH,
    ConnectionId,
    Cookie,
    Router,
    get_worker_cookie,
    is_valid_worker_cookie,
    load_ebpf,
    setup_rlimit,
};

pub use routing::{
    current_generation,
    generate_connection_id,
    get_expected_cookie,
    initialize_router,
    is_router_initialised,
    is_valid_cookie,
    register_worker_socket,
    rotate_generation,
    unregister_worker_socket,
    validate_and_extract_worker,
};