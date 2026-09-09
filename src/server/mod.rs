//! Network listeners: UDP/TCP (RFC 1035), DoH (RFC 8484), and the management
//! REST API. Thread-per-worker model (no async runtime).

pub mod doh;
pub mod http;
pub mod tcp;
pub mod udp;

pub use tcp::serve_tcp;
pub use udp::serve_udp;
