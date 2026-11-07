pub mod config;
pub mod forward;
pub mod http_proxy;
pub mod mapping;
pub mod netstack;
pub mod ping;
pub mod resolver;
pub mod socks;
pub mod stats;

/// Auto-incremented build number (set by build.rs).
pub const BUILD_NUM: &str = env!("BUILD_NUM");
