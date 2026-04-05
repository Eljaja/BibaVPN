//! BibaVPN: WebSocket-over-TLS tunnel with optional per-frame padding (AmneziaWG-style traffic shaping)
//! and browser-looking HTTP upgrade headers. Intended to run alongside zapret on Linux routers
//! (see `scripts/zapret-sidecar.sh`); zapret is not linked into these binaries.

pub mod crypto_layer;
pub mod frame;
pub mod http_connect;
pub mod protocol;
pub mod socks5;
pub mod stealth;
pub mod tls_util;
pub mod ws_bridge;

pub use frame::{FrameError, read_padded_frame, write_padded_frame};
pub use stealth::browser_websocket_request;
