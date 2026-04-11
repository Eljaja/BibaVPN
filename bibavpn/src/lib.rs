//! BibaVPN: WebSocket-over-TLS tunnel with optional per-frame padding (AmneziaWG-style traffic shaping)
//! and browser-looking HTTP upgrade headers. Intended to run alongside zapret on Linux routers
//! (see `scripts/zapret-sidecar.sh`); zapret is not linked into these binaries.

pub mod camouflage;
pub mod crypto_layer;
pub mod decoy_traffic;
pub mod frame;
pub mod incoming;
pub mod http_connect;
pub mod invite_uri;
mod retry;
mod tcp_mux_roadmap;
pub mod local_client;
pub mod outbound_protect;
pub mod protocol;
pub mod socks5;
pub mod stealth;
pub mod tcp_mux;
pub mod tls_util;
pub mod udp_mux;
pub mod ws_auth;
pub mod ws_bridge;

pub use frame::{FrameError, PadMode, read_padded_frame, write_padded_frame, write_padded_frame_with_mode};
pub use invite_uri::{InviteV1, decode_invite_v1, encode_invite_v1};
pub use stealth::browser_websocket_request;
pub use tls_util::{ClientTlsParams, TlsClientProfile, client_tls_config};
