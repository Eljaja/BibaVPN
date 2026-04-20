//! BibaVPN: WebSocket-over-TLS tunnel with optional per-frame padding (AmneziaWG-style traffic shaping)
//! and browser-looking HTTP upgrade headers. Intended to run alongside zapret on Linux routers
//! (see `scripts/zapret-sidecar.sh`); zapret is not linked into these binaries.

pub mod camouflage;
pub mod crypto_layer;
pub mod decoy_traffic;
pub mod frame;
pub mod http_connect;
pub mod incoming;
pub mod invite_uri;
pub mod local_client;
pub mod outbound_protect;
pub mod protocol;
mod retry;
pub mod socks5;
pub mod start_json_config;
pub mod stealth;
pub mod tcp_mux;
mod tcp_mux_roadmap;
pub mod tls_util;
pub mod reality;
pub mod udp_mux;
pub mod ws_auth;
pub mod ws_bridge;

pub use frame::{
    read_padded_frame, read_padded_frame_borrow, read_padded_frame_into, write_padded_frame,
    write_padded_frame_with_mode, FrameError, PadMode,
};
pub use invite_uri::{decode_invite_v1, encode_invite_v1, InviteV1};
pub use reality::{
    RealityClientConfig, RealityServerConfig, TlsFingerprint, RealitySession,
    bridge_reality_server, encode_client_hello, decode_server_hello,
    extract_sni, is_short_id_allowed, REALITY_MAGIC, REALITY_VERSION,
    spiderx_fetch, spawn_spiderx, parse_target, create_tls_connector,
};
pub use start_json_config::{
    local_client_options_from_json_str, local_client_options_from_json_str_with_binds,
};
pub use stealth::browser_websocket_request;
pub use tls_util::{client_tls_config, ClientTlsParams, TlsClientProfile};
