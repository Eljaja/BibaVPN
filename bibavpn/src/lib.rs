//! BibaVPN: WebSocket-over-TLS tunnel with optional per-frame padding (AmneziaWG-style traffic shaping)
//! and browser-looking HTTP upgrade headers. Intended to run alongside zapret on Linux routers
//! (see `scripts/zapret-sidecar.sh`); zapret is not linked into these binaries.

pub mod activity;
pub mod camouflage;
pub mod client_policy;
pub mod client_tls_stream;
#[cfg(feature = "boring-tls")]
pub mod tls_boring;
pub mod crypto_layer;
pub mod desync;
pub mod decoy_traffic;
pub mod domain_route;
pub mod frame;
pub mod http_connect;
pub mod incoming;
pub mod invite_uri;
pub mod local_client;
pub mod outbound_protect;
pub mod protocol;
mod retry;
pub use retry::ServerWsOutTiming;
pub mod socks5;
pub mod start_json_config;
pub mod stealth;
pub mod stealth_v12;
pub mod tcp_mux;
mod tcp_mux_roadmap;
pub mod tls_util;
pub mod reality;
pub mod log_ratelimit;
pub mod logging;
pub mod server_limits;
pub mod server_metrics;
pub mod transport_capabilities;
pub mod udp_mux;
pub mod ws_auth;
pub mod ws_bridge;

pub use crypto_layer::secret_eq;
pub use frame::{
    read_padded_frame, read_padded_frame_borrow, read_padded_frame_into, write_padded_frame,
    write_padded_frame_with_mode, write_padded_frame_with_mode_state, AdaptivePadState, FrameError,
    PadMode,
};
pub use invite_uri::{decode_invite_v1, encode_invite_v1, InviteV1};
pub use reality::{
    decode_server_hello, effective_tls_sni, encode_client_hello, extract_sni,
    is_short_id_allowed, parse_target, create_tls_connector, reality_client_exchange_verify,
    reality_confirm_mac, server_handshake_reality, server_hello_with_confirm,
    RealityClientConfig, RealityServerConfig,
    REALITY_MAGIC, REALITY_VERSION, spiderx_fetch, spawn_spiderx, TlsFingerprint,
};
pub use start_json_config::{
    local_client_options_from_json_str, local_client_options_from_json_str_with_binds,
};
pub use stealth::browser_websocket_request;
pub use stealth_v12::{
    apply_preset_ws_jitter, merge_idle_decoy_secs, DecoyMode, DesyncMode, ServerRttDefaults,
    StealthProfile, StealthPreset, TcpFooling, preset,
};
pub use tcp_mux::MuxWriterStopped;
pub use tls_util::{client_tls_config, ClientTlsParams, TlsClientProfile, TlsStack};
