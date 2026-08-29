//! Transport-neutral outer duplex framing (WebSocket today; gRPC-Web later).

pub mod ws;

pub use ws::{OuterMsg, WsConn};
