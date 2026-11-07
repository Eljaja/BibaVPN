//! Transport layer: TLS configuration/certificates plus the optional
//! WebSocket (`ws` feature: ws:// and wss://) and QUIC (`quic` feature:
//! quic://) link transports.

pub mod tls;

#[cfg(feature = "quic")]
pub(crate) mod quic;

#[cfg(feature = "ws")]
pub(crate) mod ws;
