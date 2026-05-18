//! Client-side TCP desync / TCP options “fooling” hooks. Real low-TTL fake ClientHello and IP fragmentation need raw sockets or OS helpers — not shipped in the default build.

pub use crate::transport_capabilities::{effective_desync_mode, DesyncApplied};

use std::io;
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::warn;

use crate::stealth_v12::{DesyncMode, TcpFooling};

/// Log once per connection if user enabled desync modes that are not applied in-process.
pub fn note_desync_request(mode: DesyncMode) {
    if mode != DesyncMode::Off {
        warn!(
            target: "bibavpn_stealth",
            "desync-mode {:?}: split/disorder/fake handshake require raw sockets or an external helper (e.g. zapret); not applied by rustls/Tokio alone",
            mode
        );
    }
}

/// Best-effort no-op today: platform-specific setsockopt may be added later.
pub async fn after_tcp_connect(
    _stream: &TcpStream,
    mode: DesyncMode,
    fooling: TcpFooling,
) -> io::Result<()> {
    note_desync_request(mode);
    match fooling {
        TcpFooling::Off => Ok(()),
        TcpFooling::Md5Sig | TcpFooling::BadSeq | TcpFooling::BadSum => {
            warn!(
                target: "bibavpn_stealth",
                "tcp fooling {:?}: needs CAP_NET_ADMIN / platform TCP option support; skipped",
                fooling
            );
            Ok(())
        }
    }
}

/// Placeholder for TLS record fragmentation (rustls does not expose record-size control). User may use an external tunnel.
pub fn note_tls_fragment_requested(enabled: bool) {
    if enabled {
        warn!(
            target: "bibavpn_stealth",
            "--tls-fragment: TLS record splitting is not implemented for the rustls stack; use BoringSSL-based transport or a wrapping proxy if you need it"
        );
    }
}

/// High RTT variance decoy hint: use long random sleep before a decoy fetch (browser mode).
pub fn decoy_high_rtt_delay_ms() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen_range(120u64..=480u64)
}

/// Sleep before a “noisy” decoy request.
pub async fn sleep_decoy_rtt_variance() {
    tokio::time::sleep(Duration::from_millis(decoy_high_rtt_delay_ms())).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_high_rtt_delay_in_range() {
        for _ in 0..64 {
            let ms = decoy_high_rtt_delay_ms();
            assert!((120..=480).contains(&ms));
        }
    }

    #[tokio::test]
    async fn after_tcp_connect_is_noop_ok() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = listener.accept().await;
        after_tcp_connect(&client, DesyncMode::Split2, TcpFooling::Off)
            .await
            .unwrap();
    }
}
