//! Multiplex many TCP streams over one WebSocket (after `MUX_OPEN_MAGIC`).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio_tungstenite::WebSocketStream;
use tracing::info;

use crate::crypto_layer::SessionCrypto;
use crate::frame::PadMode;
use crate::protocol::encode_atyp_host_port;
use crate::retry::{ServerWsOutTiming, WsSendJitter};

#[path = "tcp_mux_flow.rs"]
mod flow;

pub type SharedCrypto = Arc<SessionCrypto>;

pub const MUX_OPEN_MAGIC: &[u8] = b"BIBA\x01MUXO\x00";

pub const MUX_FLAG_OPEN: u8 = 0x01;
pub const MUX_FLAG_DATA: u8 = 0x02;
pub const MUX_FLAG_CLOSE: u8 = 0x04;
pub const MUX_FLAG_RST: u8 = 0x08;
pub const MUX_FLAG_WIN: u8 = 0x10;

pub const MUX_INITIAL_WINDOW: u32 = 1024 * 1024;

/// Returned when the mux WebSocket writer task stopped (e.g. reconnect).
#[derive(Debug)]
pub struct MuxWriterStopped;

impl std::fmt::Display for MuxWriterStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tcp mux writer stopped")
    }
}

impl std::error::Error for MuxWriterStopped {}

pub fn is_mux_open(data: &[u8]) -> bool {
    data == MUX_OPEN_MAGIC
}

pub fn encode_mux_open() -> Vec<u8> {
    MUX_OPEN_MAGIC.to_vec()
}

pub fn encode_mux_record(stream_id: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 1 + 4 + payload.len());
    write_mux_record_to(&mut v, stream_id, flags, payload);
    v
}

/// Append a mux record header + payload into an existing buffer (avoids extra allocation).
pub fn write_mux_record_to(buf: &mut Vec<u8>, stream_id: u32, flags: u8, payload: &[u8]) {
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.push(flags);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
}

fn mux_record_header(data: &[u8]) -> anyhow::Result<(u32, u8)> {
    if data.len() < 9 {
        anyhow::bail!("short mux record");
    }
    let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let flags = data[4];
    let plen = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    let total = 9usize.saturating_add(plen);
    if data.len() < total {
        anyhow::bail!("truncated mux payload");
    }
    if data.len() != total {
        anyhow::bail!("mux record length mismatch (trailing bytes)");
    }
    Ok((stream_id, flags))
}

pub fn decode_mux_record(data: &[u8]) -> anyhow::Result<(u32, u8, Vec<u8>)> {
    let (sid, flags) = mux_record_header(data)?;
    Ok((sid, flags, data[9..].to_vec()))
}

/// Slice a validated mux record; its payload retains the complete backing allocation.
pub fn decode_mux_record_bytes(data: bytes::Bytes) -> anyhow::Result<(u32, u8, bytes::Bytes)> {
    let (sid, flags) = mux_record_header(&data)?;
    Ok((sid, flags, data.slice(9..)))
}

pub fn decode_mux_open_target(payload: &[u8]) -> anyhow::Result<(String, u16)> {
    let (h, p, n) = crate::protocol::decode_atyp_host_port(payload)?;
    if n != payload.len() {
        anyhow::bail!("trailing junk in mux open target");
    }
    Ok((h, p))
}

pub fn encode_mux_open_target(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let mut v = Vec::new();
    encode_atyp_host_port(host, port, &mut v)?;
    Ok(v)
}

#[derive(Clone)]
pub struct MuxClientConfig {
    pub max_pad: u8,
    pub decoy_max: u8,
    pub max_ws_binary: usize,
    pub ws_ping_secs: u64,
    pub ws_ping_jitter_percent: u8,
    pub ws_binary_send_jitter_ms: u8,
    /// Outbound delay range in ms; when both 0, only `ws_binary_send_jitter_ms` is used.
    pub ws_jitter_min_ms: u8,
    pub ws_jitter_max_ms: u8,
    /// BibaV2 AEAD outer framing (set from `spawn_tcp_mux_client`).
    pub transport_v2: bool,
    pub pad_mode: PadMode,
    /// Idle empty padded frames on the shared mux WSS (0 = off).
    pub dummy_interval_secs: u64,
    /// When set, update on each mux read/write of payload (for idle decoy, etc.).
    pub activity: Option<Arc<crate::activity::ActivityTracker>>,
}

impl MuxClientConfig {
    fn send_jitter(&self) -> WsSendJitter {
        WsSendJitter {
            min_ms: self.ws_jitter_min_ms,
            max_ms: self.ws_jitter_max_ms,
            legacy_0_to_max: self.ws_binary_send_jitter_ms,
        }
    }
}

/// `open_stream` failed before the bridge task was spawned; the socket can be retried.
pub struct MuxOpenStreamDropped {
    pub local: TcpStream,
    pub err: anyhow::Error,
}

/// A shared, byte-bounded mux session.
#[derive(Clone)]
pub struct TcpMuxClientHandle {
    endpoint: Arc<flow::Endpoint>,
}

impl TcpMuxClientHandle {
    pub async fn open_stream(
        &self,
        local: TcpStream,
        host: String,
        port: u16,
        tcp_uplink_prefix: Vec<u8>,
    ) -> Result<(), MuxOpenStreamDropped> {
        self.endpoint
            .open_stream(local, host, port, tcp_uplink_prefix)
            .await
    }
}

static TCP_MUX_SESSION_GEN: AtomicU64 = AtomicU64::new(1);

/// One or more parallel client→server WSS links, each a full `MUX_OPEN` session (round-robin `open_stream`).
pub struct TcpMuxSessionPool {
    pub sessions: Arc<Mutex<Vec<(u64, TcpMuxClientHandle)>>>,
    next: AtomicUsize,
}

impl TcpMuxSessionPool {
    pub fn new_empty() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Vec::new())),
            next: AtomicUsize::new(0),
        }
    }

    pub fn from_sessions(sessions: Vec<(u64, TcpMuxClientHandle)>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(sessions)),
            next: AtomicUsize::new(0),
        }
    }

    /// `None` if every outer WSS session has been torn down but the slot was not yet cleared.
    pub async fn pick(&self) -> Option<TcpMuxClientHandle> {
        let g = self.sessions.lock().await;
        let n = g.len();
        if n == 0 {
            return None;
        }
        let i = self.next.fetch_add(1, Ordering::Relaxed) % n;
        Some(g[i].1.clone())
    }
}

pub type TcpMuxClientSlot = Arc<tokio::sync::Mutex<Option<TcpMuxSessionPool>>>;

/// Remove one dead outer WSS; clear slot if that was the last session.
pub async fn remove_mux_session(slot: &TcpMuxClientSlot, session_id: u64) {
    let mut g = slot.lock().await;
    let Some(pool) = g.as_mut() else {
        return;
    };
    let mut v = pool.sessions.lock().await;
    let before = v.len();
    v.retain(|(id, _)| *id != session_id);
    if v.is_empty() {
        drop(v);
        *g = None;
        info!("tcp mux: all {before} session(s) ended; slot cleared for reconnect");
    } else {
        info!(
            "tcp mux session {session_id} closed; {} session(s) remain",
            v.len()
        );
    }
}

/// Server: after `MUX_OPEN`, dispatch logical streams.
pub async fn bridge_ws_tcp_mux_server<S>(
    ws: WebSocketStream<S>,
    max_pad: u8,
    decoy_max: u8,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    ws_jitter_min_ms: u8,
    ws_jitter_max_ms: u8,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
    server_out_timing: ServerWsOutTiming,
    mux_connect_timeout: Duration,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let cfg = MuxClientConfig {
        max_pad,
        decoy_max,
        max_ws_binary,
        ws_ping_secs,
        ws_ping_jitter_percent,
        ws_binary_send_jitter_ms,
        ws_jitter_min_ms,
        ws_jitter_max_ms,
        transport_v2: crypto.is_some(),
        pad_mode,
        dummy_interval_secs,
        activity: None,
    };
    let endpoint = flow::Endpoint::new(false, cfg, server_out_timing);
    endpoint.run(ws, crypto, None, mux_connect_timeout).await
}

/// After `MUX_OPEN`, start the reader/writer and negotiate flow control once per session.
pub fn spawn_tcp_mux_client<S>(
    ws: WebSocketStream<S>,
    crypto: Option<SharedCrypto>,
    mut cfg: MuxClientConfig,
    tcp_mux_slot: TcpMuxClientSlot,
    shutdown: watch::Receiver<bool>,
    tasks: &mut Vec<JoinHandle<()>>,
) -> (u64, TcpMuxClientHandle)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let session_id = TCP_MUX_SESSION_GEN.fetch_add(1, Ordering::Relaxed);
    cfg.transport_v2 = crypto.is_some();
    let endpoint = flow::Endpoint::new(true, cfg, ServerWsOutTiming::default());
    let running = endpoint.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(e) = running
            .run(ws, crypto, Some(shutdown), Duration::from_secs(10))
            .await
        {
            tracing::debug!(target: "bibavpn_mux", session_id, "mux session ended: {e:#}");
        }
        remove_mux_session(&tcp_mux_slot, session_id).await;
    }));
    (session_id, TcpMuxClientHandle { endpoint })
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn bytes_mux_decoder_preserves_backing_and_validates_lengths() {
        let wire = bytes::Bytes::from(encode_mux_record(7, MUX_FLAG_DATA, b"payload"));
        let start = wire.as_ptr().wrapping_add(9);
        let (sid, flags, payload) = decode_mux_record_bytes(wire.clone()).unwrap();
        assert_eq!((sid, flags), (7, MUX_FLAG_DATA));
        assert_eq!(payload.as_ref(), b"payload");
        assert_eq!(payload.as_ptr(), start);
        assert!(decode_mux_record_bytes(wire.slice(..wire.len() - 1)).is_err());
        assert!(decode_mux_record_bytes(bytes::Bytes::from_static(&[0; 8])).is_err());
        let empty = bytes::Bytes::from(encode_mux_record(1, MUX_FLAG_CLOSE, b""));
        assert!(decode_mux_record_bytes(empty).unwrap().2.is_empty());
        let mut extra = wire.to_vec();
        extra.push(0);
        assert!(decode_mux_record_bytes(extra.into()).is_err());
    }

    #[test]
    fn mux_record_rejects_trailing() {
        let mut v = encode_mux_record(3, MUX_FLAG_DATA, b"abc");
        v.push(9);
        assert!(decode_mux_record(&v).is_err());
    }

    #[test]
    fn mux_record_roundtrip() {
        let v = encode_mux_record(9, MUX_FLAG_OPEN, b"");
        let (sid, f, pl) = decode_mux_record(&v).unwrap();
        assert_eq!(sid, 9);
        assert_eq!(f, MUX_FLAG_OPEN);
        assert!(pl.is_empty());
    }
}

#[cfg(test)]
mod pick_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mirrors `TcpMuxSessionPool::pick` index logic (round-robin over n parallel outer WSS).
    fn rr_index(next: &AtomicUsize, n: usize) -> usize {
        next.fetch_add(1, Ordering::Relaxed) % n
    }

    #[test]
    fn round_robin_indices_cycle() {
        let next = AtomicUsize::new(0);
        let n = 3;
        let mut out = Vec::new();
        for _ in 0..9 {
            out.push(rr_index(&next, n));
        }
        assert_eq!(out, vec![0, 1, 2, 0, 1, 2, 0, 1, 2]);
    }
}

#[cfg(test)]
mod open_target_tests {
    use super::*;

    #[test]
    fn mux_open_target_domain_ipv4_ipv6() {
        for (host, port) in [
            ("example.com", 443u16),
            ("127.0.0.1", 8080),
            ("::1", 8443),
            ("2001:db8::53", 53),
        ] {
            let pl = encode_mux_open_target(host, port).unwrap();
            let (h, p) = decode_mux_open_target(&pl).unwrap();
            assert_eq!(h, host, "host {host}");
            assert_eq!(p, port, "port for {host}");
        }
    }

    #[test]
    fn mux_open_target_rejects_trailing() {
        let mut pl = encode_mux_open_target("h", 1).unwrap();
        pl.push(0);
        assert!(decode_mux_open_target(&pl).is_err());
    }

    #[test]
    fn mux_record_large_payload_roundtrip() {
        let payload = vec![0xABu8; 4096];
        let wire = encode_mux_record(99, MUX_FLAG_DATA, &payload);
        let (sid, flags, out) = decode_mux_record(&wire).unwrap();
        assert_eq!(sid, 99);
        assert_eq!(flags, MUX_FLAG_DATA);
        assert_eq!(out, payload);
    }
}
