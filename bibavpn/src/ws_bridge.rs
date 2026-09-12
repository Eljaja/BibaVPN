//! Shared WebSocket ↔ TCP bridge: BibaV2 seals, padded frames, MTU cap, optional WS ping (v2.1).

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use std::collections::VecDeque;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::crypto_layer::SessionCrypto;
use crate::frame::{AdaptivePadState, PadMode};
use crate::protocol::{decode_open_err, decode_v3_open_err, is_open_ok, is_v3_open_ok};
use crate::retry::{
    maybe_server_ack_and_rtt_mask, maybe_ws_send_jitter, ws_ping_period_duration,
    ServerWsOutTiming, WsSendJitter,
};
use crate::{read_padded_frame_borrow, read_padded_frame_into, write_padded_frame_with_mode_state};

pub type SharedCrypto = Arc<SessionCrypto>;

/// Prefetched WS downlink items for `bridge_ws_tcp_padded` (legacy `--no-mux` open wait).
#[derive(Debug)]
pub enum WsBridgePrefetch {
    /// Control / non-binary frames passed through unchanged.
    Ws(Message),
    /// Server→client payload already AEAD-opened and unpadded; write to TCP as-is.
    OpenedPayload(Vec<u8>),
}

/// After client-side AEAD open + unpad: drop v3 `OPEN_OK`, fail on v3 `OPEN_ERR`.
fn filter_client_downlink(inner: &[u8]) -> anyhow::Result<Option<&[u8]>> {
    if is_v3_open_ok(inner) {
        return Ok(None);
    }
    if let Ok(err) = decode_v3_open_err(inner) {
        anyhow::bail!("remote OPEN failed: {err}");
    }
    Ok(Some(inner))
}

#[derive(Clone, Copy, Debug)]
pub enum TunnelEnd {
    /// Client binary to server uses seal_client_to_server; server→client uses open_server_to_client.
    Client,
    /// Server binary to client uses seal_server_to_client; client→server uses open_client_to_server.
    Server,
}

/// Bytes already read from the client TCP socket (e.g. TLS after HTTP CONNECT) before bridging.
struct PrefixedRead {
    prefix: Cursor<Vec<u8>>,
    inner: OwnedReadHalf,
}

impl AsyncRead for PrefixedRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pos = self.prefix.position() as usize;
        let pref = self.prefix.get_ref();
        if pos < pref.len() {
            let rest = &pref[pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

enum BridgedTcpRead {
    Plain(OwnedReadHalf),
    Prefixed(PrefixedRead),
}

impl AsyncRead for BridgedTcpRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            BridgedTcpRead::Plain(r) => Pin::new(r).poll_read(cx, buf),
            BridgedTcpRead::Prefixed(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

/// Bridge after OPEN: TCP ↔ WebSocket padded binary (optional BibaV2 AEAD).
///
/// `tcp_uplink_prefix`: data already consumed from the client socket (forward before reading more).
///
/// `dummy_interval_secs`: send empty padded frames on idle (0 = off); interval jittered ±50% around this base.
///
/// `server_out_timing`: server-only; extra delay before each WS binary toward the client (ignored for `TunnelEnd::Client`).
pub async fn bridge_ws_tcp_padded<S>(
    ws: WebSocketStream<S>,
    prefetched_ws_messages: Vec<WsBridgePrefetch>,
    tcp: TcpStream,
    tcp_uplink_prefix: Vec<u8>,
    max_pad: u8,
    decoy_max: u8,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    ws_jitter_min_ms: u8,
    ws_jitter_max_ms: u8,
    end: TunnelEnd,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
    server_out_timing: ServerWsOutTiming,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let send_jitter = WsSendJitter {
        min_ms: ws_jitter_min_ms,
        max_ms: ws_jitter_max_ms,
        legacy_0_to_max: ws_binary_send_jitter_ms,
    };
    let v2 = crypto.is_some();
    let max_chunk =
        crate::frame::max_tcp_payload_per_ws_message(v2, decoy_max, max_pad, max_ws_binary)
            .max(256);

    let (mut ws_sink, mut ws_rx) = ws.split();
    let mut prefetched_ws_messages: VecDeque<WsBridgePrefetch> = prefetched_ws_messages.into();

    // One writer owns the WebSocket sink; producers use an async channel (no Mutex on send path).
    const WS_OUT_CAP: usize = 512;
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Message>(WS_OUT_CAP);
    let ws_out_up = ws_out_tx.clone();
    let ws_out_dn = ws_out_tx.clone();
    let ws_out_dummy = ws_out_tx.clone();
    let (peer_closed_tx, mut peer_closed_rx) = oneshot::channel::<()>();

    let writer = async move {
        let ping_sleep = sleep(ws_ping_period_duration(
            ws_ping_secs,
            ws_ping_jitter_percent,
        ));
        tokio::pin!(ping_sleep);
        loop {
            let msg = tokio::select! {
                biased;
                _ = &mut peer_closed_rx => {
                    // Tungstenite queued the close reply while the reader handled
                    // Close. Flush it; application writes are no longer legal.
                    ws_sink.flush().await.context("ws close reply")?;
                    return Ok::<_, anyhow::Error>(());
                }
                m = ws_out_rx.recv() => m,
                _ = &mut ping_sleep, if ws_ping_secs > 0 => {
                    ws_sink.send(Message::Ping(bytes::Bytes::new())).await.context("ws ping")?;
                    ping_sleep.as_mut().reset(tokio::time::Instant::now()
                        + ws_ping_period_duration(ws_ping_secs, ws_ping_jitter_percent));
                    continue;
                }
            };
            let Some(mut msg) = msg else { break };
            loop {
                let closing = matches!(msg, Message::Close(_));
                ws_sink.feed(msg).await.context("ws feed")?;
                if closing {
                    // Close is queued after all TCP payload. Never feed anything
                    // after it (including concurrent dummy/Pong messages).
                    ws_sink.flush().await.context("ws close")?;
                    return Ok(());
                }
                match ws_out_rx.try_recv() {
                    Ok(next) => msg = next,
                    Err(_) => break,
                }
            }
            ws_sink.flush().await.context("ws flush")?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let (tcp_read, mut tcp_write): (OwnedReadHalf, OwnedWriteHalf) = tcp.into_split();
    let mut tcp_read = if tcp_uplink_prefix.is_empty() {
        BridgedTcpRead::Plain(tcp_read)
    } else {
        BridgedTcpRead::Prefixed(PrefixedRead {
            prefix: Cursor::new(tcp_uplink_prefix),
            inner: tcp_read,
        })
    };

    let crypto_up = crypto.clone();
    let up = async move {
        loop {
            let m = if let Some(item) = prefetched_ws_messages.pop_front() {
                match item {
                    WsBridgePrefetch::OpenedPayload(payload) => {
                        if !payload.is_empty() {
                            tcp_write.write_all(&payload).await?;
                        }
                        continue;
                    }
                    WsBridgePrefetch::Ws(m) => m,
                }
            } else {
                let Some(msg) = ws_rx.next().await else {
                    break;
                };
                match msg {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(anyhow::Error::from(e).context("websocket read"));
                    }
                }
            };
            match m {
                Message::Binary(b) => {
                    if is_open_ok(b.as_ref()) {
                        continue;
                    }
                    if let Ok(err) = decode_open_err(b.as_ref()) {
                        anyhow::bail!("remote OPEN failed: {err}");
                    }
                    if b.len() > max_ws_binary.saturating_mul(4) {
                        anyhow::bail!(
                            "oversized WS binary from peer (>{})",
                            max_ws_binary.saturating_mul(4)
                        );
                    }
                    match (&crypto_up, end) {
                        (Some(c), TunnelEnd::Client) => {
                            let raw = c.open_server_to_client(b.as_ref()).context("v2 open s2c")?;
                            let payload = read_padded_frame_into(raw).context("padded frame")?;
                            if let Some(tcp_payload) = filter_client_downlink(&payload)? {
                                if !tcp_payload.is_empty() {
                                    tcp_write.write_all(tcp_payload).await?;
                                }
                            }
                        }
                        (Some(c), TunnelEnd::Server) => {
                            let raw = c.open_client_to_server(b.as_ref()).context("v2 open c2s")?;
                            let payload = read_padded_frame_into(raw).context("padded frame")?;
                            if !payload.is_empty() {
                                tcp_write.write_all(&payload).await?;
                            }
                        }
                        (None, _) => {
                            let payload =
                                read_padded_frame_borrow(b.as_ref()).context("padded frame")?;
                            if !payload.is_empty() {
                                tcp_write.write_all(payload).await?;
                            }
                        }
                    }
                }
                Message::Ping(p) => {
                    ws_out_up.send(Message::Pong(p)).await.context("ws pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => {
                    break;
                }
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let crypto_dn = crypto.clone();
    let crypto_dum = crypto.clone();
    let st_out = server_out_timing;
    let st_dummy = server_out_timing;
    let down = async move {
        let read_cap = max_chunk.saturating_mul(8).min(512 * 1024).max(max_chunk);
        let mut buf = vec![0u8; read_cap];
        let mut wire = Vec::with_capacity(max_ws_binary.min(256 * 1024));
        let mut adaptive = AdaptivePadState::default();
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            while off < n {
                let take = (n - off).min(max_chunk);
                write_padded_frame_with_mode_state(
                    &mut wire,
                    &buf[off..off + take],
                    max_pad,
                    pad_mode,
                    Some(&mut adaptive),
                )
                .context("pack frame")?;
                let blob = match (&crypto_dn, end) {
                    (Some(c), TunnelEnd::Client) => {
                        bytes::Bytes::from(c.seal_client_to_server(&wire).context("v2 seal c2s")?)
                    }
                    (Some(c), TunnelEnd::Server) => {
                        bytes::Bytes::from(c.seal_server_to_client(&wire).context("v2 seal s2c")?)
                    }
                    (None, _) => bytes::Bytes::from(std::mem::take(&mut wire)),
                };
                if blob.len() > max_ws_binary {
                    anyhow::bail!(
                        "WS binary {} exceeds --max-ws-binary {} (lower MTU or max_pad/decoy)",
                        blob.len(),
                        max_ws_binary
                    );
                }
                // Do not apply RTT / WS send jitter to every large TCP chunk, or bulk up/download stalls.
                let bulk_chunk = take > 512;
                let bulk_s2c = matches!(end, TunnelEnd::Server) && bulk_chunk;
                let bulk_c2s = matches!(end, TunnelEnd::Client) && bulk_chunk;
                if !bulk_s2c {
                    if matches!(end, TunnelEnd::Server) {
                        maybe_server_ack_and_rtt_mask(st_out).await;
                    }
                    if !bulk_c2s {
                        maybe_ws_send_jitter(send_jitter).await;
                    }
                }
                ws_out_dn
                    .send(Message::Binary(blob))
                    .await
                    .context("websocket send queue")?;
                off += take;
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let dummy = async move {
        if dummy_interval_secs == 0 {
            return std::future::pending::<anyhow::Result<()>>().await;
        }
        let mut wire = Vec::with_capacity(max_ws_binary.min(256 * 1024));
        let mut adaptive_d = AdaptivePadState::default();
        loop {
            let lo = dummy_interval_secs
                .saturating_mul(1)
                .saturating_div(2)
                .max(1);
            let hi = dummy_interval_secs
                .saturating_mul(3)
                .saturating_div(2)
                .max(lo);
            let secs = rand::thread_rng().gen_range(lo..=hi);
            sleep(Duration::from_secs(secs)).await;
            wire.clear();
            if write_padded_frame_with_mode_state(
                &mut wire,
                &[],
                max_pad,
                pad_mode,
                Some(&mut adaptive_d),
            )
            .is_err()
            {
                continue;
            }
            let blob = match (&crypto_dum, end) {
                (Some(c), TunnelEnd::Client) => match c.seal_client_to_server(&wire) {
                    Ok(b) => bytes::Bytes::from(b),
                    Err(_) => continue,
                },
                (Some(c), TunnelEnd::Server) => match c.seal_server_to_client(&wire) {
                    Ok(b) => bytes::Bytes::from(b),
                    Err(_) => continue,
                },
                (None, _) => bytes::Bytes::from(std::mem::take(&mut wire)),
            };
            if blob.len() > max_ws_binary {
                continue;
            }
            if matches!(end, TunnelEnd::Server) {
                maybe_server_ack_and_rtt_mask(st_dummy).await;
            }
            maybe_ws_send_jitter(send_jitter).await;
            let _ = ws_out_dummy.send(Message::Binary(blob)).await;
        }
    };

    // Dedicated WSS has no directional FIN: TCP EOF closes the whole tunnel.
    // Mux handles TCP half-close separately. Keep the writer and reader running
    // during the close handshake so queued payload reaches TCP before teardown.
    const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
    tokio::pin!(writer, up, down, dummy);
    tokio::select! {
        result = &mut writer => result,
        result = &mut dummy => result,
        result = &mut up => {
            result?;
            let _ = peer_closed_tx.send(());
            timeout(CLOSE_TIMEOUT, &mut writer).await.context("WS close reply timed out")?
        }
        result = &mut down => {
            result?;
            let close = async {
                ws_out_tx.send(Message::Close(None)).await.context("queue WS close")
            };
            timeout(CLOSE_TIMEOUT, async {
                tokio::try_join!(close, writer, up).map(|_| ())
            }).await.context("WS close handshake timed out")?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::encode_v3_open_ok;
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::protocol::Role;

    async fn bridge_fixture(
        end: TunnelEnd,
        dummy_interval_secs: u64,
    ) -> (
        TcpStream,
        WebSocketStream<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        let (a, b) = tokio::io::duplex(1024);
        let (role, peer_role) = match end {
            TunnelEnd::Client => (Role::Client, Role::Server),
            TunnelEnd::Server => (Role::Server, Role::Client),
        };
        let ws = WebSocketStream::from_raw_socket(a, role, None).await;
        let peer = WebSocketStream::from_raw_socket(b, peer_role, None).await;
        let task = tokio::spawn(bridge_ws_tcp_padded(
            ws,
            Vec::new(),
            tcp,
            Vec::new(),
            0,
            0,
            None,
            16384,
            1,
            0,
            0,
            0,
            0,
            end,
            PadMode::Random,
            dummy_interval_secs,
            ServerWsOutTiming::default(),
        ));
        (local, peer, task)
    }

    #[tokio::test]
    async fn tcp_eof_flushes_payload_before_ws_close() {
        for (end, dummy) in [(TunnelEnd::Client, 0), (TunnelEnd::Server, 60)] {
            let (mut local, mut peer, task) = bridge_fixture(end, dummy).await;
            let payload = vec![0x5a; 1024 * 1024];
            timeout(Duration::from_secs(3), async {
                let upload = async {
                    local.write_all(&payload).await.unwrap();
                    local.shutdown().await.unwrap();
                };
                let download = async {
                    let mut received = Vec::new();
                    while let Some(message) = peer.next().await {
                        match message.unwrap() {
                            Message::Binary(data) => {
                                received.extend_from_slice(read_padded_frame_borrow(&data).unwrap())
                            }
                            Message::Close(_) => {
                                peer.flush().await.unwrap();
                                break;
                            }
                            Message::Ping(_) => peer.flush().await.unwrap(),
                            _ => {}
                        }
                    }
                    assert_eq!(received, payload, "TCP EOF truncated queued data");
                };
                tokio::join!(upload, download);
                task.await.unwrap().unwrap();
            })
            .await
            .expect("TCP EOF leaked the WSS bridge");
        }
    }

    #[tokio::test]
    async fn ws_close_finishes_idle_tcp_and_dummy_tasks() {
        let (mut local, mut peer, task) = bridge_fixture(TunnelEnd::Client, 60).await;
        timeout(Duration::from_secs(2), async {
            peer.send(Message::Close(None)).await.unwrap();
            assert!(matches!(
                peer.next().await.unwrap().unwrap(),
                Message::Close(_)
            ));
            task.await.unwrap().unwrap();
            assert_eq!(local.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await
        .expect("WS close left the TCP read or dummy timer alive");
    }

    #[tokio::test]
    async fn tcp_eof_bounds_wait_for_unresponsive_ws_peer() {
        let (mut local, _peer, task) = bridge_fixture(TunnelEnd::Client, 0).await;
        local.shutdown().await.unwrap();
        let result = timeout(Duration::from_secs(7), task)
            .await
            .expect("unresponsive peer retained the bridge")
            .unwrap();
        assert!(result.is_err(), "missing close reply must report a timeout");
    }

    #[test]
    fn late_v3_open_ok_filtered_from_client_downlink() {
        let inner = encode_v3_open_ok();
        assert!(filter_client_downlink(&inner).unwrap().is_none());
    }

    #[test]
    fn v3_open_err_on_client_downlink_fails() {
        use crate::protocol::encode_v3_open_err;
        let inner = encode_v3_open_err("late fail").unwrap();
        let err = filter_client_downlink(&inner).unwrap_err();
        assert!(err.to_string().contains("late fail"));
    }

    #[test]
    fn payload_passes_client_downlink_filter() {
        let data = b"hello";
        assert_eq!(filter_client_downlink(data).unwrap(), Some(data.as_slice()));
    }
}
