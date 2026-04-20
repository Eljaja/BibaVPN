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
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::crypto_layer::SessionCrypto;
use crate::frame::PadMode;
use crate::protocol::{decode_open_err, is_open_ok};
use crate::retry::{maybe_ws_binary_send_jitter, ws_ping_period_duration};
use crate::{read_padded_frame_borrow, read_padded_frame_into, write_padded_frame_with_mode};

pub type SharedCrypto = Arc<SessionCrypto>;

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
pub async fn bridge_ws_tcp_padded<S>(
    ws: WebSocketStream<S>,
    prefetched_ws_messages: Vec<Message>,
    tcp: TcpStream,
    tcp_uplink_prefix: Vec<u8>,
    max_pad: u8,
    decoy_max: u8,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    end: TunnelEnd,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let v2 = crypto.is_some();
    let max_chunk =
        crate::frame::max_tcp_payload_per_ws_message(v2, decoy_max, max_pad, max_ws_binary)
            .max(256);

    let (mut ws_sink, mut ws_rx) = ws.split();
    let mut prefetched_ws_messages: VecDeque<Message> = prefetched_ws_messages.into();

    // One writer owns the WebSocket sink; producers use an async channel (no Mutex on send path).
    const WS_OUT_CAP: usize = 512;
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Message>(WS_OUT_CAP);
    let ws_out_up = ws_out_tx.clone();
    let ws_out_dn = ws_out_tx.clone();
    let ws_out_dummy = ws_out_tx.clone();
    drop(ws_out_tx);

    let writer = async move {
        let mut ping_sleep: Option<Pin<Box<tokio::time::Sleep>>> = if ws_ping_secs > 0 {
            Some(Box::pin(sleep(ws_ping_period_duration(
                ws_ping_secs,
                ws_ping_jitter_percent,
            ))))
        } else {
            None
        };
        loop {
            let msg = match ping_sleep.as_mut() {
                Some(sleep_pin) => {
                    tokio::select! {
                        m = ws_out_rx.recv() => m,
                        _ = sleep_pin.as_mut() => {
                            ws_sink
                                .send(Message::Ping(bytes::Bytes::new()))
                                .await
                                .context("ws ping")?;
                            *sleep_pin = Box::pin(sleep(ws_ping_period_duration(
                                ws_ping_secs,
                                ws_ping_jitter_percent,
                            )));
                            continue;
                        }
                    }
                }
                None => ws_out_rx.recv().await,
            };
            let Some(msg) = msg else { break };
            ws_sink.feed(msg).await.context("ws feed")?;
            while let Ok(msg) = ws_out_rx.try_recv() {
                ws_sink.feed(msg).await.context("ws feed")?;
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
            let m = if let Some(m) = prefetched_ws_messages.pop_front() {
                m
            } else {
                let Some(m) = ws_rx.next().await else { break };
                m.context("websocket read")?
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
                            let raw = c
                                .open_server_to_client(b.as_ref())
                                .context("v2 open s2c")?;
                            let payload = read_padded_frame_into(raw).context("padded frame")?;
                            if !payload.is_empty() {
                                tcp_write.write_all(&payload).await?;
                            }
                        }
                        (Some(c), TunnelEnd::Server) => {
                            let raw = c
                                .open_client_to_server(b.as_ref())
                                .context("v2 open c2s")?;
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
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let crypto_dn = crypto.clone();
    let crypto_dum = crypto.clone();
    let down = async move {
        let read_cap = max_chunk.saturating_mul(8).min(512 * 1024).max(max_chunk);
        let mut buf = vec![0u8; read_cap];
        let mut wire = Vec::with_capacity(max_ws_binary.min(256 * 1024));
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut off = 0usize;
            while off < n {
                let take = (n - off).min(max_chunk);
                write_padded_frame_with_mode(&mut wire, &buf[off..off + take], max_pad, pad_mode)
                    .context("pack frame")?;
                let blob = match (&crypto_dn, end) {
                    (Some(c), TunnelEnd::Client) => bytes::Bytes::from(
                        c.seal_client_to_server(&wire)
                            .context("v2 seal c2s")?,
                    ),
                    (Some(c), TunnelEnd::Server) => bytes::Bytes::from(
                        c.seal_server_to_client(&wire)
                            .context("v2 seal s2c")?,
                    ),
                    (None, _) => bytes::Bytes::from(std::mem::take(&mut wire)),
                };
                if blob.len() > max_ws_binary {
                    anyhow::bail!(
                        "WS binary {} exceeds --max-ws-binary {} (lower MTU or max_pad/decoy)",
                        blob.len(),
                        max_ws_binary
                    );
                }
                maybe_ws_binary_send_jitter(ws_binary_send_jitter_ms).await;
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
            return Ok::<_, anyhow::Error>(());
        }
        let mut wire = Vec::with_capacity(max_ws_binary.min(256 * 1024));
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
            if write_padded_frame_with_mode(&mut wire, &[], max_pad, pad_mode).is_err() {
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
            maybe_ws_binary_send_jitter(ws_binary_send_jitter_ms).await;
            let _ = ws_out_dummy.send(Message::Binary(blob)).await;
        }
    };

    tokio::try_join!(writer, up, down, dummy)?;
    Ok(())
}
