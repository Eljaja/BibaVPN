//! Shared WebSocket ↔ TCP bridge: BibaV2 seals, padded frames, MTU cap, optional WS ping (v2.1).

use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::crypto_layer::SessionCrypto;
use crate::retry::{maybe_ws_binary_send_jitter, ws_ping_period_duration};
use crate::{read_padded_frame, write_padded_frame};

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
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            BridgedTcpRead::Plain(r) => Pin::new(r).poll_read(cx, buf),
            BridgedTcpRead::Prefixed(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

/// Bridge after OPEN: TCP ↔ WebSocket padded binary (optional BibaV2 AEAD).
///
/// `tcp_uplink_prefix`: data already consumed from the client socket (forward before reading more).
pub async fn bridge_ws_tcp_padded<S>(
    ws: WebSocketStream<S>,
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
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let v2 = crypto.is_some();
    let max_chunk = crate::frame::max_tcp_payload_per_ws_message(v2, decoy_max, max_pad, max_ws_binary)
        .max(256);

    let (mut ws_sink, mut ws_rx) = ws.split();

    // One writer owns the WebSocket sink; producers use an async channel (no Mutex on send path).
    const WS_OUT_CAP: usize = 256;
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Message>(WS_OUT_CAP);
    let ws_out_up = ws_out_tx.clone();
    let ws_out_dn = ws_out_tx.clone();
    drop(ws_out_tx);

    let writer = async move {
        let mut ping_sleep: Option<Pin<Box<tokio::time::Sleep>>> = if ws_ping_secs > 0 {
            Some(Box::pin(sleep(ws_ping_period_duration(ws_ping_secs, ws_ping_jitter_percent))))
        } else {
            None
        };
        loop {
            match ping_sleep.as_mut() {
                Some(sleep_pin) => {
                    tokio::select! {
                        m = ws_out_rx.recv() => {
                            match m {
                                None => break,
                                Some(msg) => {
                                    ws_sink.send(msg).await.context("websocket send")?;
                                }
                            }
                        }
                        _ = sleep_pin.as_mut() => {
                            ws_sink
                                .send(Message::Ping(bytes::Bytes::new()))
                                .await
                                .context("ws ping")?;
                            *sleep_pin = Box::pin(sleep(ws_ping_period_duration(
                                ws_ping_secs,
                                ws_ping_jitter_percent,
                            )));
                        }
                    }
                }
                None => {
                    match ws_out_rx.recv().await {
                        None => break,
                        Some(msg) => {
                            ws_sink.send(msg).await.context("websocket send")?;
                        }
                    }
                }
            }
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
        while let Some(m) = ws_rx.next().await {
            let m = m.context("websocket read")?;
            match m {
                Message::Binary(b) => {
                    if b.len() > max_ws_binary.saturating_mul(4) {
                        anyhow::bail!("oversized WS binary from peer (>{})", max_ws_binary.saturating_mul(4));
                    }
                    let raw = match (&crypto_up, end) {
                        (Some(c), TunnelEnd::Client) => c
                            .open_server_to_client(b.as_ref())
                            .await
                            .context("v2 open s2c")?,
                        (Some(c), TunnelEnd::Server) => c
                            .open_client_to_server(b.as_ref())
                            .await
                            .context("v2 open c2s")?,
                        (None, _) => b.to_vec(),
                    };
                    let payload = read_padded_frame(&raw).context("padded frame")?;
                    if !payload.is_empty() {
                        tcp_write.write_all(&payload).await?;
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
                write_padded_frame(&mut wire, &buf[off..off + take], max_pad).context("pack frame")?;
                let blob = match (&crypto_dn, end) {
                    (Some(c), TunnelEnd::Client) => {
                        bytes::Bytes::from(
                            c.seal_client_to_server(&wire)
                                .await
                                .context("v2 seal c2s")?,
                        )
                    }
                    (Some(c), TunnelEnd::Server) => {
                        bytes::Bytes::from(
                            c.seal_server_to_client(&wire)
                                .await
                                .context("v2 seal s2c")?,
                        )
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

    tokio::try_join!(writer, up, down)?;
    Ok(())
}
