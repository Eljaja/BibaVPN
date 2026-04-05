//! Shared WebSocket ↔ TCP bridge: BibaV2 seals, padded frames, MTU cap, optional WS ping (v2.1).

use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{Interval, MissedTickBehavior, interval};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::crypto_layer::SessionCrypto;
use crate::{read_padded_frame, write_padded_frame};

pub type SharedCrypto = Arc<Mutex<SessionCrypto>>;

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
    end: TunnelEnd,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let v2 = crypto.is_some();
    let max_chunk = crate::frame::max_tcp_payload_per_ws_message(v2, decoy_max, max_pad, max_ws_binary)
        .max(256);

    let (ws_tx, mut ws_rx) = ws.split();
    let ws_tx = Arc::new(Mutex::new(ws_tx));
    let (tcp_read, mut tcp_write): (OwnedReadHalf, OwnedWriteHalf) = tcp.into_split();
    let mut tcp_read = if tcp_uplink_prefix.is_empty() {
        BridgedTcpRead::Plain(tcp_read)
    } else {
        BridgedTcpRead::Prefixed(PrefixedRead {
            prefix: Cursor::new(tcp_uplink_prefix),
            inner: tcp_read,
        })
    };

    let ws_tx_up = ws_tx.clone();
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
                            .lock()
                            .await
                            .open_server_to_client(b.as_ref())
                            .context("v2 open s2c")?,
                        (Some(c), TunnelEnd::Server) => c
                            .lock()
                            .await
                            .open_client_to_server(b.as_ref())
                            .context("v2 open c2s")?,
                        (None, _) => b.to_vec(),
                    };
                    let payload = read_padded_frame(&raw).context("padded frame")?;
                    if !payload.is_empty() {
                        tcp_write.write_all(&payload).await?;
                    }
                }
                Message::Ping(p) => {
                    let mut g = ws_tx_up.lock().await;
                    g.send(Message::Pong(p.clone())).await.context("ws pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let crypto_dn = crypto.clone();
    let ws_tx_dn = ws_tx.clone();
    let mut ping_tok: Option<Interval> = if ws_ping_secs > 0 {
        let mut i = interval(Duration::from_secs(ws_ping_secs));
        i.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Some(i)
    } else {
        None
    };

    let down = async move {
        let mut buf = vec![0u8; max_chunk];
        let mut wire = Vec::with_capacity(max_ws_binary.min(64 * 1024));
        loop {
            if let Some(ref mut ticker) = ping_tok {
                tokio::select! {
                    biased;
                    _ = ticker.tick() => {
                        let mut g = ws_tx_dn.lock().await;
                        g.send(Message::Ping(bytes::Bytes::new())).await.context("ws ping")?;
                    }
                    r = tcp_read.read(&mut buf) => {
                        let n = r?;
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
                                        c.lock()
                                            .await
                                            .seal_client_to_server(&wire)
                                            .context("v2 seal c2s")?,
                                    )
                                }
                                (Some(c), TunnelEnd::Server) => {
                                    bytes::Bytes::from(
                                        c.lock()
                                            .await
                                            .seal_server_to_client(&wire)
                                            .context("v2 seal s2c")?,
                                    )
                                }
                                (None, _) => bytes::Bytes::from(wire.clone()),
                            };
                            if blob.len() > max_ws_binary {
                                anyhow::bail!(
                                    "WS binary {} exceeds --max-ws-binary {} (lower MTU or max_pad/decoy)",
                                    blob.len(),
                                    max_ws_binary
                                );
                            }
                            let mut g = ws_tx_dn.lock().await;
                            g.send(Message::Binary(blob)).await.context("websocket send")?;
                            drop(g);
                            off += take;
                        }
                    }
                }
            } else {
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
                                c.lock()
                                    .await
                                    .seal_client_to_server(&wire)
                                    .context("v2 seal c2s")?,
                            )
                        }
                        (Some(c), TunnelEnd::Server) => {
                            bytes::Bytes::from(
                                c.lock()
                                    .await
                                    .seal_server_to_client(&wire)
                                    .context("v2 seal s2c")?,
                            )
                        }
                        (None, _) => bytes::Bytes::from(wire.clone()),
                    };
                    if blob.len() > max_ws_binary {
                        anyhow::bail!(
                            "WS binary {} exceeds --max-ws-binary {}",
                            blob.len(),
                            max_ws_binary
                        );
                    }
                    let mut g = ws_tx_dn.lock().await;
                    g.send(Message::Binary(blob)).await.context("websocket send")?;
                    drop(g);
                    off += take;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(up, down)?;
    Ok(())
}
