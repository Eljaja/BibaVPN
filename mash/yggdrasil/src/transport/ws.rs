//! WebSocket transport primitives (ws:// and, with TLS, wss://).
//!
//! Provides a WebSocket handshake over an already-connected byte stream and a
//! `WsStream` adapter that exposes the binary-framed WebSocket connection as a
//! plain `AsyncRead + AsyncWrite` byte stream for the Yggdrasil handshake.
//! Wire-compatible with yggdrasil-go's ws/wss links (coder/websocket with the
//! `ygg-ws` subprotocol, one binary message per write).

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream as FuturesStream};
use ironwood::types::AsyncConn;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::tungstenite::Bytes;
use tokio_tungstenite::WebSocketStream;

pub(crate) const WS_SUBPROTOCOL: &str = "ygg-ws";

/// Upper bound for a single WebSocket message/frame. Legitimate peers send at
/// most one link-layer frame per message (ironwood caps those at 2×65535
/// bytes), so 256 KiB is comfortably above anything real while keeping the
/// pre-authentication memory an attacker can pin per connection small.
/// (tungstenite's defaults are 64 MiB / 16 MiB; yggdrasil-go disables the
/// limit entirely, so a tighter cap here does not hurt interop.)
const MAX_WS_MESSAGE_SIZE: usize = 256 * 1024;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_MESSAGE_SIZE))
}

/// Perform a WebSocket client handshake over an already-connected stream
/// (plain TCP for ws://, or a TLS stream for wss://).
pub(crate) async fn ws_client_handshake(
    stream: Box<dyn AsyncConn>,
    host: &str,
    port: u16,
    path: &str,
    remote_addr: SocketAddr,
    peer_cert: Option<CertificateDer<'static>>,
) -> Result<WsStream, String> {
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;
    use tokio_tungstenite::tungstenite::http::{Request, Uri};

    // IPv6 addresses must be bracketed in URIs and Host headers
    let authority = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    // Honor the peer URL's path (e.g. `/yws` when behind a reverse proxy).
    // Empty path falls back to root.
    let path = if path.is_empty() { "/" } else { path };
    let ws_url = format!("ws://{}{}", authority, path);
    let uri: Uri = ws_url
        .parse()
        .map_err(|e| format!("invalid WS URI: {}", e))?;

    let request = Request::builder()
        .uri(&uri)
        .header("Host", &authority)
        .header("Sec-WebSocket-Protocol", WS_SUBPROTOCOL)
        .header("Sec-WebSocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .body(())
        .map_err(|e| format!("build request: {}", e))?;

    let (ws_stream, _response) =
        tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config()))
            .await
            .map_err(|e| format!("WebSocket handshake failed: {}", e))?;

    Ok(WsStream::new(ws_stream, remote_addr, peer_cert))
}

/// Perform a WebSocket server handshake, requiring the Yggdrasil subprotocol
/// (like yggdrasil-go). Also answers `/health` and `/healthz` with a plain
/// HTTP 200 so the listener can sit behind a load balancer's health checks.
pub(crate) async fn ws_server_handshake(
    stream: Box<dyn AsyncConn>,
    remote_addr: SocketAddr,
    peer_cert: Option<CertificateDer<'static>>,
) -> Result<WsStream, String> {
    use tokio_tungstenite::tungstenite::handshake::server::{
        ErrorResponse, Request as WsRequest, Response as WsResponse,
    };
    use tokio_tungstenite::tungstenite::http::StatusCode;

    let callback =
        |req: &WsRequest, mut response: WsResponse| -> Result<WsResponse, ErrorResponse> {
            // Health check endpoint
            let path = req.uri().path();
            if path == "/health" || path == "/healthz" {
                let mut resp = ErrorResponse::new(Some("OK".to_string()));
                *resp.status_mut() = StatusCode::OK;
                return Err(resp);
            }

            let has_subprotocol = req
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').any(|s| s.trim() == WS_SUBPROTOCOL))
                .unwrap_or(false);

            if !has_subprotocol {
                let mut resp = ErrorResponse::new(Some(format!(
                    "client must speak the {} subprotocol",
                    WS_SUBPROTOCOL
                )));
                *resp.status_mut() = StatusCode::BAD_REQUEST;
                return Err(resp);
            }

            response.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                WS_SUBPROTOCOL.parse().expect("valid header value"),
            );
            Ok(response)
        };

    let ws_stream =
        tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config()))
            .await
            .map_err(|e| format!("WebSocket handshake failed: {}", e))?;

    Ok(WsStream::new(ws_stream, remote_addr, peer_cert))
}

/// Adapts a type-erased WebSocket stream to AsyncRead + AsyncWrite.
///
/// Translates between WebSocket binary message framing and byte-stream
/// semantics: reads buffer incoming binary messages and serve bytes
/// sequentially; each write becomes one binary WebSocket message.
///
/// No internal locking: ironwood consumes the link through `tokio::io::split`,
/// which already serializes all `poll_*` calls on the underlying stream.
pub(crate) struct WsStream {
    ws: WebSocketStream<Box<dyn AsyncConn>>,
    /// Unconsumed tail of the last binary message.
    read_buf: Bytes,
    read_pos: usize,
    remote_addr: SocketAddr,
    /// TLS certificate of the peer (wss only), for cert/identity binding.
    peer_cert: Option<CertificateDer<'static>>,
}

impl WsStream {
    fn new(
        ws: WebSocketStream<Box<dyn AsyncConn>>,
        remote_addr: SocketAddr,
        peer_cert: Option<CertificateDer<'static>>,
    ) -> Self {
        Self {
            ws,
            read_buf: Bytes::new(),
            read_pos: 0,
            remote_addr,
            peer_cert,
        }
    }

    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub(crate) fn peer_cert(&self) -> Option<&CertificateDer<'static>> {
        self.peer_cert.as_ref()
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Serve from the buffered message first
        if this.read_pos < this.read_buf.len() {
            let remaining = &this.read_buf[this.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.read_pos += to_copy;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf = Bytes::new();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match Pin::new(&mut this.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        let to_copy = data.len().min(buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        if to_copy < data.len() {
                            this.read_buf = data;
                            this.read_pos = to_copy;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    // Peer closed cleanly — report EOF (0 bytes read)
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    // Skip non-binary messages (ping/pong handled by tungstenite)
                    _ => continue,
                },
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e)))
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // Stream ended
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::Binary(Bytes::copy_from_slice(buf));
                match Pin::new(&mut this.ws).start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.ws)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.ws)
            .poll_close(cx)
            .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn duplex_pair() -> (Box<dyn AsyncConn>, Box<dyn AsyncConn>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Box::new(a), Box::new(b))
    }

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    /// Handshake + byte round-trip over an in-memory pipe, including a
    /// message larger than the read buffer (exercises the leftover buffer).
    #[tokio::test]
    async fn test_ws_roundtrip() {
        let (client_io, server_io) = duplex_pair();

        let server = tokio::spawn(async move {
            ws_server_handshake(server_io, dummy_addr(), None)
                .await
                .expect("server handshake")
        });
        let mut client = ws_client_handshake(client_io, "127.0.0.1", 1, "/", dummy_addr(), None)
            .await
            .expect("client handshake");
        let mut server = server.await.unwrap();

        // Write and read concurrently: the payload exceeds the duplex pipe's
        // buffer, so a sequential write-then-read would deadlock.
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut received = vec![0u8; payload.len()];
        let (write_res, read_res) = tokio::join!(
            async {
                client.write_all(&payload).await?;
                client.flush().await
            },
            server.read_exact(&mut received),
        );
        write_res.unwrap();
        read_res.unwrap();
        assert_eq!(received, payload);

        // And the other direction (small, fits in the pipe buffer)
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
    }

    /// The server must reject clients that do not offer the ygg-ws subprotocol.
    #[tokio::test]
    async fn test_ws_server_requires_subprotocol() {
        use tokio_tungstenite::tungstenite::handshake::client::generate_key;
        use tokio_tungstenite::tungstenite::http::Request;

        let (client_io, server_io) = duplex_pair();
        let server = tokio::spawn(async move {
            ws_server_handshake(server_io, dummy_addr(), None).await
        });

        // Plain WebSocket client without Sec-WebSocket-Protocol
        let request = Request::builder()
            .uri("ws://127.0.0.1:1/")
            .header("Host", "127.0.0.1:1")
            .header("Sec-WebSocket-Key", generate_key())
            .header("Sec-WebSocket-Version", "13")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .body(())
            .unwrap();
        let client_result = tokio_tungstenite::client_async(request, client_io).await;

        assert!(client_result.is_err(), "client without subprotocol must be rejected");
        assert!(server.await.unwrap().is_err());
    }

    /// Oversized messages from a non-conforming client must terminate the
    /// connection instead of being buffered by the server.
    #[tokio::test]
    async fn test_ws_message_size_limit() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::handshake::client::generate_key;
        use tokio_tungstenite::tungstenite::http::Request;

        let (client_io, server_io) = duplex_pair();

        let server = tokio::spawn(async move {
            ws_server_handshake(server_io, dummy_addr(), None)
                .await
                .expect("server handshake")
        });
        // Raw tungstenite client with default (64 MiB) limits, so it happily
        // sends a message our server must reject.
        let request = Request::builder()
            .uri("ws://127.0.0.1:1/")
            .header("Host", "127.0.0.1:1")
            .header("Sec-WebSocket-Protocol", WS_SUBPROTOCOL)
            .header("Sec-WebSocket-Key", generate_key())
            .header("Sec-WebSocket-Version", "13")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .body(())
            .unwrap();
        let (mut raw_client, _) = tokio_tungstenite::client_async(request, client_io)
            .await
            .expect("client handshake");
        let mut server = server.await.unwrap();

        // The sender runs detached: the server rejects the frame from its
        // header without draining the payload, so the send may block forever
        // on pipe backpressure and must not be awaited.
        let writer = tokio::spawn(async move {
            let oversized = vec![0u8; MAX_WS_MESSAGE_SIZE + 1];
            let _ = raw_client.send(Message::Binary(Bytes::from(oversized))).await;
        });

        let mut buf = vec![0u8; 1024];
        let read_res =
            tokio::time::timeout(std::time::Duration::from_secs(5), server.read(&mut buf))
                .await
                .expect("server must reject the oversized message promptly");
        // Either an explicit error or EOF — never the oversized payload.
        match read_res {
            Ok(n) => assert_eq!(n, 0, "oversized message must not be delivered"),
            Err(_) => {}
        }
        writer.abort();
    }
}
