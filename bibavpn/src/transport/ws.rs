//! WebSocket-backed [`OuterMsg`] duplex (`WsConn`).

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// Subset of `tungstenite::Message` the tunnel uses on the outer path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OuterMsg {
    Data(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close,
}

impl OuterMsg {
    fn into_tungstenite(self) -> Message {
        match self {
            OuterMsg::Data(b) => Message::Binary(b),
            OuterMsg::Ping(b) => Message::Ping(b),
            OuterMsg::Pong(b) => Message::Pong(b),
            OuterMsg::Close => Message::Close(None),
        }
    }

    fn from_tungstenite(msg: Message) -> Option<Self> {
        match msg {
            Message::Binary(b) => Some(OuterMsg::Data(b)),
            Message::Ping(b) => Some(OuterMsg::Ping(b)),
            Message::Pong(b) => Some(OuterMsg::Pong(b)),
            Message::Close(_) => Some(OuterMsg::Close),
            _ => None,
        }
    }
}

/// WebSocket outer duplex; mux/handshake code speaks [`OuterMsg`], not `WebSocketStream`.
pub struct WsConn<S> {
    inner: WebSocketStream<S>,
}

impl<S> WsConn<S> {
    pub fn from_websocket(inner: WebSocketStream<S>) -> Self {
        Self { inner }
    }

    pub async fn close(
        &mut self,
        frame: Option<CloseFrame>,
    ) -> Result<(), tokio_tungstenite::tungstenite::Error>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.inner.close(frame).await
    }
}

impl<S> Stream for WsConn<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Item = Result<OuterMsg, tokio_tungstenite::tungstenite::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    if let Some(outer) = OuterMsg::from_tungstenite(msg) {
                        return Poll::Ready(Some(Ok(outer)));
                    }
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> Sink<OuterMsg> for WsConn<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: OuterMsg) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item.into_tungstenite())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    async fn ws_test_pair() -> (
        WsConn<tokio::net::TcpStream>,
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            accept_async(tcp).await.expect("accept ws")
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
            format!("ws://{addr}/"),
        )
        .expect("request");
        let (peer, _) = tokio_tungstenite::client_async(req, tcp)
            .await
            .expect("client ws");
        let raw = accept.await.expect("join");
        (WsConn::from_websocket(raw), peer)
    }

    #[tokio::test]
    async fn data_round_trip_matches_binary_payload() {
        let (mut conn, mut peer) = ws_test_pair().await;
        let payload = Bytes::from_static(b"proto3-mux-payload");
        peer.send(WsMessage::Binary(payload.clone()))
            .await
            .expect("peer send");
        let got = conn.next().await.expect("read").expect("ok");
        assert_eq!(got, OuterMsg::Data(payload));
        conn.send(OuterMsg::Data(Bytes::from_static(b"echo")))
            .await
            .expect("conn send");
        match peer.next().await.expect("peer read").expect("ok") {
            WsMessage::Binary(b) => assert_eq!(b.as_ref(), b"echo"),
            other => panic!("expected binary, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ping_pong_map_to_tungstenite() {
        let (mut conn, mut peer) = ws_test_pair().await;
        let ping = Bytes::from_static(b"ping-body");
        peer.send(WsMessage::Ping(ping.clone()))
            .await
            .expect("peer ping");
        assert_eq!(
            conn.next().await.expect("read").expect("ok"),
            OuterMsg::Ping(ping)
        );
        conn.send(OuterMsg::Pong(Bytes::from_static(b"pong-body")))
            .await
            .expect("conn pong");
        match peer.next().await.expect("peer read").expect("ok") {
            WsMessage::Pong(b) => assert_eq!(b.as_ref(), b"pong-body"),
            other => panic!("expected pong, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn peer_close_surfaces_as_outer_close() {
        let (mut conn, mut peer) = ws_test_pair().await;
        peer.close(None).await.expect("peer close");
        assert_eq!(
            conn.next().await.expect("read").expect("ok"),
            OuterMsg::Close
        );
    }

    #[tokio::test]
    async fn text_frames_are_dropped() {
        let (mut conn, mut peer) = ws_test_pair().await;
        peer.send(WsMessage::Text("ignored".into()))
            .await
            .expect("text");
        peer.send(WsMessage::Binary(Bytes::from_static(b"seen")))
            .await
            .expect("binary");
        assert_eq!(
            conn.next().await.expect("read").expect("ok"),
            OuterMsg::Data(Bytes::from_static(b"seen"))
        );
    }
}
