//! Unified async TLS stream for WSS: rustls (default) or BoringSSL (`--tls-stack boring` + feature `boring-tls`).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as RustlsTs;

/// `AsyncRead` + `AsyncWrite` over the main VPN outer TLS (before WebSocket).
pub enum ClientTlsStream {
    Rustls(RustlsTs<TcpStream>),
    #[cfg(feature = "boring-tls")]
    Boring(tokio_boring::SslStream<TcpStream>),
}

impl AsyncRead for ClientTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientTlsStream::Rustls(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "boring-tls")]
            ClientTlsStream::Boring(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ClientTlsStream::Rustls(s) => Pin::new(s).poll_write(cx, b),
            #[cfg(feature = "boring-tls")]
            ClientTlsStream::Boring(s) => Pin::new(s).poll_write(cx, b),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientTlsStream::Rustls(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "boring-tls")]
            ClientTlsStream::Boring(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientTlsStream::Rustls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "boring-tls")]
            ClientTlsStream::Boring(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
