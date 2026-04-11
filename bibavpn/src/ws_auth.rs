//! Wait for [`crate::protocol::AUTH_MAGIC`] after WebSocket upgrade (token not in URL).

use std::time::Duration;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::protocol::{decode_auth, is_auth_frame};

/// Read WebSocket messages until a valid AUTH frame matching `expected_token` or timeout.
/// Ignores non-AUTH binary frames (noise). Handles Ping/Pong.
pub async fn server_wait_token_auth<S>(
    ws: &mut WebSocketStream<S>,
    expected_token: &str,
    wait: Duration,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let fut = async {
        loop {
            let m = ws
                .next()
                .await
                .context("eof during auth wait")?
                .context("ws error during auth wait")?;
            match m {
                Message::Binary(b) => {
                    if is_auth_frame(b.as_ref()) {
                        let tok = decode_auth(b.as_ref())?;
                        if tok == expected_token {
                            return Ok::<_, anyhow::Error>(());
                        }
                        anyhow::bail!("auth token mismatch");
                    }
                }
                Message::Ping(p) => {
                    ws.send(Message::Pong(p)).await.context("pong during auth")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => anyhow::bail!("closed during auth"),
                _ => {}
            }
        }
    };
    match timeout(wait, fut).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!("auth timeout waiting for AUTH frame"),
    }
}
