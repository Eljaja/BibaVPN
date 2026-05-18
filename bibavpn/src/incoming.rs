//! First request on a TLS stream: WebSocket upgrade vs plain HTTP (camouflage).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

use crate::camouflage;

/// Same meaning as server bin `WsAcceptKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsHandshakeKind {
    NewPath,
    LegacyPath,
}

#[derive(Clone, Default)]
pub struct CamouflageServeConfig {
    pub static_dir: Option<PathBuf>,
    /// Plaintext reverse proxy origin only: `http://host:port` (no TLS to origin in this build).
    pub reverse_proxy: Option<String>,
}

/// Read HTTP headers, then either complete WebSocket handshake or serve camouflage HTTP.
pub async fn accept_websocket_or_camouflage<S>(
    mut stream: S,
    ws_path: &str,
    legacy_path_auth: bool,
    token: &str,
    camo: CamouflageServeConfig,
    peer: Option<SocketAddr>,
) -> anyhow::Result<Option<(WebSocketStream<S>, WsHandshakeKind)>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let buf = read_http_head(&mut stream).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let parsed = req.parse(&buf).context("parse http request")?;
    let header_len = match parsed {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => anyhow::bail!("incomplete http headers"),
    };

    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");

    let remainder = if header_len < buf.len() {
        buf[header_len..].to_vec()
    } else {
        Vec::new()
    };

    if is_websocket_upgrade(&req) {
        let kind = if path == ws_path {
            WsHandshakeKind::NewPath
        } else if legacy_path_auth {
            let legacy = format!("/b/{token}");
            if path == legacy.as_str() {
                WsHandshakeKind::LegacyPath
            } else {
                write_camouflage_status(&mut stream, 404, camouflage::NOT_FOUND_HTML).await?;
                return Ok(None);
            }
        } else {
            write_camouflage_status(&mut stream, 404, camouflage::NOT_FOUND_HTML).await?;
            return Ok(None);
        };

        let key = header_line(&req, "Sec-WebSocket-Key").context("websocket: missing key")?;
        let ver = header_line(&req, "Sec-WebSocket-Version").unwrap_or_else(|| "13".to_string());
        if ver != "13" {
            write_camouflage_status(&mut stream, 400, "bad websocket version\r\n").await?;
            return Ok(None);
        }
        let accept = derive_accept_key(key.as_bytes());
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: {accept}\r\n\
\r\n"
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;

        let mut ws_cfg = WebSocketConfig::default();
        ws_cfg.write_buffer_size = 256 * 1024;
        ws_cfg.max_write_buffer_size = 1024 * 1024;
        let ws =
            WebSocketStream::from_partially_read(stream, remainder, Role::Server, Some(ws_cfg))
                .await;
        return Ok(Some((ws, kind)));
    }

    // Plain HTTP
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        serve_camouflage_http(&mut stream, method, path, &camo, peer).await?;
    } else {
        write_camouflage_status(&mut stream, 405, camouflage::NOT_FOUND_HTML).await?;
    }
    Ok(None)
}

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        if buf.len() > 65536 {
            anyhow::bail!("http headers too large");
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("eof before http headers");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(buf)
}

fn is_websocket_upgrade(req: &httparse::Request<'_, '_>) -> bool {
    let up = header_line(req, "Upgrade");
    let conn = header_line(req, "Connection");
    let key = header_line(req, "Sec-WebSocket-Key");
    let Some(up) = up else {
        return false;
    };
    if !up.eq_ignore_ascii_case("websocket") {
        return false;
    }
    let Some(conn) = conn else {
        return false;
    };
    if !conn.to_ascii_lowercase().contains("upgrade") {
        return false;
    }
    key.is_some()
}

fn header_line<'h>(req: &httparse::Request<'_, 'h>, name: &str) -> Option<String> {
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case(name) {
            return std::str::from_utf8(h.value)
                .ok()
                .map(|s| s.trim().to_string());
        }
    }
    None
}

async fn write_camouflage_status<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    body: &str,
) -> anyhow::Result<()> {
    let reason = match code {
        404 => "Not Found",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let cl = body.as_bytes().len();
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\n\
Server: nginx/1.24.0\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: {cl}\r\n\
Connection: close\r\n\
\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_camouflage_http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    method: &str,
    path: &str,
    camo: &CamouflageServeConfig,
    peer: Option<SocketAddr>,
) -> anyhow::Result<()> {
    if let Some(origin) = camo.reverse_proxy.as_deref() {
        if let Err(e) = forward_http_get(stream, method, path, origin).await {
            tracing::warn!(
                target: "bibavpn_camouflage",
                ?peer,
                "camouflage reverse-proxy: {e:#}"
            );
            let (st, body) = camouflage::html_ok_index();
            write_html_response(stream, method, st.as_u16(), &body).await?;
        }
        return Ok(());
    }

    if let Some(dir) = camo.static_dir.as_deref() {
        match serve_static_file(dir, path).await {
            Some((st, ctype, body)) => {
                write_binary_response(stream, method, st, ctype, &body).await?;
                return Ok(());
            }
            None => {
                write_camouflage_status(stream, 404, camouflage::NOT_FOUND_HTML).await?;
                return Ok(());
            }
        }
    }

    // Default synthetic pages
    let path = path.split('?').next().unwrap_or(path);
    match path {
        "/" => {
            let (st, body) = camouflage::html_ok_index();
            write_html_response(stream, method, st.as_u16(), &body).await?;
        }
        "/robots.txt" => {
            let body = "User-agent: *\nDisallow:\n";
            write_binary_response(
                stream,
                method,
                200,
                "text/plain; charset=utf-8",
                body.as_bytes(),
            )
            .await?;
        }
        "/favicon.ico" => {
            write_binary_response(stream, method, 204, "image/x-icon", &[]).await?;
        }
        _ => {
            write_camouflage_status(stream, 404, camouflage::NOT_FOUND_HTML).await?;
        }
    }
    Ok(())
}

fn safe_static_path_under_base(base: &Path, url_path: &str) -> Option<std::path::PathBuf> {
    let base_canon = std::fs::canonicalize(base).ok()?;
    let p = url_path.split('?').next()?.trim_start_matches('/');
    let rel = if p.is_empty() || p.ends_with('/') {
        "index.html"
    } else {
        p
    };
    let mut out = base_canon.clone();
    for seg in rel.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg == ".." {
            return None;
        }
        out.push(seg);
    }
    if out.starts_with(&base_canon) {
        Some(out)
    } else {
        None
    }
}

async fn serve_static_file(dir: &Path, path: &str) -> Option<(u16, &'static str, Vec<u8>)> {
    let fs_path = safe_static_path_under_base(dir, path)?;
    let data = tokio::fs::read(&fs_path).await.ok()?;
    let ctype = guess_mime(fs_path.extension().and_then(|e| e.to_str()).unwrap_or(""));
    Some((200, ctype, data))
}

fn guess_mime(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        _ => "application/octet-stream",
    }
}

async fn write_html_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    method: &str,
    status: u16,
    body: &str,
) -> anyhow::Result<()> {
    write_binary_response(
        stream,
        method,
        status,
        "text/html; charset=utf-8",
        body.as_bytes(),
    )
    .await
}

async fn write_binary_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    method: &str,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        404 => "Not Found",
        _ => "OK",
    };
    let cl = body.len();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
Server: nginx/1.24.0\r\n\
Content-Type: {ctype}\r\n\
Content-Length: {cl}\r\n\
Connection: close\r\n\
Cache-Control: public, max-age=3600\r\n\
\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    if !method.eq_ignore_ascii_case("HEAD") {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Minimal GET forward to `http://host:port` origin (same path + query as client).
async fn forward_http_get<S: AsyncWrite + AsyncRead + Unpin>(
    client_tls: &mut S,
    method: &str,
    path: &str,
    origin: &str,
) -> anyhow::Result<()> {
    let uri = origin
        .parse::<http::Uri>()
        .context("camouflage-url parse")?;
    if uri.scheme_str() != Some("http") {
        anyhow::bail!("camouflage-url must be http://host:port (TLS to origin not implemented)");
    }
    let authority = uri.authority().context("camouflage-url: missing host")?;
    let host = authority.host();
    if host.is_empty() {
        anyhow::bail!("camouflage-url: empty host");
    }
    let port = authority.port_u16().unwrap_or(80);
    let host_header = authority.as_str();

    let mut upstream = tokio::net::TcpStream::connect((host, port))
        .await
        .context("camouflage upstream tcp")?;

    let req = format!(
        "{method} {path} HTTP/1.1\r\n\
Host: {host_header}\r\n\
Accept: */*\r\n\
Accept-Encoding: identity\r\n\
Connection: close\r\n\
\r\n",
        method = if method.eq_ignore_ascii_case("HEAD") {
            "HEAD"
        } else {
            "GET"
        },
        path = path,
        host_header = host_header,
    );
    upstream.write_all(req.as_bytes()).await?;

    let mut buf = vec![0u8; 65536];
    loop {
        let n = upstream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        client_tls.write_all(&buf[..n]).await?;
    }
    client_tls.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn guess_mime_common_extensions() {
        assert!(guess_mime("html").contains("text/html"));
        assert!(guess_mime("CSS").contains("text/css"));
        assert_eq!(guess_mime("bin"), "application/octet-stream");
    }

    #[test]
    fn safe_static_path_blocks_traversal() {
        let base = std::env::temp_dir().join(format!("bibavpn_incoming_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("index.html"), b"ok").unwrap();
        assert!(safe_static_path_under_base(&base, "/").is_some());
        assert!(safe_static_path_under_base(&base, "/../etc/passwd").is_none());
        assert!(safe_static_path_under_base(&base, "/subdir/../../outside").is_none());
        let _ = fs::remove_dir_all(&base);
    }
}
