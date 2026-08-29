//! First request on a TLS stream: WebSocket upgrade vs plain HTTP (camouflage).

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;

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
) -> anyhow::Result<Option<(WebSocketStream<S>, WsHandshakeKind, Option<String>)>>
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
            if crate::crypto_layer::secret_eq(path, legacy.as_str()) {
                WsHandshakeKind::LegacyPath
            } else {
                write_camouflage_status(&mut stream, 404).await?;
                return Ok(None);
            }
        } else {
            write_camouflage_status(&mut stream, 404).await?;
            return Ok(None);
        };

        let key = header_line(&req, "Sec-WebSocket-Key").context("websocket: missing key")?;
        let http_host = header_line(&req, "Host");
        let ver = header_line(&req, "Sec-WebSocket-Version").unwrap_or_else(|| "13".to_string());
        if ver != "13" {
            write_camouflage_status(&mut stream, 400).await?;
            return Ok(None);
        }
        let accept = derive_accept_key(key.as_bytes());
        // nginx proxying a WebSocket upgrade emits Server, Date, then the
        // lowercase `Connection: upgrade` it synthesises for 101, then the
        // upstream's own headers. Order and `Date` are both fingerprints.
        let date = camouflage::http_date_now();
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
Server: {server}\r\n\
Date: {date}\r\n\
Connection: upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Accept: {accept}\r\n\
\r\n",
            server = camouflage::SERVER_TOKEN,
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;

        let mut ws_cfg = WebSocketConfig::default();
        ws_cfg.write_buffer_size = 256 * 1024;
        ws_cfg.max_write_buffer_size = 1024 * 1024;
        let ws =
            WebSocketStream::from_partially_read(stream, remainder, Role::Server, Some(ws_cfg))
                .await;
        return Ok(Some((ws, kind, http_host)));
    }

    // Plain HTTP
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        let range = header_line(&req, "Range");
        let camo_req = CamoRequest {
            method,
            path,
            range: range.as_deref(),
        };
        serve_camouflage_http(&mut stream, camo_req, &camo, peer).await?;
    } else {
        write_camouflage_status(&mut stream, 405).await?;
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

/// The parts of the client request the camouflage responses depend on.
#[derive(Clone, Copy, Debug, Default)]
struct CamoRequest<'a> {
    method: &'a str,
    path: &'a str,
    range: Option<&'a str>,
}

impl CamoRequest<'_> {
    fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }
}

/// What nginx knows about a file on disk: drives `Last-Modified`, `ETag`, ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileMeta {
    mtime_secs: u64,
    len: u64,
}

/// nginx's `ngx_http_set_etag` format: `"%xT-%xO"` (hex mtime, hex size), strong.
fn nginx_etag(meta: FileMeta) -> String {
    format!("\"{:x}-{:x}\"", meta.mtime_secs, meta.len)
}

/// Synthetic pages have no file on disk. Use a per-process timestamp so
/// `Last-Modified` / `ETag` stay stable across requests the way a real file's
/// would, without baking in a constant that would be identical on every deploy.
fn synthetic_mtime() -> u64 {
    static MTIME: OnceLock<u64> = OnceLock::new();
    *MTIME.get_or_init(camouflage::unix_now)
}

/// One camouflage response head. Header order mirrors nginx's own output:
/// `Server`, `Date`, `Content-Type`, `Content-Length`, `Last-Modified`,
/// `Connection`, `ETag`, `Cache-Control`, then `Accept-Ranges` / `Content-Range`.
/// Order is itself a fingerprint, so it is fixed here rather than in call sites.
#[derive(Default)]
struct NginxHead<'a> {
    status: u16,
    ctype: Option<&'a str>,
    content_length: Option<u64>,
    /// Set for bodies backed by a file: adds `Last-Modified` + `ETag`.
    file: Option<FileMeta>,
    /// nginx only advertises `Accept-Ranges` on the non-range 200 path.
    accept_ranges: bool,
    content_range: Option<String>,
    cache_control: bool,
}

impl NginxHead<'_> {
    fn render(&self, date: &str) -> String {
        let mut h = String::with_capacity(384);
        let status = self.status;
        let reason = camouflage::reason_phrase(status);
        h.push_str(&format!("HTTP/1.1 {status} {reason}\r\n"));
        h.push_str(&format!("Server: {}\r\n", camouflage::SERVER_TOKEN));
        h.push_str(&format!("Date: {date}\r\n"));
        if let Some(ctype) = self.ctype {
            h.push_str(&format!("Content-Type: {ctype}\r\n"));
        }
        if let Some(cl) = self.content_length {
            h.push_str(&format!("Content-Length: {cl}\r\n"));
        }
        if let Some(f) = self.file {
            h.push_str(&format!(
                "Last-Modified: {}\r\n",
                camouflage::format_http_date(f.mtime_secs)
            ));
        }
        // Single-shot connection: nginx also says `close` when it will close.
        h.push_str("Connection: close\r\n");
        if let Some(f) = self.file {
            h.push_str(&format!("ETag: {}\r\n", nginx_etag(f)));
        }
        if self.cache_control {
            h.push_str("Cache-Control: public, max-age=3600\r\n");
        }
        if self.accept_ranges {
            h.push_str("Accept-Ranges: bytes\r\n");
        }
        if let Some(cr) = self.content_range.as_deref() {
            h.push_str(&format!("Content-Range: {cr}\r\n"));
        }
        h.push_str("\r\n");
        h
    }
}

/// nginx error page: status, reason and body always come from the same table.
/// No `Last-Modified` / `ETag` / `Accept-Ranges` — nginx omits them on these.
async fn write_camouflage_status<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
) -> anyhow::Result<()> {
    let (code, body) = camouflage::error_page(code);
    let head = NginxHead {
        status: code,
        ctype: Some("text/html; charset=utf-8"),
        content_length: Some(body.len() as u64),
        ..Default::default()
    };
    stream
        .write_all(head.render(&camouflage::http_date_now()).as_bytes())
        .await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn serve_camouflage_http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    req: CamoRequest<'_>,
    camo: &CamouflageServeConfig,
    peer: Option<SocketAddr>,
) -> anyhow::Result<()> {
    if let Some(origin) = camo.reverse_proxy.as_deref() {
        // Reverse proxy streams the origin's own bytes: never rewrite its headers.
        if let Err(e) = forward_http_get(stream, req.method, req.path, origin).await {
            tracing::warn!(
                target: "bibavpn_camouflage",
                ?peer,
                "camouflage reverse-proxy: {e:#}"
            );
            let (_st, body) = camouflage::html_ok_index();
            write_synthetic_response(stream, req, "text/html; charset=utf-8", body.as_bytes())
                .await?;
        }
        return Ok(());
    }

    if let Some(dir) = camo.static_dir.as_deref() {
        match serve_static_file(dir, req.path).await {
            Some(f) => {
                write_file_response(stream, req, f.ctype, &f.body, f.meta).await?;
                return Ok(());
            }
            None => {
                write_camouflage_status(stream, 404).await?;
                return Ok(());
            }
        }
    }

    // Default synthetic pages
    let path = req.path.split('?').next().unwrap_or(req.path);
    match path {
        "/" => {
            let (_st, body) = camouflage::html_ok_index();
            write_synthetic_response(stream, req, "text/html; charset=utf-8", body.as_bytes())
                .await?;
        }
        "/robots.txt" => {
            let body = "User-agent: *\nDisallow:\n";
            write_synthetic_response(stream, req, "text/plain; charset=utf-8", body.as_bytes())
                .await?;
        }
        "/favicon.ico" => {
            write_no_content(stream).await?;
        }
        _ => {
            write_camouflage_status(stream, 404).await?;
        }
    }
    Ok(())
}

/// A single URL path segment must be one normal component with no separators or drive prefixes.
fn static_url_segment_is_safe(seg: &str) -> bool {
    if seg.is_empty() || seg.contains('\\') || seg.contains('\0') {
        return false;
    }
    let b = seg.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return false;
    }
    let mut comps = Path::new(seg).components();
    matches!(
        (comps.next(), comps.next()),
        (Some(Component::Normal(_)), None)
    )
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
        if !static_url_segment_is_safe(seg) {
            return None;
        }
        out.push(seg);
    }
    if !out.starts_with(&base_canon) {
        return None;
    }
    let canon = std::fs::canonicalize(&out).ok()?;
    if canon.starts_with(&base_canon) {
        Some(canon)
    } else {
        None
    }
}

/// A file from `--camouflage-dir`, with the metadata nginx would report for it.
struct StaticFile {
    ctype: &'static str,
    body: Vec<u8>,
    meta: FileMeta,
}

async fn serve_static_file(dir: &Path, path: &str) -> Option<StaticFile> {
    let fs_path = safe_static_path_under_base(dir, path)?;
    let md = tokio::fs::metadata(&fs_path).await.ok()?;
    if !md.is_file() {
        return None;
    }
    let data = tokio::fs::read(&fs_path).await.ok()?;
    let ctype = guess_mime(fs_path.extension().and_then(|e| e.to_str()).unwrap_or(""));
    let meta = FileMeta {
        mtime_secs: mtime_secs(&md),
        len: data.len() as u64,
    };
    Some(StaticFile {
        ctype,
        body: data,
        meta,
    })
}

/// File mtime as whole seconds since the epoch (0 if unavailable / pre-1970).
fn mtime_secs(md: &std::fs::Metadata) -> u64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

/// Outcome of a `Range: bytes=...` header against a body of `total` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RangeOutcome {
    /// No usable range: serve the whole body as 200, which is also what nginx
    /// does for absent / malformed / multi-range requests under `max_ranges 1`.
    Whole,
    /// Inclusive byte range, `start <= end < total`.
    Partial { start: u64, end: u64 },
    /// Well-formed but outside the body: 416 with `Content-Range: bytes */total`.
    Unsatisfiable,
}

/// Single-range subset of RFC 9110 byte ranges, matching nginx's tolerances.
fn parse_single_range(header: Option<&str>, total: u64) -> RangeOutcome {
    let Some(raw) = header else {
        return RangeOutcome::Whole;
    };
    if total == 0 {
        return RangeOutcome::Whole;
    }
    let raw = raw.trim();
    let bytes = raw.as_bytes();
    if bytes.len() < 7 || !bytes[..6].eq_ignore_ascii_case(b"bytes=") {
        return RangeOutcome::Whole;
    }
    let spec = raw[6..].trim();
    if spec.contains(',') {
        return RangeOutcome::Whole;
    }
    let Some((from, to)) = spec.split_once('-') else {
        return RangeOutcome::Whole;
    };
    let (from, to) = (from.trim(), to.trim());

    if from.is_empty() {
        // Suffix range: the last `n` bytes.
        let Ok(n) = to.parse::<u64>() else {
            return RangeOutcome::Whole;
        };
        if n == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        return RangeOutcome::Partial {
            start: total.saturating_sub(n),
            end: total - 1,
        };
    }

    let Ok(start) = from.parse::<u64>() else {
        return RangeOutcome::Whole;
    };
    if start >= total {
        return RangeOutcome::Unsatisfiable;
    }
    let end = if to.is_empty() {
        total - 1
    } else {
        match to.parse::<u64>() {
            Ok(e) if e >= start => e.min(total - 1),
            Ok(_) => return RangeOutcome::Unsatisfiable,
            Err(_) => return RangeOutcome::Whole,
        }
    };
    RangeOutcome::Partial { start, end }
}

/// 204 for `/favicon.ico`: nginx sends no `Content-Type` and no
/// `Content-Length` on a 204, and never a body.
async fn write_no_content<S: AsyncWrite + Unpin>(stream: &mut S) -> anyhow::Result<()> {
    let head = NginxHead {
        status: 204,
        cache_control: true,
        ..Default::default()
    };
    stream
        .write_all(head.render(&camouflage::http_date_now()).as_bytes())
        .await?;
    stream.flush().await?;
    Ok(())
}

/// Synthetic page served as if it were a file on disk.
async fn write_synthetic_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    req: CamoRequest<'_>,
    ctype: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let meta = FileMeta {
        mtime_secs: synthetic_mtime(),
        len: body.len() as u64,
    };
    write_file_response(stream, req, ctype, body, meta).await
}

/// 200 / 206 / 416 for a body backed by a file, in nginx's header order.
/// `HEAD` gets byte-identical headers and no body.
async fn write_file_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    req: CamoRequest<'_>,
    ctype: &str,
    body: &[u8],
    meta: FileMeta,
) -> anyhow::Result<()> {
    let date = camouflage::http_date_now();
    let total = body.len() as u64;
    let (head, payload) = match parse_single_range(req.range, total) {
        RangeOutcome::Whole => {
            let head = NginxHead {
                status: 200,
                ctype: Some(ctype),
                content_length: Some(total),
                file: Some(meta),
                accept_ranges: true,
                cache_control: true,
                ..Default::default()
            };
            (head, body)
        }
        RangeOutcome::Partial { start, end } => {
            let slice = &body[start as usize..=end as usize];
            // nginx drops `Accept-Ranges` once it actually answers with a range.
            let head = NginxHead {
                status: 206,
                ctype: Some(ctype),
                content_length: Some(slice.len() as u64),
                file: Some(meta),
                content_range: Some(format!("bytes {start}-{end}/{total}")),
                cache_control: true,
                ..Default::default()
            };
            (head, slice)
        }
        RangeOutcome::Unsatisfiable => {
            let (_code, page) = camouflage::error_page(416);
            let head = NginxHead {
                status: 416,
                ctype: Some("text/html; charset=utf-8"),
                content_length: Some(page.len() as u64),
                content_range: Some(format!("bytes */{total}")),
                ..Default::default()
            };
            (head, page.as_bytes())
        }
    };
    stream.write_all(head.render(&date).as_bytes()).await?;
    if !req.is_head() {
        stream.write_all(payload).await?;
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
    use std::time::Duration;

    #[test]
    fn guess_mime_common_extensions() {
        assert!(guess_mime("html").contains("text/html"));
        assert!(guess_mime("CSS").contains("text/css"));
        assert_eq!(guess_mime("bin"), "application/octet-stream");
    }

    /// `read_http_head` waits for `\r\n\r\n` with no deadline of its own, so the caller
    /// must impose one: the server bounds this call with `--handshake-timeout-secs`
    /// because the concurrency permit is already held here.
    #[tokio::test]
    async fn partial_http_head_never_completes_and_the_caller_deadline_fires() {
        let (mut client, server) = tokio::io::duplex(4096);
        // Request line + one header, never the terminating CRLF CRLF.
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.org\r\n")
            .await
            .unwrap();
        let res = tokio::time::timeout(
            Duration::from_millis(50),
            accept_websocket_or_camouflage(
                server,
                "/ws",
                false,
                "tok",
                CamouflageServeConfig::default(),
                None,
            ),
        )
        .await;
        assert!(
            res.is_err(),
            "a peer that never finishes the head must not resolve"
        );
        // Keep the peer half alive until here; dropping it earlier would be EOF, not a stall.
        drop(client);
    }

    /// The timeout must not change the camouflage path: a complete probe is still served.
    #[tokio::test]
    async fn complete_http_head_still_gets_camouflage_response() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            accept_websocket_or_camouflage(
                server,
                "/ws",
                false,
                "tok",
                CamouflageServeConfig::default(),
                None,
            )
            .await
        });
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
            .await
            .unwrap();
        let mut resp = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut resp))
            .await
            .expect("camouflage answers well inside the handshake deadline")
            .unwrap();
        let text = String::from_utf8_lossy(&resp[..n]);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
        let out = srv.await.expect("join").expect("accept");
        assert!(out.is_none(), "a plain GET is not a websocket upgrade");
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
        assert!(safe_static_path_under_base(&base, "/..\\..\\windows\\win.ini").is_none());
        assert!(safe_static_path_under_base(&base, "/foo\\bar").is_none());
        assert!(safe_static_path_under_base(&base, "/C:/Windows/win.ini").is_none());
        assert!(safe_static_path_under_base(&base, "/C:\\Windows\\win.ini").is_none());
        assert!(safe_static_path_under_base(&base, "/foo\0bar").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    /// Header names of a rendered head, in the order they appear on the wire.
    fn header_names(head: &str) -> Vec<&str> {
        head.split("\r\n")
            .skip(1)
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap_or(l))
            .collect()
    }

    /// `Date` is generated per response; drop it when comparing two heads.
    fn strip_date(head: &str) -> String {
        head.split("\r\n")
            .filter(|l| !l.starts_with("Date: "))
            .collect::<Vec<_>>()
            .join("\r\n")
    }

    fn req(method: &'static str, range: Option<&'static str>) -> CamoRequest<'static> {
        CamoRequest {
            method,
            path: "/x.txt",
            range,
        }
    }

    // nginx's own default index.html: mtime 0x5e9f695d, size 0x264 (612 bytes).
    const DEMO_META: FileMeta = FileMeta {
        mtime_secs: 0x5e9f_695d,
        len: 0x264,
    };

    #[test]
    fn nginx_etag_format() {
        assert_eq!(nginx_etag(DEMO_META), "\"5e9f695d-264\"");
        assert_eq!(
            nginx_etag(FileMeta {
                mtime_secs: 0,
                len: 0
            }),
            "\"0-0\""
        );
        assert_eq!(
            nginx_etag(FileMeta {
                mtime_secs: 1_709_164_800,
                len: 255
            }),
            "\"65dfc900-ff\""
        );
    }

    #[test]
    fn static_200_header_order_matches_nginx() {
        let head = NginxHead {
            status: 200,
            ctype: Some("text/html; charset=utf-8"),
            content_length: Some(DEMO_META.len),
            file: Some(DEMO_META),
            accept_ranges: true,
            cache_control: true,
            ..Default::default()
        }
        .render("Tue, 15 Nov 1994 08:12:31 GMT");
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert_eq!(
            header_names(&head),
            vec![
                "Server",
                "Date",
                "Content-Type",
                "Content-Length",
                "Last-Modified",
                "Connection",
                "ETag",
                "Cache-Control",
                "Accept-Ranges",
            ]
        );
        assert!(
            head.contains("Date: Tue, 15 Nov 1994 08:12:31 GMT\r\n"),
            "{head}"
        );
        assert!(
            head.contains("Last-Modified: Tue, 21 Apr 2020 21:45:01 GMT\r\n"),
            "{head}"
        );
        assert!(head.contains("ETag: \"5e9f695d-264\"\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n"), "{head}");
    }

    #[test]
    fn parse_single_range_cases() {
        use RangeOutcome::{Partial, Unsatisfiable, Whole};
        assert_eq!(parse_single_range(None, 100), Whole);
        assert_eq!(
            parse_single_range(Some("bytes=0-9"), 100),
            Partial { start: 0, end: 9 }
        );
        assert_eq!(
            parse_single_range(Some("BYTES=0-9"), 100),
            Partial { start: 0, end: 9 }
        );
        assert_eq!(
            parse_single_range(Some("bytes=10-"), 100),
            Partial { start: 10, end: 99 }
        );
        assert_eq!(
            parse_single_range(Some("bytes=-10"), 100),
            Partial { start: 90, end: 99 }
        );
        // Suffix longer than the body clamps to the whole body, still a 206.
        assert_eq!(
            parse_single_range(Some("bytes=-500"), 100),
            Partial { start: 0, end: 99 }
        );
        assert_eq!(
            parse_single_range(Some("bytes=0-500"), 100),
            Partial { start: 0, end: 99 }
        );
        assert_eq!(parse_single_range(Some("bytes=100-"), 100), Unsatisfiable);
        assert_eq!(parse_single_range(Some("bytes=9-4"), 100), Unsatisfiable);
        assert_eq!(parse_single_range(Some("bytes=-0"), 100), Unsatisfiable);
        // Multi-range, other units and junk: serve the whole body like nginx.
        assert_eq!(parse_single_range(Some("bytes=0-1,4-5"), 100), Whole);
        assert_eq!(parse_single_range(Some("items=0-1"), 100), Whole);
        assert_eq!(parse_single_range(Some("bytes=abc"), 100), Whole);
        assert_eq!(parse_single_range(Some("bytes="), 100), Whole);
        assert_eq!(parse_single_range(Some(""), 100), Whole);
        assert_eq!(parse_single_range(Some("bytes=0-9"), 0), Whole);
    }

    #[tokio::test]
    async fn error_405_has_its_own_body_and_reason() {
        let mut out: Vec<u8> = Vec::new();
        write_camouflage_status(&mut out, 405).await.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 405 Not Allowed\r\n"), "{s}");
        let (head, body) = s.split_once("\r\n\r\n").unwrap();
        assert_eq!(body, camouflage::NOT_ALLOWED_HTML);
        assert!(
            !body.contains("404"),
            "405 must not carry the 404 body: {body}"
        );
        assert_eq!(
            header_names(&format!("{head}\r\n\r\n")),
            vec![
                "Server",
                "Date",
                "Content-Type",
                "Content-Length",
                "Connection"
            ]
        );
        let cl: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(cl, body.len());
        let date = head
            .lines()
            .find_map(|l| l.strip_prefix("Date: "))
            .expect("Date header");
        assert!(date.ends_with(" GMT") && date.len() == 29, "{date}");
    }

    #[tokio::test]
    async fn error_404_keeps_the_404_body() {
        let mut out: Vec<u8> = Vec::new();
        write_camouflage_status(&mut out, 404).await.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n"), "{s}");
        assert!(s.ends_with(camouflage::NOT_FOUND_HTML), "{s}");
    }

    #[tokio::test]
    async fn head_and_get_headers_are_identical() {
        let body = b"hello world";
        let meta = FileMeta {
            mtime_secs: 0x5e9f_695d,
            len: body.len() as u64,
        };
        let mut get_out: Vec<u8> = Vec::new();
        write_file_response(&mut get_out, req("GET", None), "text/plain", body, meta)
            .await
            .unwrap();
        let mut head_out: Vec<u8> = Vec::new();
        write_file_response(&mut head_out, req("HEAD", None), "text/plain", body, meta)
            .await
            .unwrap();
        let g = String::from_utf8(get_out).unwrap();
        let h = String::from_utf8(head_out).unwrap();
        let (g_head, g_body) = g.split_once("\r\n\r\n").unwrap();
        let (h_head, h_body) = h.split_once("\r\n\r\n").unwrap();
        assert_eq!(g_body.as_bytes(), &body[..]);
        assert_eq!(h_body, "");
        assert_eq!(strip_date(g_head), strip_date(h_head));
        assert!(g_head.contains("Content-Length: 11\r\n"), "{g_head}");
        assert!(h_head.contains("Content-Length: 11\r\n"), "{h_head}");
    }

    #[tokio::test]
    async fn range_request_gets_206_without_accept_ranges() {
        let body = b"0123456789";
        let meta = FileMeta {
            mtime_secs: 0x5e9f_695d,
            len: 10,
        };
        let mut out: Vec<u8> = Vec::new();
        write_file_response(
            &mut out,
            req("GET", Some("bytes=2-5")),
            "text/plain",
            body,
            meta,
        )
        .await
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 206 Partial Content\r\n"), "{s}");
        assert!(s.contains("Content-Length: 4\r\n"), "{s}");
        assert!(s.contains("Content-Range: bytes 2-5/10\r\n"), "{s}");
        assert!(!s.contains("Accept-Ranges"), "{s}");
        assert!(s.ends_with("\r\n\r\n2345"), "{s}");
    }

    #[tokio::test]
    async fn unsatisfiable_range_gets_416() {
        let body = b"0123456789";
        let meta = FileMeta {
            mtime_secs: 0x5e9f_695d,
            len: 10,
        };
        let mut out: Vec<u8> = Vec::new();
        write_file_response(
            &mut out,
            req("GET", Some("bytes=50-60")),
            "text/plain",
            body,
            meta,
        )
        .await
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.starts_with("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"),
            "{s}"
        );
        assert!(s.contains("Content-Range: bytes */10\r\n"), "{s}");
        assert!(!s.contains("Cache-Control"), "{s}");
        assert!(!s.contains("Accept-Ranges"), "{s}");
        assert!(s.ends_with(camouflage::RANGE_NOT_SATISFIABLE_HTML), "{s}");
    }

    #[tokio::test]
    async fn synthetic_pages_look_like_files_on_disk() {
        let mut out: Vec<u8> = Vec::new();
        let (_st, body) = camouflage::html_ok_index();
        write_synthetic_response(
            &mut out,
            req("GET", None),
            "text/html; charset=utf-8",
            body.as_bytes(),
        )
        .await
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        let (head, _) = s.split_once("\r\n\r\n").unwrap();
        assert_eq!(
            header_names(&format!("{head}\r\n\r\n")),
            vec![
                "Server",
                "Date",
                "Content-Type",
                "Content-Length",
                "Last-Modified",
                "Connection",
                "ETag",
                "Cache-Control",
                "Accept-Ranges",
            ]
        );
    }

    #[tokio::test]
    async fn no_content_omits_type_and_length() {
        let mut out: Vec<u8> = Vec::new();
        write_no_content(&mut out).await.unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 204 No Content\r\n"), "{s}");
        assert!(!s.contains("Content-Length"), "{s}");
        assert!(!s.contains("Content-Type"), "{s}");
        assert!(s.ends_with("\r\n\r\n"), "{s}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn static_file_symlink_escape_is_rejected() {
        let pid = std::process::id();
        let outside = std::env::temp_dir().join(format!("bibavpn_outside_{pid}"));
        let base = std::env::temp_dir().join(format!("bibavpn_symlink_{pid}"));
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(&outside, b"outside secret").unwrap();
        std::os::unix::fs::symlink(&outside, base.join("escape")).unwrap();
        assert!(
            serve_static_file(&base, "/escape").await.is_none(),
            "symlink pointing outside camouflage dir must not be served"
        );
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn static_file_carries_real_mtime_and_size() {
        let base = std::env::temp_dir().join(format!("bibavpn_static_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("index.html"), b"<html>hi</html>").unwrap();
        fs::create_dir_all(base.join("sub")).unwrap();
        let f = serve_static_file(&base, "/").await.expect("index served");
        assert_eq!(f.ctype, "text/html; charset=utf-8");
        assert_eq!(f.meta.len, 15);
        assert_eq!(f.body.len(), 15);
        assert!(f.meta.mtime_secs > 1_600_000_000, "{}", f.meta.mtime_secs);
        // Directories are not served.
        assert!(serve_static_file(&base, "/sub").await.is_none());
        assert!(serve_static_file(&base, "/missing.html").await.is_none());
        let _ = fs::remove_dir_all(&base);
    }
}
