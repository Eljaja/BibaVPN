/// HTTP proxy server using the Yggdrasil netstack.
///
/// Supports CONNECT tunneling (HTTPS and other TCP protocols) and
/// forwarding of plain-HTTP absolute-URI requests, rewritten to
/// origin-form with `Connection: close` — one origin connection per
/// request, the client connection closes when the response completes.
/// Authentication: none.
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::netstack::YggNetstack;
use crate::resolver::NameResolver;
use crate::stats::{counting_copy, ConnGuard, Dir, ListenerStats, ListenerStatsRegistry, HTTP_STATS_KEY};

/// Largest request head (request line + headers) we are willing to parse.
const MAX_HEAD_BYTES: usize = 16 * 1024;

pub struct HttpProxyServer {
    netstack: Arc<YggNetstack>,
    resolver: Arc<NameResolver>,
}

impl HttpProxyServer {
    pub fn new(netstack: Arc<YggNetstack>, resolver: Arc<NameResolver>) -> Self {
        Self { netstack, resolver }
    }

    pub async fn serve_tcp(
        self: Arc<Self>,
        addr: &str,
        stop_tx: broadcast::Sender<()>,
        stats: Arc<ListenerStatsRegistry>,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let entry = stats.entry(HTTP_STATS_KEY, "http", &listener.local_addr()?.to_string(), "");
        tracing::info!("HTTP proxy server listening on {}", addr);
        let mut stop = stop_tx.subscribe();
        loop {
            tokio::select! {
                _ = stop.recv() => {
                    tracing::info!("HTTP proxy: stopped on {}", addr);
                    stats.remove(HTTP_STATS_KEY);
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            tracing::debug!("HTTP proxy connection from {}", peer);
                            let srv = self.clone();
                            let stop_conn = stop_tx.subscribe();
                            let entry = entry.clone();
                            tokio::spawn(async move {
                                if let Err(e) = srv.handle_client(stream, stop_conn, entry).await {
                                    tracing::debug!("HTTP proxy client error: {}", e);
                                }
                            });
                        }
                        Err(e) => tracing::warn!("HTTP proxy accept error: {}", e),
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_client(
        &self,
        mut client: TcpStream,
        stop: broadcast::Receiver<()>,
        entry: Arc<ListenerStats>,
    ) -> io::Result<()> {
        let (head, extra) = read_head(&mut client).await?;
        let req = match parse_request(&head) {
            Ok(r) => r,
            Err(e) => {
                let _ = send_simple_response(&mut client, 400, "Bad Request").await;
                return Err(e);
            }
        };
        if req.method == "CONNECT" {
            self.handle_connect(client, extra, req, stop, entry).await
        } else {
            self.handle_forward(client, extra, req, stop, entry).await
        }
    }

    async fn handle_connect(
        &self,
        mut client: TcpStream,
        extra: Vec<u8>,
        req: Request,
        mut stop: broadcast::Receiver<()>,
        entry: Arc<ListenerStats>,
    ) -> io::Result<()> {
        let (host, port) = split_authority(&req.target, 443).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "bad CONNECT authority")
        })?;
        let remote_addr = match self.resolve_remote(&host, port).await {
            Ok(a) => a,
            Err(e) => {
                let _ = send_simple_response(&mut client, 502, "Bad Gateway").await;
                return Err(io::Error::other(e));
            }
        };

        tracing::debug!("HTTP CONNECT dialing {}", remote_addr);
        let mut ygg_stream = match self.netstack.dial_tcp(remote_addr).await {
            Ok(s) => s,
            Err(e) => {
                let _ = send_simple_response(&mut client, 502, "Bad Gateway").await;
                return Err(e);
            }
        };

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // Bytes the client pipelined behind the CONNECT head belong to the tunnel.
        if !extra.is_empty() {
            ygg_stream.write_all(&extra).await?;
            entry
                .tx_bytes
                .fetch_add(extra.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        tracing::debug!("HTTP CONNECT relaying data for {}", remote_addr);

        let _guard = ConnGuard::new(entry.clone());
        let (cr, mut cw) = client.into_split();
        let (mut yr, mut yw) = tokio::io::split(ygg_stream);

        tokio::select! {
            _ = stop.recv() => {
                tracing::debug!("HTTP CONNECT relay cancelled for {}", remote_addr);
            }
            r = counting_copy(cr, &mut yw, entry.clone(), Dir::Tx) => {
                tracing::debug!("HTTP CONNECT client→ygg done: {:?}", r);
            }
            r = counting_copy(&mut yr, &mut cw, entry, Dir::Rx) => {
                tracing::debug!("HTTP CONNECT ygg→client done: {:?}", r);
            }
        }

        Ok(())
    }

    async fn handle_forward(
        &self,
        mut client: TcpStream,
        extra: Vec<u8>,
        req: Request,
        mut stop: broadcast::Receiver<()>,
        entry: Arc<ListenerStats>,
    ) -> io::Result<()> {
        let target = match forward_target(&req) {
            Ok(t) => t,
            Err(e) => {
                let _ = send_simple_response(&mut client, 400, "Bad Request").await;
                return Err(e);
            }
        };
        let remote_addr = match self.resolve_remote(&target.host, target.port).await {
            Ok(a) => a,
            Err(e) => {
                let _ = send_simple_response(&mut client, 502, "Bad Gateway").await;
                return Err(io::Error::other(e));
            }
        };

        tracing::debug!("HTTP {} dialing {}", req.method, remote_addr);
        let mut ygg_stream = match self.netstack.dial_tcp(remote_addr).await {
            Ok(s) => s,
            Err(e) => {
                let _ = send_simple_response(&mut client, 502, "Bad Gateway").await;
                return Err(e);
            }
        };

        let out_head = rewrite_head(&req, &target);
        ygg_stream.write_all(out_head.as_bytes()).await?;
        entry
            .tx_bytes
            .fetch_add(out_head.len() as u64, std::sync::atomic::Ordering::Relaxed);
        if !extra.is_empty() {
            ygg_stream.write_all(&extra).await?;
            entry
                .tx_bytes
                .fetch_add(extra.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }

        let _guard = ConnGuard::new(entry.clone());
        let (cr, mut cw) = client.into_split();
        let (mut yr, mut yw) = tokio::io::split(ygg_stream);

        tokio::select! {
            _ = stop.recv() => {
                tracing::debug!("HTTP forward relay cancelled for {}", remote_addr);
            }
            r = counting_copy(cr, &mut yw, entry.clone(), Dir::Tx) => {
                tracing::debug!("HTTP forward client→ygg done: {:?}", r);
            }
            r = counting_copy(&mut yr, &mut cw, entry, Dir::Rx) => {
                tracing::debug!("HTTP forward ygg→client done: {:?}", r);
            }
        }

        Ok(())
    }

    /// Resolve a request host to a socket address the netstack can dial:
    /// IPv6 literal passthrough, IPv4 literal via CKR (same as SOCKS5),
    /// `.pk.ygg` mapping / DNS-over-Yggdrasil through the shared resolver.
    async fn resolve_remote(&self, host: &str, port: u16) -> Result<SocketAddr, String> {
        if let Ok(ip) = host.parse::<Ipv6Addr>() {
            return Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));
        }
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }
        tracing::debug!("HTTP proxy resolving '{}'", host);
        match self.resolver.resolve(host).await {
            Ok(ip6) => {
                tracing::debug!("HTTP proxy resolved '{}' → {}", host, ip6);
                Ok(SocketAddr::V6(SocketAddrV6::new(ip6, port, 0, 0)))
            }
            Err(e) => {
                tracing::debug!("HTTP proxy resolve '{}' failed: {}", host, e);
                Err(e)
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// A parsed request head.
struct Request {
    method: String,
    /// Request-target as sent: authority for CONNECT, absolute-URI or
    /// origin-form otherwise.
    target: String,
    version: String,
    /// Header lines verbatim (name, colon, value), without the CRLF.
    headers: Vec<String>,
}

/// Where to send a forwarded (non-CONNECT) request.
struct ForwardTarget {
    host: String,
    port: u16,
    /// Path (+query) to use in the rewritten request line.
    origin_form: String,
    /// Authority for a synthesized Host header when the client sent none.
    authority: String,
}

/// Read a request head (through the blank line) plus any bytes already
/// buffered behind it (start of the request body). Everything read is
/// returned, so nothing is lost for the relay phase.
async fn read_head(client: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = find_head_end(&buf) {
            let extra = buf.split_off(pos + 4);
            return Ok((buf, extra));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof in request head",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request(head: &[u8]) -> io::Result<Request> {
    let text = std::str::from_utf8(head)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 request head"))?;
    let text = text.trim_end_matches("\r\n");
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "empty request head")
    })?;
    let mut parts = request_line.split(' ').filter(|s| !s.is_empty());
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP version"))?;
    if parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }
    Ok(Request {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers: lines.map(|l| l.to_string()).collect(),
    })
}

/// Split `host:port` / `[v6]:port` / `host` into host and port.
fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        Some((host, port))
    } else {
        match authority.rfind(':') {
            Some(i) => Some((
                authority[..i].to_string(),
                authority[i + 1..].parse().ok()?,
            )),
            None => Some((authority.to_string(), default_port)),
        }
    }
}

/// Work out where a forwarded request goes and what its origin-form
/// request line is. Accepts proxy-style absolute-URI targets and (for
/// leniency) origin-form targets with a Host header.
fn forward_target(req: &Request) -> io::Result<ForwardTarget> {
    if let Some(rest) = req.target.strip_prefix("http://") {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = split_authority(authority, 80).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "bad absolute-URI authority")
        })?;
        Ok(ForwardTarget {
            host,
            port,
            origin_form: path.to_string(),
            authority: authority.to_string(),
        })
    } else if req.target.starts_with('/') {
        let host_header = find_header(&req.headers, "Host").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "origin-form request without Host")
        })?;
        let (host, port) =
            split_authority(host_header, 80).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "bad Host header")
            })?;
        Ok(ForwardTarget {
            host,
            port,
            origin_form: req.target.clone(),
            authority: host_header.to_string(),
        })
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported request target '{}'", req.target),
        ))
    }
}

fn find_header<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|h| {
        let (k, v) = h.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// Re-serialize a forwarded request head: origin-form request line, hop-by-hop
/// proxy headers dropped, `Connection: close` so the origin closes after the
/// response (we close the client side when it completes).
fn rewrite_head(req: &Request, target: &ForwardTarget) -> String {
    let mut out = String::with_capacity(256 + req.headers.len() * 48);
    out.push_str(&req.method);
    out.push(' ');
    out.push_str(&target.origin_form);
    out.push(' ');
    out.push_str(&req.version);
    out.push_str("\r\n");

    let mut have_connection = false;
    let mut have_host = false;
    for h in &req.headers {
        let lower = h
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match lower.as_str() {
            "proxy-connection" | "proxy-authorization" | "proxy-authentication" | "keep-alive" => {
                continue;
            }
            "connection" => {
                if !have_connection {
                    out.push_str("Connection: close\r\n");
                    have_connection = true;
                }
                continue;
            }
            "host" => have_host = true,
            _ => {}
        }
        out.push_str(h);
        out.push_str("\r\n");
    }
    if !have_connection {
        out.push_str("Connection: close\r\n");
    }
    if !have_host {
        out.push_str("Host: ");
        out.push_str(&target.authority);
        out.push_str("\r\n");
    }
    // The blank line terminating the header block.
    out.push_str("\r\n");
    out
}

/// Minimal error response with no body, then the caller closes.
async fn send_simple_response(client: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let resp = format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(resp.as_bytes()).await
}
