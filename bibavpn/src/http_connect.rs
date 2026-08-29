//! HTTP forward proxy: `CONNECT` (HTTPS) and absolute-form `http://…` (plain HTTP via system proxy).

use std::net::Ipv6Addr;

use anyhow::{bail, Context};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Local-only liveness path for desktop recovery probes (not forwarded to the tunnel).
pub const LOCAL_HEALTH_PATH: &str = "/bibavpn-health";

/// Parsed first client request on the local HTTP proxy port.
#[derive(Debug)]
pub enum HttpProxyHandshake {
    /// After this, send `200 Connection Established` and tunnel raw bytes (TLS, etc.).
    Connect {
        host: String,
        port: u16,
        client_prefetch: Vec<u8>,
    },
    /// Plain HTTP: Windows often sends `GET http://host/path HTTP/1.1` instead of `CONNECT`.
    /// Tunnel to `host:port` and send `to_origin` first (rewritten request line + headers + body prefix).
    ForwardHttp {
        host: String,
        port: u16,
        to_origin: Vec<u8>,
    },
}

/// Respond to `GET /bibavpn-health` without opening a tunnel (desktop liveness probe).
pub async fn try_serve_health_check(stream: &mut TcpStream) -> anyhow::Result<bool> {
    let mut buf = [0u8; 128];
    let n = stream.peek(&mut buf).await.context("health peek")?;
    if n == 0 {
        return Ok(false);
    }
    let prefix = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if !prefix.starts_with("GET /bibavpn-health ") && !prefix.starts_with("GET /bibavpn-health\r") {
        return Ok(false);
    }

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.context("health read line")?;
    read_header_block(&mut reader).await?;
    let stream = reader.into_inner();
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await
        .context("health write")?;
    stream.flush().await.context("health flush")?;
    Ok(true)
}

/// True when the peer opened TCP then closed before sending an HTTP request line.
pub fn is_benign_handshake_abort(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}");
    msg.contains("empty request line") || (msg.contains("early eof") && msg.contains("read request line"))
}

/// Read the first HTTP request: either `CONNECT` or proxy-style `METHOD http://authority/path …`.
pub async fn http_proxy_handshake(stream: &mut TcpStream) -> anyhow::Result<HttpProxyHandshake> {
    let mut reader = BufReader::new(&mut *stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .context("read request line")?;
    if request_line.len() > 8192 {
        bail!("request line too long");
    }
    let request_line = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("empty request line")?;
    let target = parts.next().context("missing request target")?;
    let version = parts.next().context("missing HTTP version")?;
    if parts.next().is_some() {
        bail!("bad request line");
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let authority = target.to_string();
        read_header_block(&mut reader).await?;
        let prefetch = reader.buffer().to_vec();
        let (h, p) = parse_authority(&authority)?;
        return Ok(HttpProxyHandshake::Connect {
            host: h,
            port: p,
            client_prefetch: prefetch,
        });
    }

    let uri: http::Uri = target.parse().context("invalid request URI")?;
    let scheme = uri.scheme_str().context("URI missing scheme")?;
    if !scheme.eq_ignore_ascii_case("http") {
        bail!("unsupported proxy URI scheme ({scheme}); use CONNECT for HTTPS targets");
    }
    let host = uri.host().context("URI missing host")?.to_string();
    let port = uri.port_u16().unwrap_or(80);
    let path_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("/");

    let new_first = format!("{method} {path_query} {version}\r\n");
    let mut to_origin = Vec::new();
    to_origin.extend_from_slice(new_first.as_bytes());
    read_header_lines_into(&mut reader, &mut to_origin).await?;
    to_origin.extend_from_slice(b"\r\n");
    to_origin.extend_from_slice(reader.buffer());

    Ok(HttpProxyHandshake::ForwardHttp {
        host,
        port,
        to_origin,
    })
}

async fn read_header_block<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> anyhow::Result<()> {
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.context("read header")?;
        if line.len() > 8192 {
            bail!("header line too long");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    Ok(())
}

async fn read_header_lines_into<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.context("read header")?;
        if line.len() > 8192 {
            bail!("header line too long");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        out.extend_from_slice(line.as_bytes());
    }
    Ok(())
}

fn parse_authority(auth: &str) -> anyhow::Result<(String, u16)> {
    let auth = auth.trim();
    if auth.is_empty() {
        bail!("empty authority");
    }
    if auth.starts_with('[') {
        let end = auth.find(']').context("invalid IPv6 authority")?;
        let host = auth[1..end].to_string();
        let rest = &auth[end + 1..];
        let port: u16 = if rest.is_empty() {
            443
        } else if rest.starts_with(':') {
            rest[1..].parse().context("IPv6 CONNECT port")?
        } else {
            bail!("IPv6 CONNECT: expected nothing or :port after ]");
        };
        return Ok((host, port));
    }
    if let Some((h, p)) = auth.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = p.parse().context("CONNECT port")?;
            if h.contains(':') {
                // IPv6 literal without brackets: port is the segment after the last ':'.
                if h.parse::<Ipv6Addr>().is_ok() {
                    return Ok((h.to_string(), port));
                }
                bail!("ambiguous authority; use bracketed IPv6");
            }
            return Ok((h.to_string(), port));
        }
    }
    Ok((auth.to_string(), 443))
}

pub async fn reply_connect_ok(stream: &mut TcpStream) -> anyhow::Result<()> {
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("write 200 established")?;
    stream.flush().await.context("flush")?;
    Ok(())
}

pub async fn reply_connect_error(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
) -> anyhow::Result<()> {
    let body =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.flush().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_authority;
    use http::Uri;

    #[test]
    fn authority_host_port() {
        assert_eq!(
            parse_authority("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
    }

    #[test]
    fn authority_default_443() {
        assert_eq!(
            parse_authority("example.com").unwrap(),
            ("example.com".into(), 443)
        );
    }

    #[test]
    fn authority_ipv6() {
        assert_eq!(parse_authority("[::1]:8443").unwrap(), ("::1".into(), 8443));
        assert_eq!(
            parse_authority("[2001:db8::1]").unwrap(),
            ("2001:db8::1".into(), 443)
        );
    }

    #[test]
    fn authority_ipv6_no_brackets() {
        assert_eq!(
            parse_authority("2001:db8::1:8443").unwrap(),
            ("2001:db8::1".into(), 8443)
        );
    }

    #[test]
    fn authority_ipv4_literal() {
        assert_eq!(
            parse_authority("93.184.216.34:443").unwrap(),
            ("93.184.216.34".into(), 443)
        );
        assert_eq!(parse_authority("1.1.1.1").unwrap(), ("1.1.1.1".into(), 443));
    }

    #[test]
    fn http_uri_ipv4_for_forward() {
        let uri: Uri = "http://192.168.50.2:8080/admin".parse().unwrap();
        assert_eq!(uri.host(), Some("192.168.50.2"));
        assert_eq!(uri.port_u16(), Some(8080));
        assert!(uri.path_and_query().unwrap().as_str().starts_with('/'));
    }

    #[test]
    fn http_uri_ipv4_default_port() {
        let uri: Uri = "http://10.0.0.1/".parse().unwrap();
        assert_eq!(uri.host(), Some("10.0.0.1"));
        assert_eq!(uri.port_u16(), None);
    }

    #[test]
    fn benign_abort_detects_empty_request_line() {
        let err = anyhow::anyhow!("empty request line");
        assert!(super::is_benign_handshake_abort(&err));
    }
}
