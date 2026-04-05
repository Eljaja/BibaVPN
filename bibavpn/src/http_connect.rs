//! Minimal HTTP `CONNECT` proxy (no auth). Only tunneling; plain `GET http://` is not supported.

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Parse `CONNECT host:port HTTP/1.x`, drain headers, return target and any bytes already read
/// after the header block (often TLS ClientHello in the same TCP segment as the CONNECT).
pub async fn http_connect_handshake(stream: &mut TcpStream) -> anyhow::Result<(String, u16, Vec<u8>)> {
    let (authority, prefetch) = {
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
        if !method.eq_ignore_ascii_case("CONNECT") {
            bail!("only CONNECT is supported, got {method}");
        }
        let authority = parts.next().context("CONNECT missing authority")?.to_string();
        let _http_version = parts.next().context("CONNECT missing HTTP version")?;

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
        let prefetch = reader.buffer().to_vec();
        (authority, prefetch)
    };

    let (h, p) = parse_authority(&authority)?;
    Ok((h, p, prefetch))
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
        if !rest.starts_with(':') {
            bail!("IPv6 CONNECT requires :port");
        }
        let port: u16 = rest[1..].parse().context("IPv6 CONNECT port")?;
        return Ok((host, port));
    }
    if let Some((h, p)) = auth.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = p.parse().context("CONNECT port")?;
            if h.contains(':') {
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

pub async fn reply_connect_error(stream: &mut TcpStream, status: u16, reason: &str) -> anyhow::Result<()> {
    let body = format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.flush().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_authority;

    #[test]
    fn authority_host_port() {
        assert_eq!(parse_authority("example.com:443").unwrap(), ("example.com".into(), 443));
    }

    #[test]
    fn authority_default_443() {
        assert_eq!(parse_authority("example.com").unwrap(), ("example.com".into(), 443));
    }

    #[test]
    fn authority_ipv6() {
        assert_eq!(
            parse_authority("[::1]:8443").unwrap(),
            ("::1".into(), 8443)
        );
    }
}
