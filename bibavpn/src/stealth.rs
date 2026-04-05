//! Browser-like WebSocket upgrade (TLS still uses rustls — not a perfect Chrome JA3 clone;
//! combine with reverse proxy + real site certs in production like naiveproxy + Caddy).
//! BibaV2.1: customizable Host / Origin / extra headers.

use http::{Request, Uri};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;

const DEFAULT_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const DEFAULT_AL: &str = "en-US,en;q=0.9";

/// Parameters for the outbound WebSocket HTTP upgrade (BibaV2.1 configurable fingerprint).
pub struct WsHandshakeParams<'a> {
    pub host_for_tcp: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub sni: &'a str,
    /// `Host` header value (default: `sni` if port 443 else `sni:port`).
    pub host_header: Option<&'a str>,
    /// `Origin` header (default: `https://{sni}`).
    pub origin: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub accept_language: Option<&'a str>,
    /// Extra headers (e.g. `Cookie`, custom `Sec-*`). Names sent as given.
    pub extra_headers: &'a [(String, String)],
}

/// Build WebSocket GET with optional header overrides (BibaV2.1).
pub fn build_websocket_request(p: WsHandshakeParams<'_>) -> Request<()> {
    let key = generate_key();
    let scheme = "wss";
    let uri_s = format!("{scheme}://{}:{}{}", p.host_for_tcp, p.port, p.path);
    let uri: Uri = uri_s.parse().expect("uri");

    let default_host: String = if p.port == 443 {
        p.sni.to_string()
    } else {
        format!("{}:{}", p.sni, p.port)
    };
    let host_h = p.host_header.unwrap_or(default_host.as_str());

    let ua = p.user_agent.unwrap_or(DEFAULT_UA);
    let origin = p
        .origin
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("https://{}", p.sni));
    let al = p.accept_language.unwrap_or(DEFAULT_AL);

    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", host_h)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", key)
        .header("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
        .header("User-Agent", ua)
        .header("Origin", origin)
        .header("Accept-Language", al);

    for (k, v) in p.extra_headers {
        req = req.header(k, v);
    }

    req.body(()).expect("request")
}

/// Default browser-like handshake (backward compatible).
pub fn browser_websocket_request(host_for_tcp: &str, port: u16, path: &str, sni: &str) -> Request<()> {
    build_websocket_request(WsHandshakeParams {
        host_for_tcp,
        port,
        path,
        sni,
        host_header: None,
        origin: None,
        user_agent: None,
        accept_language: None,
        extra_headers: &[],
    })
}
