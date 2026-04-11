//! Browser-like WebSocket upgrade (TLS still uses rustls — not a perfect Chrome JA3 clone;
//! combine with reverse proxy + real site certs in production like naiveproxy + Caddy).
//! BibaV2.1: customizable Host / Origin / extra headers; `TlsClientProfile` drives default UA / Sec-CH-UA.

use http::{Request, Uri};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;

use crate::tls_util::TlsClientProfile;

const DEFAULT_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

const DEFAULT_AL: &str = "en-US,en;q=0.9";

const UA_FIREFOX65: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

const UA_FIREFOX63: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0";

const ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";

/// Default `User-Agent` for `TlsClientProfile` (also used by decoy GETs).
pub fn default_user_agent_for_profile(profile: TlsClientProfile) -> &'static str {
    match profile {
        TlsClientProfile::Firefox65 => UA_FIREFOX65,
        TlsClientProfile::Firefox63 => UA_FIREFOX63,
        _ => DEFAULT_UA,
    }
}

fn is_firefox_profile(profile: TlsClientProfile) -> bool {
    matches!(
        profile,
        TlsClientProfile::Firefox65 | TlsClientProfile::Firefox63
    )
}

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
    /// Drives default `User-Agent` and Chrome-style client hints when UA is unset.
    pub tls_profile: TlsClientProfile,
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

    let ua = p
        .user_agent
        .unwrap_or_else(|| default_user_agent_for_profile(p.tls_profile));
    let origin = p
        .origin
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("https://{}", p.sni));
    let al = p.accept_language.unwrap_or(DEFAULT_AL);

    let mut req = if is_firefox_profile(p.tls_profile) {
        Request::builder()
            .method("GET")
            .uri(uri.clone())
            .header("Host", host_h)
            .header("User-Agent", ua)
            .header("Accept", "*/*")
            .header("Accept-Language", al)
            .header("Accept-Encoding", ACCEPT_ENCODING)
            .header("Sec-WebSocket-Version", "13")
            .header("Origin", origin)
            .header(
                "Sec-WebSocket-Extensions",
                "permessage-deflate; client_max_window_bits",
            )
            .header("Sec-WebSocket-Key", &key)
            .header("Connection", "keep-alive, Upgrade")
            .header("Upgrade", "websocket")
            .header("Pragma", "no-cache")
            .header("Cache-Control", "no-cache")
    } else {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("Host", host_h)
            .header("Connection", "Upgrade")
            .header("Pragma", "no-cache")
            .header("Cache-Control", "no-cache")
            .header("User-Agent", ua)
            .header("Upgrade", "websocket")
            .header("Origin", origin)
            .header("Sec-WebSocket-Version", "13")
            .header("Accept-Encoding", ACCEPT_ENCODING)
            .header("Accept-Language", al)
            .header("Sec-WebSocket-Key", &key)
            .header(
                "Sec-WebSocket-Extensions",
                "permessage-deflate; client_max_window_bits",
            )
            .header(
                "Sec-CH-UA",
                "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            )
            .header("Sec-CH-UA-Mobile", "?0")
            .header("Sec-CH-UA-Platform", "\"Windows\"")
    };

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
        tls_profile: TlsClientProfile::default(),
    })
}
