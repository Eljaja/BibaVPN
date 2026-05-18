//! Browser-like WebSocket upgrade (TLS still uses rustls — not a perfect Chrome JA3 clone;
//! combine with reverse proxy + real site certs in production like naiveproxy + Caddy).
//! BibaV2.1: customizable Host / Origin / extra headers; `TlsClientProfile` drives default UA / Sec-CH-UA.

use http::{Request, Uri};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;

use crate::stealth_v12::DecoyMode;
use crate::tls_util::TlsClientProfile;

const DEFAULT_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36";

const DEFAULT_AL: &str = "en-US,en;q=0.9";

/// Default `Accept-Language` for browser-like HTTP used in decoy GETs and WS when unset.
pub const DEFAULT_ACCEPT_LANGUAGE: &str = DEFAULT_AL;

const UA_CHROME132: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36";

const UA_SAFARI18: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

const UA_FIREFOX65: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

const UA_FIREFOX63: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0";

const UA_FIREFOX136: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0";

const ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";

/// Default `User-Agent` for `TlsClientProfile` (also used by decoy GETs).
pub fn default_user_agent_for_profile(profile: TlsClientProfile) -> &'static str {
    match profile {
        TlsClientProfile::Firefox65 => UA_FIREFOX65,
        TlsClientProfile::Firefox63 => UA_FIREFOX63,
        TlsClientProfile::Firefox136 => UA_FIREFOX136,
        TlsClientProfile::Safari18 => UA_SAFARI18,
        TlsClientProfile::Chrome70 | TlsClientProfile::Chrome132 => UA_CHROME132,
        TlsClientProfile::Default
        | TlsClientProfile::Randomized
        | TlsClientProfile::RandomizedAlpn
        | TlsClientProfile::RandomizedNoAlpn => DEFAULT_UA,
    }
}

fn is_firefox_profile(profile: TlsClientProfile) -> bool {
    matches!(
        profile,
        TlsClientProfile::Firefox65 | TlsClientProfile::Firefox63 | TlsClientProfile::Firefox136
    )
}

fn is_safari_profile(profile: TlsClientProfile) -> bool {
    profile == TlsClientProfile::Safari18
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
    } else if is_safari_profile(p.tls_profile) {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("Host", host_h)
            .header("User-Agent", ua)
            .header("Accept", "*/*")
            .header("Accept-Language", al)
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Sec-WebSocket-Version", "13")
            .header("Origin", origin)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", &key)
            .header("Sec-WebSocket-Extensions", "permessage-deflate")
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
                "\"Google Chrome\";v=\"132\", \"Chromium\";v=\"132\", \"Not_A Brand\";v=\"24\"",
            )
            .header("Sec-CH-UA-Mobile", "?0")
            .header("Sec-CH-UA-Platform", "\"Windows\"")
    };

    for (k, v) in p.extra_headers {
        req = req.header(k, v);
    }

    req.body(()).expect("request")
}

/// Plain HTTP/1.1 GET for decoy traffic (aligns with [`build_websocket_request`] per TLS profile).
pub fn format_decoy_get_request(
    path: &str,
    host_header: &str,
    sni: &str,
    user_agent: &str,
    accept_language: &str,
    tls_profile: TlsClientProfile,
    mode: DecoyMode,
) -> String {
    let origin = format!("https://{}", sni);
    match mode {
        DecoyMode::Simple => format!(
            "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\n\r\n",
            path = path,
            host_header = host_header,
            user_agent = user_agent,
        ),
        DecoyMode::Browser => {
            if is_firefox_profile(tls_profile) {
                format!(
                    "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: {accept_language}\r\nAccept-Encoding: {ACCEPT_ENCODING}\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\n\r\n",
                    path = path,
                    host_header = host_header,
                    user_agent = user_agent,
                    accept_language = accept_language,
                )
            } else if is_safari_profile(tls_profile) {
                format!(
                    "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: {accept_language}\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
                    path = path,
                    host_header = host_header,
                    user_agent = user_agent,
                    accept_language = accept_language,
                )
            } else {
                format!(
                    "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: {accept_language}\r\nAccept-Encoding: {ACCEPT_ENCODING}\r\nReferer: {origin}/\r\nDNT: 1\r\nConnection: close\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\nUpgrade-Insecure-Requests: 1\r\nSec-CH-UA: \"Google Chrome\";v=\"132\", \"Chromium\";v=\"132\", \"Not_A Brand\";v=\"24\"\r\nSec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\n\r\n",
                    path = path,
                    host_header = host_header,
                    user_agent = user_agent,
                    accept_language = accept_language,
                    origin = origin,
                )
            }
        }
    }
}

/// Default browser-like handshake (backward compatible).
pub fn browser_websocket_request(
    host_for_tcp: &str,
    port: u16,
    path: &str,
    sni: &str,
) -> Request<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::header;

    #[test]
    fn chrome_request_has_client_hints() {
        let req = build_websocket_request(WsHandshakeParams {
            host_for_tcp: "1.2.3.4",
            port: 443,
            path: "/ws",
            sni: "vpn.example.com",
            host_header: None,
            origin: None,
            user_agent: None,
            accept_language: None,
            extra_headers: &[],
            tls_profile: TlsClientProfile::Chrome132,
        });
        assert_eq!(req.uri().path(), "/ws");
        assert!(req.headers().contains_key(header::SEC_WEBSOCKET_KEY));
        assert!(req.headers().contains_key("Sec-CH-UA"));
        assert_eq!(
            req.headers()
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok()),
            Some(default_user_agent_for_profile(TlsClientProfile::Chrome132))
        );
    }

    #[test]
    fn firefox_request_uses_upgrade_connection() {
        let req = build_websocket_request(WsHandshakeParams {
            host_for_tcp: "127.0.0.1",
            port: 8443,
            path: "/tunnel",
            sni: "localhost",
            host_header: Some("localhost:8443"),
            origin: Some("https://localhost"),
            user_agent: None,
            accept_language: None,
            extra_headers: &[],
            tls_profile: TlsClientProfile::Firefox136,
        });
        let conn = req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(conn.to_ascii_lowercase().contains("upgrade"));
        assert!(!req.headers().contains_key("Sec-CH-UA"));
    }

    #[test]
    fn extra_headers_are_appended() {
        let extras = [("Cookie".to_string(), "a=b".to_string())];
        let req = build_websocket_request(WsHandshakeParams {
            host_for_tcp: "h",
            port: 443,
            path: "/ws",
            sni: "h",
            host_header: None,
            origin: None,
            user_agent: None,
            accept_language: None,
            extra_headers: &extras,
            tls_profile: TlsClientProfile::Default,
        });
        assert_eq!(
            req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok()),
            Some("a=b")
        );
    }

    #[test]
    fn browser_websocket_request_backward_compat() {
        let req = browser_websocket_request("host", 443, "/ws", "host");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri().to_string(), "wss://host:443/ws");
    }

    #[test]
    fn decoy_browser_chrome_matches_ws_client_hints() {
        let s = format_decoy_get_request(
            "/",
            "vpn.example.com",
            "vpn.example.com",
            default_user_agent_for_profile(TlsClientProfile::Chrome132),
            DEFAULT_ACCEPT_LANGUAGE,
            TlsClientProfile::Chrome132,
            DecoyMode::Browser,
        );
        assert!(s.contains("Sec-CH-UA:"), "{s:?}");
        assert!(s.contains("Sec-Fetch-Site: same-origin"), "{s:?}");
    }

    #[test]
    fn decoy_browser_firefox_has_no_client_hints() {
        let s = format_decoy_get_request(
            "/",
            "vpn.example.com",
            "vpn.example.com",
            default_user_agent_for_profile(TlsClientProfile::Firefox136),
            DEFAULT_ACCEPT_LANGUAGE,
            TlsClientProfile::Firefox136,
            DecoyMode::Browser,
        );
        assert!(!s.contains("Sec-CH-UA:"), "{s:?}");
    }
}
