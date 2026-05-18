//! HTTP responses that look like a generic nginx site (wrong-path / probing).

use tokio_tungstenite::tungstenite::handshake::server::ErrorResponse;

/// Reject WebSocket upgrade with a realistic404 HTML body (nginx-style headers).
pub fn ws_reject_not_found() -> ErrorResponse {
    http::Response::builder()
        .status(404)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Server", "nginx/1.24.0")
        .header("Connection", "close")
        .body(Some(NOT_FOUND_HTML.to_string()))
        .expect("response")
}

pub const NOT_FOUND_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
"#;

/// Minimal nginx-style 200 index (for GET / and static camouflage).
pub fn html_ok_index() -> (http::StatusCode, String) {
    (http::StatusCode::OK, INDEX_HTML.to_string())
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Welcome</title></head>
<body><h1>It works</h1><p>nginx/1.24.0</p></body>
</html>
"#;

/// Plain text for tiny assets (favicon, robots.txt).
pub fn text_plain_ok(body: &str) -> (http::StatusCode, String) {
    (http::StatusCode::OK, body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_reject_is_404_nginx() {
        let r = ws_reject_not_found();
        assert_eq!(r.status(), 404);
        assert_eq!(
            r.headers().get("Server").and_then(|v| v.to_str().ok()),
            Some("nginx/1.24.0")
        );
        assert!(r.body().as_ref().is_some_and(|b| b.contains("404 Not Found")));
    }

    #[test]
    fn html_ok_index_looks_like_nginx() {
        let (code, body) = html_ok_index();
        assert_eq!(code, http::StatusCode::OK);
        assert!(body.contains("nginx/1.24.0"));
    }
}
