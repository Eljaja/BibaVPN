//! HTTP responses that look like a generic nginx site (wrong-path / probing).

use std::time::{SystemTime, UNIX_EPOCH};

use tokio_tungstenite::tungstenite::handshake::server::ErrorResponse;

/// `Server:` value used by every camouflage response.
pub const SERVER_TOKEN: &str = "nginx/1.24.0";

/// Reject WebSocket upgrade with a realistic 404 HTML body (nginx-style headers).
///
/// Header order and name casing are decided by `http::HeaderMap` + tungstenite's
/// writer (lowercase names, map order), so only the header *set* can be matched
/// here; the hand-rolled responses in `incoming` control order exactly.
pub fn ws_reject_not_found() -> ErrorResponse {
    http::Response::builder()
        .status(404)
        .header("Server", SERVER_TOKEN)
        .header("Date", http_date_now())
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Content-Length", NOT_FOUND_HTML.len().to_string())
        .header("Connection", "close")
        .body(Some(NOT_FOUND_HTML.to_string()))
        .expect("response")
}

/// nginx's built-in error page (`ngx_http_special_response.c`): CRLF line
/// endings, no DOCTYPE, title and `<h1>` both carry "<code> <reason>".
macro_rules! nginx_error_page {
    ($title:expr) => {
        concat!(
            "<html>\r\n",
            "<head><title>",
            $title,
            "</title></head>\r\n",
            "<body>\r\n",
            "<center><h1>",
            $title,
            "</h1></center>\r\n",
            "<hr><center>nginx/1.24.0</center>\r\n",
            "</body>\r\n",
            "</html>\r\n",
        )
    };
}

pub const BAD_REQUEST_HTML: &str = nginx_error_page!("400 Bad Request");
pub const FORBIDDEN_HTML: &str = nginx_error_page!("403 Forbidden");
pub const NOT_FOUND_HTML: &str = nginx_error_page!("404 Not Found");
pub const NOT_ALLOWED_HTML: &str = nginx_error_page!("405 Not Allowed");
pub const RANGE_NOT_SATISFIABLE_HTML: &str =
    nginx_error_page!("416 Requested Range Not Satisfiable");
pub const INTERNAL_ERROR_HTML: &str = nginx_error_page!("500 Internal Server Error");

/// Reason phrase in nginx's wording (`ngx_http_status_lines`). Note 405 is
/// "Not Allowed", not the RFC's "Method Not Allowed".
pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        416 => "Requested Range Not Satisfiable",
        // Not emitted by this crate; never claim a reason that contradicts the code.
        _ => "Internal Server Error",
    }
}

/// Error page body for a status code, plus the code actually to be sent.
/// Codes without a page collapse to 404 so status, reason and body always agree.
pub fn error_page(code: u16) -> (u16, &'static str) {
    match code {
        400 => (400, BAD_REQUEST_HTML),
        403 => (403, FORBIDDEN_HTML),
        405 => (405, NOT_ALLOWED_HTML),
        416 => (416, RANGE_NOT_SATISFIABLE_HTML),
        500 => (500, INTERNAL_ERROR_HTML),
        _ => (404, NOT_FOUND_HTML),
    }
}

/// Seconds since the Unix epoch (0 if the clock is before 1970).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `Date` header value for now. nginx sends one on every response, 101 included.
pub fn http_date_now() -> String {
    format_http_date(unix_now())
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// RFC 9110 IMF-fixdate, always GMT: `Tue, 15 Nov 1994 08:12:31 GMT`.
pub fn format_http_date(unix_secs: u64) -> String {
    const DAY: u64 = 86_400;
    let days = (unix_secs / DAY) as i64;
    let tod = unix_secs % DAY;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // 1970-01-01 was a Thursday (index 4).
    let wday = WEEKDAYS[((days + 4).rem_euclid(7)) as usize];
    let (year, month, day) = civil_from_days(days);
    let mon = MONTHS[(month - 1) as usize];
    format!("{wday}, {day:02} {mon} {year:04} {hh:02}:{mm:02}:{ss:02} GMT")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year (Mar-based), [0, 365]
    let mp = (5 * doy + 2) / 153; // Mar-based month, [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if month <= 2 { y + 1 } else { y }, month, day)
}

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
        assert!(r
            .body()
            .as_ref()
            .is_some_and(|b| b.contains("404 Not Found")));
    }

    #[test]
    fn ws_reject_carries_date_and_length() {
        let r = ws_reject_not_found();
        let date = r
            .headers()
            .get("Date")
            .and_then(|v| v.to_str().ok())
            .expect("Date header");
        assert!(date.ends_with(" GMT"), "not IMF-fixdate: {date}");
        assert_eq!(date.len(), 29, "not IMF-fixdate: {date}");
        let expected_len = NOT_FOUND_HTML.len().to_string();
        assert_eq!(
            r.headers()
                .get("Content-Length")
                .and_then(|v| v.to_str().ok()),
            Some(expected_len.as_str())
        );
    }

    #[test]
    fn html_ok_index_looks_like_nginx() {
        let (code, body) = html_ok_index();
        assert_eq!(code, http::StatusCode::OK);
        assert!(body.contains("nginx/1.24.0"));
    }

    #[test]
    fn http_date_matches_known_timestamps() {
        // RFC 9110's own example.
        assert_eq!(
            format_http_date(784_887_151),
            "Tue, 15 Nov 1994 08:12:31 GMT"
        );
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // Year boundary, both sides.
        assert_eq!(
            format_http_date(946_684_799),
            "Fri, 31 Dec 1999 23:59:59 GMT"
        );
        assert_eq!(
            format_http_date(946_684_800),
            "Sat, 01 Jan 2000 00:00:00 GMT"
        );
        // Leap day in a century leap year (divisible by 400).
        assert_eq!(
            format_http_date(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
        // Leap day in an ordinary leap year.
        assert_eq!(
            format_http_date(1_709_164_800),
            "Thu, 29 Feb 2024 00:00:00 GMT"
        );
        // Day after that leap day, and end of that day.
        assert_eq!(
            format_http_date(1_709_251_199),
            "Thu, 29 Feb 2024 23:59:59 GMT"
        );
        assert_eq!(
            format_http_date(1_709_251_200),
            "Fri, 01 Mar 2024 00:00:00 GMT"
        );
        // Non-leap century year: 1900 is not a leap year, so 2100-03-01 is
        // 366 days after 2099-03-01 minus the missing leap day.
        assert_eq!(
            format_http_date(4_107_542_400),
            "Mon, 01 Mar 2100 00:00:00 GMT"
        );
    }

    #[test]
    fn http_date_is_fixed_width() {
        for secs in [0u64, 1, 784_887_151, 1_709_164_800, 4_107_542_400] {
            assert_eq!(format_http_date(secs).len(), 29);
        }
    }

    #[test]
    fn error_pages_agree_with_status() {
        for code in [400u16, 403, 404, 405, 416, 500] {
            let (sent, body) = error_page(code);
            assert_eq!(sent, code);
            let title = format!("{code} {}", reason_phrase(code));
            assert!(
                body.contains(&format!("<title>{title}</title>")),
                "{code}: {body}"
            );
            assert!(
                body.contains(&format!("<h1>{title}</h1>")),
                "{code}: {body}"
            );
        }
    }

    #[test]
    fn error_page_405_is_not_the_404_body() {
        let (code, body) = error_page(405);
        assert_eq!(code, 405);
        assert_eq!(reason_phrase(405), "Not Allowed");
        assert!(body.contains("405 Not Allowed"));
        assert!(!body.contains("404"));
        assert_ne!(body, NOT_FOUND_HTML);
    }

    #[test]
    fn unknown_status_collapses_to_404() {
        assert_eq!(error_page(418), (404, NOT_FOUND_HTML));
    }

    #[test]
    fn error_pages_use_crlf_and_no_doctype() {
        for body in [
            BAD_REQUEST_HTML,
            FORBIDDEN_HTML,
            NOT_FOUND_HTML,
            NOT_ALLOWED_HTML,
            RANGE_NOT_SATISFIABLE_HTML,
            INTERNAL_ERROR_HTML,
        ] {
            assert!(body.starts_with("<html>\r\n"), "{body}");
            assert!(body.ends_with("</html>\r\n"), "{body}");
            assert!(!body.contains("DOCTYPE"), "{body}");
            assert_eq!(body.matches('\n').count(), body.matches("\r\n").count());
        }
        // nginx/1.24.0 serves exactly 153 bytes for its built-in 404 page.
        assert_eq!(NOT_FOUND_HTML.len(), 153);
    }
}
