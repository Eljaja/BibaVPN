//! Prometheus text exposition and optional HTTP listener for `bibavpn-server`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::server_limits::{AuthRateLimiter, ServerStats};

/// Upper bound for one metrics HTTP request (read + write). A client that opens
/// the socket and never finishes the request line must not pin a task forever.
const METRICS_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Concurrent metrics HTTP connections. Bounds the number of spawned tasks so a
/// connection burst cannot exhaust file descriptors/memory.
const METRICS_MAX_CONNECTIONS: usize = 32;

/// Pause after a failed `accept(2)` (e.g. EMFILE) so the loop cannot spin hot.
const METRICS_ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Failed Basic Auth attempts allowed per peer IP per window before delaying.
const METRICS_AUTH_FAILURE_BUDGET: u32 = 1;

/// Window over which [`METRICS_AUTH_FAILURE_BUDGET`] is counted.
const METRICS_AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// Added latency on unauthorized responses once a peer exceeded its budget.
const METRICS_AUTH_FAILURE_DELAY: Duration = Duration::from_secs(1);

/// Cap on remembered peer IPs; the oldest window is evicted when full.
const METRICS_AUTH_TRACKED_PEERS: usize = 256;

/// Build the metrics listener auth from the CLI password flag.
///
/// `None` (flag absent) means unauthenticated. An explicitly supplied empty
/// password is a configuration error, not a silent way to disable auth.
pub fn metrics_auth_from_password(
    password: Option<&str>,
    user: &str,
) -> anyhow::Result<MetricsAuth> {
    match password {
        None => Ok(MetricsAuth::disabled()),
        Some(pw) if !pw.trim().is_empty() => Ok(MetricsAuth::basic(user.trim(), pw)),
        Some(_) => {
            anyhow::bail!("--metrics-password must not be empty; omit it to disable metrics auth")
        }
    }
}

/// Optional HTTP Basic Auth for the metrics listener.
#[derive(Clone)]
pub struct MetricsAuth {
    /// Full `Authorization` header value bytes (`Basic …`), or `None` if auth is disabled.
    expected_authorization: Option<Vec<u8>>,
}

impl MetricsAuth {
    pub fn disabled() -> Self {
        Self {
            expected_authorization: None,
        }
    }

    pub fn basic(user: &str, password: &str) -> Self {
        let cred = format!("{user}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(cred.as_bytes());
        Self {
            expected_authorization: Some(format!("Basic {encoded}").into_bytes()),
        }
    }

    pub fn is_required(&self) -> bool {
        self.expected_authorization.is_some()
    }

    fn authorize(&self, headers: &[(&str, &str)]) -> bool {
        let Some(expected) = self.expected_authorization.as_ref() else {
            return true;
        };
        let Some(got) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_bytes())
        else {
            return false;
        };
        got.len() == expected.len() && got.ct_eq(expected).into()
    }
}

fn parse_http_headers(req: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for line in req.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim(), value.trim()));
        }
    }
    out
}

/// Render current counters/gauges in Prometheus text format 0.0.4.
pub fn render_prometheus(stats: &ServerStats, auth: &AuthRateLimiter) -> String {
    let process_start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64() - stats.started_at.elapsed().as_secs_f64())
        .unwrap_or(0.0);

    format!(
        "\
# HELP bibavpn_active_sessions Current TLS/WSS sessions being handled.
# TYPE bibavpn_active_sessions gauge
bibavpn_active_sessions {active_sessions}
# HELP bibavpn_auth_bans_active Source IPs currently under temporary auth ban.
# TYPE bibavpn_auth_bans_active gauge
bibavpn_auth_bans_active {auth_bans_active}
# HELP bibavpn_auth_failures_total v3 AUTH failures (token mismatch, junk budget, decrypt errors).
# TYPE bibavpn_auth_failures_total counter
bibavpn_auth_failures_total {auth_failures_total}
# HELP bibavpn_auth_bans_issued_total Temporary auth bans issued since process start.
# TYPE bibavpn_auth_bans_issued_total counter
bibavpn_auth_bans_issued_total {auth_bans_issued_total}
# HELP bibavpn_handshake_timeouts_total Sessions that exceeded a pre-tunnel timeout (TLS, WS upgrade, REALITY, AUTH wait, post-AUTH first-channel wait).
# TYPE bibavpn_handshake_timeouts_total counter
bibavpn_handshake_timeouts_total {handshake_timeouts_total}
# HELP bibavpn_auth_rejected_banned_total Connections rejected because the source IP is banned.
# TYPE bibavpn_auth_rejected_banned_total counter
bibavpn_auth_rejected_banned_total {auth_rejected_banned_total}
# HELP bibavpn_sessions_rejected_busy_total Connections dropped waiting for the concurrent session semaphore.
# TYPE bibavpn_sessions_rejected_busy_total counter
bibavpn_sessions_rejected_busy_total {sessions_rejected_busy_total}
# HELP bibavpn_handshakes_success_total Successful v3 AUTH completions.
# TYPE bibavpn_handshakes_success_total counter
bibavpn_handshakes_success_total {handshakes_success_total}
# HELP bibavpn_session_errors_total Accepted sessions that ended with an error after TLS accept.
# TYPE bibavpn_session_errors_total counter
bibavpn_session_errors_total {session_errors_total}
# HELP bibavpn_accepts_failed_total Failed accept(2) calls the listener loop recovered from.
# TYPE bibavpn_accepts_failed_total counter
bibavpn_accepts_failed_total {accepts_failed_total}
# HELP bibavpn_process_start_time_seconds Start time of the process since the Unix epoch.
# TYPE bibavpn_process_start_time_seconds gauge
bibavpn_process_start_time_seconds {process_start}
",
        active_sessions = stats.active_sessions.load(std::sync::atomic::Ordering::Relaxed),
        auth_bans_active = auth.bans_active.load(std::sync::atomic::Ordering::Relaxed),
        auth_failures_total = auth
            .auth_failures_total
            .load(std::sync::atomic::Ordering::Relaxed),
        auth_bans_issued_total = auth
            .auth_bans_issued_total
            .load(std::sync::atomic::Ordering::Relaxed),
        handshake_timeouts_total = stats
            .handshake_timeouts_total
            .load(std::sync::atomic::Ordering::Relaxed),
        auth_rejected_banned_total = stats
            .auth_rejected_banned_total
            .load(std::sync::atomic::Ordering::Relaxed),
        sessions_rejected_busy_total = stats
            .sessions_rejected_busy_total
            .load(std::sync::atomic::Ordering::Relaxed),
        handshakes_success_total = stats
            .handshakes_success_total
            .load(std::sync::atomic::Ordering::Relaxed),
        session_errors_total = stats
            .session_errors_total
            .load(std::sync::atomic::Ordering::Relaxed),
        accepts_failed_total = stats
            .accepts_failed_total
            .load(std::sync::atomic::Ordering::Relaxed),
        process_start = process_start,
    )
}

/// Per-peer accounting of failed Basic Auth attempts on the metrics listener.
///
/// Deliberately separate from the tunnel's [`AuthRateLimiter`]: a scanner
/// hammering the metrics port must never ban real tunnel clients.
struct MetricsAuthThrottle {
    peers: Mutex<HashMap<IpAddr, AuthFailureWindow>>,
    budget: u32,
    window: Duration,
    max_peers: usize,
}

struct AuthFailureWindow {
    failures: u32,
    started: Instant,
}

impl MetricsAuthThrottle {
    fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            budget: METRICS_AUTH_FAILURE_BUDGET,
            window: METRICS_AUTH_FAILURE_WINDOW,
            max_peers: METRICS_AUTH_TRACKED_PEERS,
        }
    }

    /// Account a failed attempt and return how long the 401 response is stalled.
    fn record_failure(&self, peer: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if peers.len() >= self.max_peers && !peers.contains_key(&peer) {
            self.evict(&mut peers, now);
        }
        let window = peers.entry(peer).or_insert_with(|| AuthFailureWindow {
            failures: 0,
            started: now,
        });
        if now.duration_since(window.started) >= self.window {
            *window = AuthFailureWindow {
                failures: 0,
                started: now,
            };
        }
        window.failures = window.failures.saturating_add(1);
        (window.failures > self.budget).then_some(METRICS_AUTH_FAILURE_DELAY)
    }

    /// Drop expired windows, then the oldest one, to make room for a new peer.
    fn evict(&self, peers: &mut HashMap<IpAddr, AuthFailureWindow>, now: Instant) {
        peers.retain(|_, w| now.duration_since(w.started) < self.window);
        if peers.len() >= self.max_peers {
            let oldest = peers
                .iter()
                .min_by_key(|(_, w)| w.started)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest {
                peers.remove(&ip);
            }
        }
    }
}

/// Whether the bound metrics address is reachable from other hosts.
fn is_off_host(addr: &std::net::SocketAddr) -> bool {
    !addr.ip().is_loopback()
}

/// Spawn a background HTTP listener serving `GET /metrics` and `GET /healthz`.
pub fn spawn_metrics_listener(
    listen: String,
    stats: Arc<ServerStats>,
    auth: Arc<AuthRateLimiter>,
    metrics_auth: MetricsAuth,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                warn!(
                    target: "bibavpn_server",
                    %listen,
                    "metrics listener bind failed: {e:#}"
                );
                return;
            }
        };
        if metrics_auth.is_required() {
            if let Ok(local) = listener.local_addr() {
                if is_off_host(&local) {
                    warn!(
                        target: "bibavpn_security",
                        %local,
                        "metrics listener is reachable off-host with HTTP Basic Auth over plaintext; credentials are sent unencrypted — bind loopback or front it with TLS/SSH"
                    );
                }
            }
            info!(
                target: "bibavpn_server",
                %listen,
                "Prometheus metrics listening with HTTP Basic Auth (GET /metrics, GET /healthz)"
            );
        } else {
            if let Ok(local) = listener.local_addr() {
                if is_off_host(&local) {
                    warn!(
                        target: "bibavpn_security",
                        %local,
                        "metrics listener is reachable off-host without auth; set --metrics-password or bind loopback"
                    );
                }
            }
            info!(
                target: "bibavpn_server",
                %listen,
                "Prometheus metrics listening (GET /metrics, GET /healthz; no auth — use --metrics-password in production)"
            );
        }
        let semaphore = Arc::new(Semaphore::new(METRICS_MAX_CONNECTIONS));
        let throttle = Arc::new(MetricsAuthThrottle::new());
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    debug!(
                        target: "bibavpn_server",
                        %listen,
                        "metrics listener accept failed: {e:#}"
                    );
                    tokio::time::sleep(METRICS_ACCEPT_BACKOFF).await;
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                break;
            };
            let stats = Arc::clone(&stats);
            let auth = Arc::clone(&auth);
            let metrics_auth = metrics_auth.clone();
            let throttle = Arc::clone(&throttle);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = serve_one_with_timeout(
                    stream,
                    &stats,
                    &auth,
                    &metrics_auth,
                    &throttle,
                    METRICS_REQUEST_TIMEOUT,
                )
                .await
                {
                    debug!(
                        target: "bibavpn_server",
                        %peer,
                        "metrics HTTP: {e:#}"
                    );
                }
            });
        }
    })
}

async fn serve_one_with_timeout(
    stream: TcpStream,
    stats: &ServerStats,
    auth: &AuthRateLimiter,
    metrics_auth: &MetricsAuth,
    throttle: &MetricsAuthThrottle,
    dur: Duration,
) -> anyhow::Result<()> {
    let fut = serve_one_http(stream, stats, auth, metrics_auth, throttle);
    match tokio::time::timeout(dur, fut).await {
        Ok(r) => r,
        Err(_) => anyhow::bail!("metrics HTTP request timed out"),
    }
}

async fn serve_one_http(
    mut stream: TcpStream,
    stats: &ServerStats,
    auth: &AuthRateLimiter,
    metrics_auth: &MetricsAuth,
    throttle: &MetricsAuthThrottle,
) -> anyhow::Result<()> {
    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let headers = parse_http_headers(req);
    let mut lines = req.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method != "GET" {
        write_http_response(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
            &[],
        )
        .await?;
        return Ok(());
    }

    if !metrics_auth.authorize(&headers) {
        if let Some(ip) = peer_ip {
            if let Some(delay) = throttle.record_failure(ip) {
                tokio::time::sleep(delay).await;
            }
        }
        write_http_response(
            &mut stream,
            401,
            "text/plain; charset=utf-8",
            b"unauthorized",
            &[("WWW-Authenticate", r#"Basic realm="bibavpn-metrics""#)],
        )
        .await?;
        return Ok(());
    }

    match path {
        "/metrics" => {
            let body = render_prometheus(stats, auth);
            write_http_response(
                &mut stream,
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                body.as_bytes(),
                &[],
            )
            .await?;
        }
        "/healthz" => {
            write_http_response(&mut stream, 200, "text/plain; charset=utf-8", b"ok", &[]).await?;
        }
        _ => {
            write_http_response(
                &mut stream,
                404,
                "text/plain; charset=utf-8",
                b"not found",
                &[],
            )
            .await?;
        }
    }
    Ok(())
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let mut header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        header.push_str(&format!("{name}: {value}\r\n"));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_limits::AuthRateLimiterConfig;

    #[test]
    fn prometheus_render_contains_core_metrics() {
        let stats = ServerStats::new();
        let auth = AuthRateLimiter::new(AuthRateLimiterConfig {
            enabled: true,
            ..Default::default()
        });
        stats.inc_handshake_success();
        stats.inc_accept_failed();
        auth.auth_failures_total
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);

        let text = render_prometheus(&stats, &auth);
        assert!(text.contains("bibavpn_active_sessions 0"));
        assert!(text.contains("bibavpn_handshakes_success_total 1"));
        assert!(text.contains("bibavpn_accepts_failed_total 1"));
        assert!(text.contains("bibavpn_auth_failures_total 2"));
        assert!(text.contains("# TYPE bibavpn_active_sessions gauge"));
        assert!(text.contains("# TYPE bibavpn_auth_failures_total counter"));
    }

    #[tokio::test]
    async fn metrics_http_healthz_and_metrics() {
        let stats = ServerStats::new();
        let auth = AuthRateLimiter::new(AuthRateLimiterConfig::default());
        let metrics_auth = MetricsAuth::disabled();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stats_c = Arc::clone(&stats);
        let auth_c = Arc::clone(&auth);
        let throttle = MetricsAuthThrottle::new();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_one_http(stream, &stats_c, &auth_c, &metrics_auth, &throttle)
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        let text = std::str::from_utf8(&resp).unwrap();
        assert!(text.contains("200 OK"));
        assert!(text.contains("ok"));
    }

    #[tokio::test]
    async fn metrics_http_requires_password_when_configured() {
        let stats = ServerStats::new();
        let auth = AuthRateLimiter::new(AuthRateLimiterConfig::default());
        let metrics_auth = MetricsAuth::basic("metrics", "s3cret");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Unauthorized request.
        let stats_c = Arc::clone(&stats);
        let auth_c = Arc::clone(&auth);
        let metrics_auth_c = metrics_auth.clone();
        let throttle = MetricsAuthThrottle::new();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_one_http(stream, &stats_c, &auth_c, &metrics_auth_c, &throttle)
                .await
                .unwrap();
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        let text = std::str::from_utf8(&resp).unwrap();
        assert!(text.contains("401 Unauthorized"));
        assert!(text.contains(r#"WWW-Authenticate: Basic realm="bibavpn-metrics""#));

        // Authorized request (listener moved into the server task to avoid accept races).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stats_c = Arc::clone(&stats);
        let auth_c = Arc::clone(&auth);
        let metrics_auth_ok = MetricsAuth::basic("metrics", "s3cret");
        let throttle = MetricsAuthThrottle::new();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_one_http(stream, &stats_c, &auth_c, &metrics_auth_ok, &throttle)
                .await
                .unwrap();
        });
        let cred = base64::engine::general_purpose::STANDARD.encode(b"metrics:s3cret");
        let req = format!(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {cred}\r\n\r\n"
        );
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        let text = std::str::from_utf8(&resp).unwrap();
        assert!(text.contains("200 OK"), "response: {text}");
        assert!(text.contains("bibavpn_active_sessions"), "response: {text}");
    }

    #[test]
    fn metrics_password_flag_validation() {
        assert!(!metrics_auth_from_password(None, "metrics")
            .unwrap()
            .is_required());
        assert!(metrics_auth_from_password(Some("s3cret"), "metrics")
            .unwrap()
            .is_required());
        assert!(metrics_auth_from_password(Some(""), "metrics").is_err());
        assert!(metrics_auth_from_password(Some("   "), "metrics").is_err());
    }

    #[tokio::test]
    async fn silent_metrics_client_times_out() {
        let stats = ServerStats::new();
        let auth = AuthRateLimiter::new(AuthRateLimiterConfig::default());
        let metrics_auth = MetricsAuth::disabled();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_one_with_timeout(
                stream,
                &stats,
                &auth,
                &metrics_auth,
                &MetricsAuthThrottle::new(),
                std::time::Duration::from_millis(50),
            )
            .await
        });
        // Connect but never send a request line.
        let _client = TcpStream::connect(addr).await.unwrap();
        let start = std::time::Instant::now();
        let err = server.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("timed out"), "unexpected: {err:#}");
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn metrics_auth_basic_compare() {
        let auth = MetricsAuth::basic("metrics", "s3cret");
        let cred = base64::engine::general_purpose::STANDARD.encode(b"metrics:s3cret");
        let headers = [("Authorization", format!("Basic {cred}"))];
        let hdrs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert!(auth.authorize(&hdrs));
        assert!(!auth.authorize(&[("Authorization", "Basic wrong")]));
    }

    fn test_throttle(budget: u32, window: Duration, max_peers: usize) -> MetricsAuthThrottle {
        MetricsAuthThrottle {
            peers: Mutex::new(HashMap::new()),
            budget,
            window,
            max_peers,
        }
    }

    #[test]
    fn metrics_listener_off_host_detection() {
        let parse = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        assert!(!is_off_host(&parse("127.0.0.1:9100")));
        assert!(!is_off_host(&parse("[::1]:9100")));
        assert!(is_off_host(&parse("0.0.0.0:9100")));
        assert!(is_off_host(&parse("[::]:9100")));
    }

    #[test]
    fn metrics_auth_throttle_allows_budget_then_delays() {
        let throttle = test_throttle(1, Duration::from_secs(60), 8);
        let peer: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(throttle.record_failure(peer).is_none());
        assert_eq!(
            throttle.record_failure(peer),
            Some(METRICS_AUTH_FAILURE_DELAY)
        );
        // Budgets are per peer: another source starts fresh.
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(throttle.record_failure(other).is_none());
    }

    #[tokio::test]
    async fn metrics_auth_throttle_restores_budget_after_window() {
        let throttle = test_throttle(1, Duration::from_millis(20), 8);
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(throttle.record_failure(peer).is_none());
        assert!(throttle.record_failure(peer).is_some());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(throttle.record_failure(peer).is_none());
    }

    #[test]
    fn metrics_auth_throttle_caps_tracked_peers() {
        let throttle = test_throttle(1, Duration::from_secs(60), 3);
        for last in 0..50u8 {
            let _ = throttle.record_failure(IpAddr::from([203, 0, 113, last]));
        }
        let peers = throttle.peers.lock().unwrap();
        assert!(peers.len() <= 3, "tracked {} peers", peers.len());
    }
}
