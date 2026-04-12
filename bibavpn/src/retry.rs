//! Exponential backoff between outbound TCP+TLS+WSS connection attempts and optional WS timing jitter.

use rand::Rng;
use tokio::time::{sleep, Duration};

/// Outbound TCP+TLS+WSS attempts before giving up.
pub(crate) const OUTBOUND_CONNECT_ATTEMPTS: u32 = 12;

pub(crate) fn outbound_backoff_duration(attempt: u32) -> Duration {
    let base_ms = 200u64;
    let cap_ms = 30_000u64;
    let exp = (base_ms * 2u64.pow(attempt.min(10))).min(cap_ms);
    let jitter = rand::thread_rng().gen_range(0..=exp / 4);
    Duration::from_millis(exp + jitter)
}

pub(crate) async fn sleep_outbound_backoff(attempt: u32) {
    sleep(outbound_backoff_duration(attempt)).await;
}

/// Random WS ping period around `base_secs` within ±`jitter_percent` (clamped to 0–50). Lower bound at least 1s.
pub(crate) fn ws_ping_period_duration(base_secs: u64, jitter_percent: u8) -> Duration {
    let p = jitter_percent.min(50) as u64;
    let lo = base_secs.saturating_mul(100 - p) / 100;
    let hi = base_secs.saturating_mul(100 + p) / 100;
    let lo = lo.max(1);
    let hi = hi.max(lo);
    Duration::from_secs(rand::thread_rng().gen_range(lo..=hi))
}

pub(crate) async fn sleep_ws_ping_period(base_secs: u64, jitter_percent: u8) {
    sleep(ws_ping_period_duration(base_secs, jitter_percent)).await;
}

/// Optional delay before sending the next WS binary frame (uniform 0..=max_ms).
pub(crate) async fn maybe_ws_binary_send_jitter(max_ms: u8) {
    if max_ms == 0 {
        return;
    }
    let ms = rand::thread_rng().gen_range(0..=max_ms) as u64;
    sleep(Duration::from_millis(ms)).await;
}
