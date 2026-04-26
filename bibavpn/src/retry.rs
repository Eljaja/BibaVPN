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

/// Outbound WebSocket send timing: optional **range** (min..=max) or legacy **uniform 0..=N** ms.
#[derive(Clone, Copy, Debug, Default)]
pub struct WsSendJitter {
    /// When both `min_ms` and `max_ms` are non-zero and `min_ms <= max_ms`, sleep in that range.
    pub min_ms: u8,
    pub max_ms: u8,
    /// If range is not used, sleep `0..=legacy_0_to_max` ms (BibaV2.1).
    pub legacy_0_to_max: u8,
}

pub(crate) async fn maybe_ws_send_jitter(j: WsSendJitter) {
    if j.min_ms > 0 && j.max_ms >= j.min_ms {
        let ms = rand::thread_rng().gen_range(j.min_ms as u64..=j.max_ms as u64);
        sleep(Duration::from_millis(ms)).await;
        return;
    }
    maybe_ws_binary_send_jitter(j.legacy_0_to_max).await;
}

/// Optional delay before sending the next WS binary frame (uniform 0..=max_ms).
pub(crate) async fn maybe_ws_binary_send_jitter(max_ms: u8) {
    if max_ms == 0 {
        return;
    }
    let ms = rand::thread_rng().gen_range(0..=max_ms) as u64;
    sleep(Duration::from_millis(ms)).await;
}

/// Server → client: optional delay before each outbound binary (application-level “delayed ACK buffer” analog).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerWsOutTiming {
    /// Inclusive random delay in `[min_ms, max_ms]` before each binary (0,0 = off; supports 40–500+ ms).
    pub ack_delay_min_ms: u16,
    pub ack_delay_max_ms: u16,
    /// Extra uniform jitter 0..=`rtt_mask_jitter_ms` (stacked after ack delay, before WS send jitter).
    pub rtt_mask_jitter_ms: u16,
}

pub(crate) async fn maybe_server_ack_and_rtt_mask(t: ServerWsOutTiming) {
    if t.ack_delay_min_ms > 0 && t.ack_delay_max_ms >= t.ack_delay_min_ms {
        let ms = rand::thread_rng()
            .gen_range(t.ack_delay_min_ms as u64..=t.ack_delay_max_ms as u64);
        sleep(Duration::from_millis(ms)).await;
    }
    if t.rtt_mask_jitter_ms > 0 {
        let ms = rand::thread_rng().gen_range(0..=t.rtt_mask_jitter_ms as u64);
        sleep(Duration::from_millis(ms)).await;
    }
}
