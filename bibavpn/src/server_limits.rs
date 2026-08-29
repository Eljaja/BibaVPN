//! Per-source auth rate limiting (IPv4 /32, IPv6 /64), handshake junk budgets,
//! and server-wide session counters.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::crypto_layer;

/// Sliding window: `max_failures` within `window`, then ban for `ban`.
/// Counted per source bucket (IPv4 /32, IPv6 /64), see [`auth_limit_key`].
#[derive(Debug, Clone)]
pub struct AuthRateLimiterConfig {
    pub enabled: bool,
    pub max_failures: u32,
    pub window: Duration,
    pub ban: Duration,
}

impl Default for AuthRateLimiterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failures: 10,
            window: Duration::from_secs(60),
            ban: Duration::from_secs(300),
        }
    }
}

struct IpAuthState {
    failures: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

/// Hard cap on tracked source IPs, to bound memory under IP-rotation floods
/// (e.g. an attacker cycling through a /64). Without this the map only ever
/// shrank on a *successful* auth, so failed handshakes grew it without bound.
const MAX_TRACKED_IPS: usize = 100_000;

/// Prefix length used to bucket IPv6 peers for auth accounting. A /64 is the
/// smallest end-site allocation that is routed on the public internet (a single
/// host normally gets one, and /48s are common), so every address an attacker
/// can source without extra routing shares one bucket. Anything longer would
/// let a single host mint a fresh failure budget per source address.
const IPV6_AUTH_PREFIX_BITS: u32 = 64;

/// Zero all bits below `prefix_bits` of an IPv6 address. `prefix_bits >= 128`
/// keeps the address as-is; `0` collapses everything to `::`.
fn mask_ipv6(addr: Ipv6Addr, prefix_bits: u32) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = match 128u32.checked_sub(prefix_bits) {
        Some(shift) if shift < 128 => !0u128 << shift,
        // /0: one bucket for everything.
        Some(_) => 0,
        // Longer than /128: no masking.
        None => !0u128,
    };
    Ipv6Addr::from(bits & mask)
}

/// Bucket key under which auth failures and bans are accounted.
///
/// IPv4 keeps full /32 precision. IPv6 is masked to `IPV6_AUTH_PREFIX_BITS`,
/// otherwise a peer with a routed prefix gets a fresh failure window per source
/// address and `max_failures` never triggers.
///
/// IPv4-mapped peers (`::ffff:203.0.113.1`, seen on dual-stack sockets) are
/// canonicalized to their IPv4 form *before* masking, so they share a bucket
/// with the plain IPv4 address instead of collapsing the whole IPv4 space into
/// one `::ffff:0:0/64` bucket. IPv4-compatible (`::a.b.c.d`) is deprecated and
/// not routed, so it is left to fall into the `::/64` bucket: stricter than
/// per-address, never looser.
pub fn auth_limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(mask_ipv6(v6, IPV6_AUTH_PREFIX_BITS)),
        },
    }
}

pub struct AuthRateLimiter {
    cfg: AuthRateLimiterConfig,
    /// Keyed by [`auth_limit_key`], not by the raw peer address.
    inner: Mutex<HashMap<IpAddr, IpAuthState>>,
    pub bans_active: AtomicU64,
    pub auth_failures_total: AtomicU64,
    pub auth_bans_issued_total: AtomicU64,
}

impl AuthRateLimiter {
    pub fn new(cfg: AuthRateLimiterConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            inner: Mutex::new(HashMap::new()),
            bans_active: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            auth_bans_issued_total: AtomicU64::new(0),
        })
    }

    /// Fail fast if the peer's bucket is banned; clear expired bans.
    pub async fn check_allowed(self: &Arc<Self>, ip: IpAddr) -> anyhow::Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }
        let key = auth_limit_key(ip);
        let mut g = self.inner.lock().await;
        let now = Instant::now();
        let st = match g.get_mut(&key) {
            Some(s) => s,
            None => return Ok(()),
        };
        if let Some(until) = st.banned_until {
            if now < until {
                anyhow::bail!("temporarily banned (too many auth failures)");
            }
            st.banned_until = None;
            st.failures = 0;
            self.bans_active.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Drop entries that no longer carry state: expired (uncleared) bans and
    /// idle windows. Keeps active bans and in-progress windows. Adjusts
    /// `bans_active` for any expired ban it reaps.
    fn prune_locked(&self, g: &mut HashMap<IpAddr, IpAuthState>, now: Instant) {
        g.retain(|_, st| match st.banned_until {
            Some(until) if now < until => true,
            Some(_) => {
                // Ban expired but was never cleared, so it is still counted.
                let _ = self.bans_active.fetch_sub(1, Ordering::Relaxed);
                false
            }
            None => now.duration_since(st.window_start) <= self.cfg.window,
        });
    }

    pub async fn record_failure(self: &Arc<Self>, ip: IpAddr) {
        if !self.cfg.enabled {
            return;
        }
        let key = auth_limit_key(ip);
        let mut g = self.inner.lock().await;
        let now = Instant::now();
        if g.len() >= MAX_TRACKED_IPS && !g.contains_key(&key) {
            self.prune_locked(&mut g, now);
            if g.len() >= MAX_TRACKED_IPS {
                // Still full of active windows/bans: evict the oldest entry that
                // is not currently banned, rather than grow past the cap.
                let victim = g
                    .iter()
                    .filter(|(_, s)| s.banned_until.map_or(true, |u| now >= u))
                    .min_by_key(|(_, s)| s.window_start)
                    .map(|(k, _)| *k);
                match victim {
                    Some(k) => {
                        g.remove(&k);
                    }
                    // Everything tracked is actively banned; the table is already
                    // doing its job. Skip recording this new IP to stay bounded.
                    None => return,
                }
            }
        }
        let st = g.entry(key).or_insert(IpAuthState {
            failures: 0,
            window_start: now,
            banned_until: None,
        });
        if let Some(until) = st.banned_until {
            if now < until {
                return;
            }
            st.banned_until = None;
            let _ = self.bans_active.fetch_sub(1, Ordering::Relaxed);
        }
        if now.duration_since(st.window_start) > self.cfg.window {
            st.failures = 0;
            st.window_start = now;
        }
        st.failures = st.failures.saturating_add(1);
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
        if st.failures >= self.cfg.max_failures {
            st.banned_until = Some(now + self.cfg.ban);
            st.failures = 0;
            st.window_start = now;
            self.bans_active.fetch_add(1, Ordering::Relaxed);
            self.auth_bans_issued_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Clear the bucket's failure state after successful AUTH (entry removed).
    pub async fn record_success(self: &Arc<Self>, ip: IpAddr) {
        if !self.cfg.enabled {
            return;
        }
        let key = auth_limit_key(ip);
        let mut g = self.inner.lock().await;
        if let Some(st) = g.remove(&key) {
            if let Some(until) = st.banned_until {
                if Instant::now() < until {
                    let _ = self.bans_active.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Budget for junk / failed decrypt before v3 AUTH completes.
#[derive(Debug, Clone)]
pub struct PreAuthBudget {
    pub max_junk_frames: u32,
    pub max_junk_bytes: usize,
    pub max_decrypt_failures: u32,
}

impl Default for PreAuthBudget {
    fn default() -> Self {
        Self {
            max_junk_frames: 256,
            max_junk_bytes: 256 * 1024,
            max_decrypt_failures: 64,
        }
    }
}

#[derive(Debug, Default)]
pub struct PreAuthBudgetTracker {
    pub junk_frames: u32,
    pub junk_bytes: usize,
    pub decrypt_failures: u32,
}

impl PreAuthBudgetTracker {
    pub fn note_binary_frame(&mut self, len: usize, budget: &PreAuthBudget) -> anyhow::Result<()> {
        self.junk_frames = self.junk_frames.saturating_add(1);
        self.junk_bytes = self.junk_bytes.saturating_add(len);
        if self.junk_frames > budget.max_junk_frames || self.junk_bytes > budget.max_junk_bytes {
            anyhow::bail!("too much pre-auth data before v3 AUTH");
        }
        Ok(())
    }

    pub fn note_decrypt_failure(&mut self, budget: &PreAuthBudget) -> anyhow::Result<()> {
        self.decrypt_failures = self.decrypt_failures.saturating_add(1);
        if self.decrypt_failures > budget.max_decrypt_failures {
            anyhow::bail!("too many failed decrypt attempts before v3 AUTH");
        }
        Ok(())
    }
}

/// Hard cap on junk binary frames before a well-formed v3 HELLO.
pub const MAX_PRE_HELLO_FRAMES: u32 = 256;
/// Hard cap on junk bytes before a well-formed v3 HELLO.
pub const MAX_PRE_HELLO_BYTES: usize = 256 * 1024;
/// Bail message when either pre-HELLO cap is exceeded.
pub const PRE_HELLO_CAP_ERR: &str = "too much pre-handshake data before v3 HELLO";

#[derive(Debug, Default)]
pub struct PreHelloJunkTracker {
    pub junk_frames: u32,
    pub junk_bytes: usize,
}

/// Classify one pre-HELLO WebSocket binary: accept a well-formed HELLO, count
/// everything else as junk, and bail when caps are exceeded.
pub fn account_pre_hello_binary(
    frame: &[u8],
    tracker: &mut PreHelloJunkTracker,
    max_frames: u32,
    max_bytes: usize,
) -> anyhow::Result<Option<[u8; 32]>> {
    if let Ok(client_random) = crypto_layer::parse_hello_v3(frame) {
        return Ok(Some(client_random));
    }
    tracker.junk_frames = tracker.junk_frames.saturating_add(1);
    tracker.junk_bytes = tracker.junk_bytes.saturating_add(frame.len());
    if tracker.junk_frames > max_frames || tracker.junk_bytes > max_bytes {
        anyhow::bail!(PRE_HELLO_CAP_ERR);
    }
    Ok(None)
}

/// Counts live TLS/WSS sessions (increment when `handle_one` starts after permit, decrement on return).
pub struct ServerStats {
    pub active_sessions: AtomicU64,
    pub handshake_timeouts_total: AtomicU64,
    pub auth_rejected_banned_total: AtomicU64,
    pub sessions_rejected_busy_total: AtomicU64,
    pub handshakes_success_total: AtomicU64,
    pub session_errors_total: AtomicU64,
    /// Failed `accept(2)` calls the listener loop recovered from.
    pub accepts_failed_total: AtomicU64,
    pub started_at: Instant,
}

impl ServerStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active_sessions: AtomicU64::new(0),
            handshake_timeouts_total: AtomicU64::new(0),
            auth_rejected_banned_total: AtomicU64::new(0),
            sessions_rejected_busy_total: AtomicU64::new(0),
            handshakes_success_total: AtomicU64::new(0),
            session_errors_total: AtomicU64::new(0),
            accepts_failed_total: AtomicU64::new(0),
            started_at: Instant::now(),
        })
    }

    pub fn session_guard(self: &Arc<Self>) -> SessionGuard {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        SessionGuard {
            stats: Arc::clone(self),
        }
    }

    pub fn active_sessions(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
    }

    pub fn inc_handshake_timeout(&self) {
        self.handshake_timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_rejected_banned(&self) {
        self.auth_rejected_banned_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_sessions_rejected_busy(&self) {
        self.sessions_rejected_busy_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_handshake_success(&self) {
        self.handshakes_success_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_session_error(&self) {
        self.session_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_accept_failed(&self) {
        self.accepts_failed_total.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct SessionGuard {
    stats: Arc<ServerStats>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stats.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> IpAddr {
        auth_limit_key(s.parse().unwrap())
    }

    #[tokio::test]
    async fn rate_limit_ban_then_expire() {
        let cfg = AuthRateLimiterConfig {
            enabled: true,
            max_failures: 3,
            window: Duration::from_secs(60),
            ban: Duration::from_millis(50),
        };
        let lim = AuthRateLimiter::new(cfg);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();

        lim.check_allowed(ip).await.unwrap();
        lim.record_failure(ip).await;
        lim.record_failure(ip).await;
        lim.check_allowed(ip).await.unwrap();
        lim.record_failure(ip).await;
        assert!(lim.check_allowed(ip).await.is_err());

        tokio::time::sleep(Duration::from_millis(80)).await;
        lim.check_allowed(ip).await.unwrap();
    }

    #[tokio::test]
    async fn record_success_clears_failures() {
        let lim = AuthRateLimiter::new(AuthRateLimiterConfig {
            enabled: true,
            max_failures: 10,
            window: Duration::from_secs(60),
            ban: Duration::from_secs(300),
        });
        let ip: IpAddr = "198.51.100.2".parse().unwrap();
        lim.record_failure(ip).await;
        lim.record_failure(ip).await;
        lim.record_success(ip).await;
        lim.record_failure(ip).await;
        lim.check_allowed(ip).await.unwrap();
    }

    #[test]
    fn ipv6_keys_collapse_to_64() {
        // Same /64, different interface IDs: one bucket, equal to the prefix.
        let want: IpAddr = "2001:db8:1:2::".parse().unwrap();
        assert_eq!(key("2001:db8:1:2::1"), want);
        assert_eq!(key("2001:db8:1:2:ffff:ffff:ffff:ffff"), want);
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:dead:beef:1:2"));
    }

    #[test]
    fn ipv6_keys_differ_across_64s() {
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        // Neighbouring /48s too.
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:2:2::1"));
    }

    #[test]
    fn ipv4_keys_are_per_address() {
        assert_eq!(key("203.0.113.1"), "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_ne!(key("203.0.113.1"), key("203.0.113.2"));
    }

    #[test]
    fn ipv4_mapped_v6_shares_ipv4_bucket() {
        assert_eq!(key("::ffff:203.0.113.1"), key("203.0.113.1"));
        // ...and does not swallow the whole ::ffff:0:0/64 into one bucket.
        assert_ne!(key("::ffff:203.0.113.1"), key("::ffff:203.0.113.2"));
    }

    #[test]
    fn mask_ipv6_edge_prefixes() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(mask_ipv6(a, 128), a);
        assert_eq!(mask_ipv6(a, 0), Ipv6Addr::UNSPECIFIED);
        assert_eq!(mask_ipv6(a, 32), "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    #[tokio::test]
    async fn ipv6_rotation_within_64_is_banned() {
        let lim = AuthRateLimiter::new(AuthRateLimiterConfig {
            enabled: true,
            max_failures: 3,
            window: Duration::from_secs(60),
            ban: Duration::from_millis(50),
        });
        // Three failures spread over three distinct /128s in one /64.
        for a in ["2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2::3"] {
            let ip: IpAddr = a.parse().unwrap();
            lim.check_allowed(ip).await.unwrap();
            lim.record_failure(ip).await;
        }
        assert_eq!(lim.bans_active.load(Ordering::Relaxed), 1);
        assert_eq!(lim.auth_bans_issued_total.load(Ordering::Relaxed), 1);
        // A fourth, so far unseen address in the same /64 is banned too.
        let fresh: IpAddr = "2001:db8:1:2:aaaa::9".parse().unwrap();
        assert!(lim.check_allowed(fresh).await.is_err());

        tokio::time::sleep(Duration::from_millis(80)).await;
        lim.check_allowed(fresh).await.unwrap();
        assert_eq!(lim.bans_active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn ipv6_rotation_across_64s_is_not_banned() {
        let lim = AuthRateLimiter::new(AuthRateLimiterConfig {
            enabled: true,
            max_failures: 3,
            window: Duration::from_secs(60),
            ban: Duration::from_secs(300),
        });
        for a in ["2001:db8:1:1::1", "2001:db8:1:2::1", "2001:db8:1:3::1"] {
            let ip: IpAddr = a.parse().unwrap();
            lim.record_failure(ip).await;
            lim.check_allowed(ip).await.unwrap();
        }
        assert_eq!(lim.bans_active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn ipv4_addresses_stay_independent() {
        let lim = AuthRateLimiter::new(AuthRateLimiterConfig {
            enabled: true,
            max_failures: 2,
            window: Duration::from_secs(60),
            ban: Duration::from_secs(300),
        });
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        lim.record_failure(a).await;
        lim.record_failure(a).await;
        assert!(lim.check_allowed(a).await.is_err());
        // Same /24, unrelated bucket.
        lim.check_allowed(b).await.unwrap();
        assert_eq!(lim.bans_active.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ipv4_mapped_peer_shares_ban_with_ipv4() {
        let lim = AuthRateLimiter::new(AuthRateLimiterConfig {
            enabled: true,
            max_failures: 2,
            window: Duration::from_secs(60),
            ban: Duration::from_secs(300),
        });
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        let plain: IpAddr = "203.0.113.7".parse().unwrap();
        lim.record_failure(mapped).await;
        lim.record_failure(plain).await;
        assert!(lim.check_allowed(mapped).await.is_err());
        assert!(lim.check_allowed(plain).await.is_err());
        assert_eq!(lim.bans_active.load(Ordering::Relaxed), 1);
    }

    fn malformed_hello_garbage() -> Vec<u8> {
        vec![crypto_layer::V3_HELLO_TAG, 0xde, 0xad]
    }

    #[test]
    fn pre_hello_malformed_hello_counts_as_junk() {
        let mut tracker = PreHelloJunkTracker::default();
        let frame = malformed_hello_garbage();
        let got = account_pre_hello_binary(&frame, &mut tracker, 256, MAX_PRE_HELLO_BYTES).unwrap();
        assert!(got.is_none());
        assert_eq!(tracker.junk_frames, 1);
        assert_eq!(tracker.junk_bytes, frame.len());
    }

    #[test]
    fn pre_hello_frame_cap_exceeded_small() {
        let mut tracker = PreHelloJunkTracker::default();
        const CAP: u32 = 3;
        for _ in 0..CAP {
            account_pre_hello_binary(&malformed_hello_garbage(), &mut tracker, CAP, 1024)
                .unwrap();
        }
        assert_eq!(tracker.junk_frames, CAP);
        let err = account_pre_hello_binary(&malformed_hello_garbage(), &mut tracker, CAP, 1024)
            .unwrap_err();
        assert!(
            err.to_string().contains(PRE_HELLO_CAP_ERR),
            "unexpected: {err}"
        );
    }

    #[test]
    fn pre_hello_frame_cap_exceeded_production() {
        let mut tracker = PreHelloJunkTracker::default();
        for _ in 0..MAX_PRE_HELLO_FRAMES {
            account_pre_hello_binary(
                &malformed_hello_garbage(),
                &mut tracker,
                MAX_PRE_HELLO_FRAMES,
                MAX_PRE_HELLO_BYTES,
            )
            .unwrap();
        }
        let err = account_pre_hello_binary(
            &malformed_hello_garbage(),
            &mut tracker,
            MAX_PRE_HELLO_FRAMES,
            MAX_PRE_HELLO_BYTES,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(PRE_HELLO_CAP_ERR),
            "unexpected: {err}"
        );
    }

    #[test]
    fn pre_hello_byte_cap_exceeded() {
        let mut tracker = PreHelloJunkTracker::default();
        let mut frame = vec![crypto_layer::V3_HELLO_TAG];
        frame.extend(std::iter::repeat_n(0u8, 8));
        let err = account_pre_hello_binary(&frame, &mut tracker, 256, 4).unwrap_err();
        assert!(
            err.to_string().contains(PRE_HELLO_CAP_ERR),
            "unexpected: {err}"
        );
    }

    #[test]
    fn pre_hello_well_formed_hello_accepted() {
        let mut tracker = PreHelloJunkTracker::default();
        let (client_random, hello) = crypto_layer::build_hello_v3();
        let got = account_pre_hello_binary(
            &hello,
            &mut tracker,
            MAX_PRE_HELLO_FRAMES,
            MAX_PRE_HELLO_BYTES,
        )
        .unwrap()
        .expect("well-formed HELLO");
        assert_eq!(got, client_random);
        assert_eq!(tracker.junk_frames, 0);
        assert_eq!(tracker.junk_bytes, 0);
    }

    #[test]
    fn pre_hello_junk_then_well_formed_hello() {
        let mut tracker = PreHelloJunkTracker::default();
        account_pre_hello_binary(&[0x04], &mut tracker, MAX_PRE_HELLO_FRAMES, MAX_PRE_HELLO_BYTES)
            .unwrap();
        let (_, hello) = crypto_layer::build_hello_v3();
        let got = account_pre_hello_binary(
            &hello,
            &mut tracker,
            MAX_PRE_HELLO_FRAMES,
            MAX_PRE_HELLO_BYTES,
        )
        .unwrap()
        .expect("HELLO after junk");
        assert_eq!(got, crypto_layer::parse_hello_v3(&hello).unwrap());
        assert_eq!(tracker.junk_frames, 1);
    }

    #[test]
    fn pre_hello_non_tag_still_counts_as_junk() {
        let mut tracker = PreHelloJunkTracker::default();
        let got =
            account_pre_hello_binary(&[], &mut tracker, MAX_PRE_HELLO_FRAMES, MAX_PRE_HELLO_BYTES)
                .unwrap();
        assert!(got.is_none());
        assert_eq!(tracker.junk_frames, 1);
        assert_eq!(tracker.junk_bytes, 0);

        let got = account_pre_hello_binary(
            &[0x02, 0x01],
            &mut tracker,
            MAX_PRE_HELLO_FRAMES,
            MAX_PRE_HELLO_BYTES,
        )
        .unwrap();
        assert!(got.is_none());
        assert_eq!(tracker.junk_frames, 2);
        assert_eq!(tracker.junk_bytes, 2);
    }
}
