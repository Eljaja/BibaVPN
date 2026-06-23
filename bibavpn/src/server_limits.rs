//! Per-IP auth rate limiting, handshake junk budgets, and server-wide session counters.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Sliding window: `max_failures` within `window`, then ban for `ban`.
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

pub struct AuthRateLimiter {
    cfg: AuthRateLimiterConfig,
    inner: Mutex<HashMap<IpAddr, IpAuthState>>,
    pub bans_active: AtomicU64,
}

impl AuthRateLimiter {
    pub fn new(cfg: AuthRateLimiterConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            inner: Mutex::new(HashMap::new()),
            bans_active: AtomicU64::new(0),
        })
    }

    /// Fail fast if IP is banned; clear expired bans.
    pub async fn check_allowed(self: &Arc<Self>, ip: IpAddr) -> anyhow::Result<()> {
        if !self.cfg.enabled {
            return Ok(());
        }
        let mut g = self.inner.lock().await;
        let now = Instant::now();
        let st = match g.get_mut(&ip) {
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
        let mut g = self.inner.lock().await;
        let now = Instant::now();
        if g.len() >= MAX_TRACKED_IPS && !g.contains_key(&ip) {
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
        let st = g.entry(ip).or_insert(IpAuthState {
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
        if st.failures >= self.cfg.max_failures {
            st.banned_until = Some(now + self.cfg.ban);
            st.failures = 0;
            st.window_start = now;
            self.bans_active.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Clear per-IP failure state after successful AUTH (entry removed).
    pub async fn record_success(self: &Arc<Self>, ip: IpAddr) {
        if !self.cfg.enabled {
            return;
        }
        let mut g = self.inner.lock().await;
        if let Some(st) = g.remove(&ip) {
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

/// Counts live TLS/WSS sessions (increment when `handle_one` starts after permit, decrement on return).
pub struct ServerStats {
    pub active_sessions: AtomicU64,
}

impl ServerStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active_sessions: AtomicU64::new(0),
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
}
