//! Coarse "last userland tunnel activity" for idle-based features (e.g. idle decoy).
//! Updated from TCP mux read/write paths; cheap `Mutex<Instant>` on hot path.

use std::sync::Mutex;
use std::time::Instant;

/// Shared last-activity time for the multiplexed WSS (SOCKS/HTTP over mux).
#[derive(Debug)]
pub struct ActivityTracker {
    last: Mutex<Instant>,
}

impl ActivityTracker {
    pub fn new() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
        }
    }

    /// Call when mux sends or receives application-payload (non-ping) bytes.
    pub fn touch(&self) {
        if let Ok(mut g) = self.last.lock() {
            *g = Instant::now();
        }
    }

    /// Seconds since last `touch`, rounded down.
    pub fn idle_secs(&self) -> u64 {
        self.last
            .lock()
            .map(|g| g.elapsed().as_secs())
            .unwrap_or(0)
    }
}
