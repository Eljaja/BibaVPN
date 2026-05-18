//! Flood-safe logging helpers.

use std::sync::atomic::{AtomicU64, Ordering};

/// Emit a log only on the first `warmup` calls and then every `every`th call after `warmup`.
pub struct LogEvery {
    n: AtomicU64,
    warmup: u64,
    every: u64,
}

impl LogEvery {
    pub const fn new(warmup: u64, every: u64) -> Self {
        Self {
            n: AtomicU64::new(0),
            warmup,
            every: if every == 0 { 1 } else { every },
        }
    }

    pub fn should_emit(&self) -> bool {
        let c = self.n.fetch_add(1, Ordering::Relaxed);
        c < self.warmup || c % self.every == 0
    }
}
