/// Per-listener connection and traffic statistics.
///
/// Mirrors the Go yggstack `mobile/stats.go` registry: every listener
/// (SOCKS5 proxy, local/remote TCP/UDP forwarders) registers itself under a
/// stable key and counts active/total connections plus payload bytes on its
/// Yggdrasil-facing leg (RX = bytes read from the network, TX = bytes written
/// to it). `get_listeners_json` on the mobile bindings renders this registry
/// in the exact JSON shape the Android Ports screen parses.
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Identifies the SOCKS5 proxy listener in the registry (single entry).
pub const SOCKS_STATS_KEY: &str = "socks";

/// Identifies the HTTP proxy listener in the registry (single entry).
pub const HTTP_STATS_KEY: &str = "http";

/// One listener's counters. Stored behind the registry lock; the atomics
/// allow connection tasks to bump counters without taking that lock.
pub struct ListenerStats {
    pub key: String,
    pub kind: &'static str, // "socks" | "http" | "local-tcp" | "local-udp" | "remote-tcp" | "remote-udp"
    pub listen: String,
    pub target: String,
    pub active: AtomicI64,
    pub total: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
}

impl ListenerStats {
    pub fn conn_opened(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_closed(&self) {
        // Clamp at zero so a late close after a forced stop cannot wrap around.
        self.active.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            if v > 0 { Some(v - 1) } else { None }
        }).ok();
    }
}

fn stats_kind_order(kind: &str) -> u8 {
    match kind {
        "socks" => 0,
        "http" => 1,
        "local-tcp" => 2,
        "local-udp" => 3,
        "remote-tcp" => 4,
        "remote-udp" => 5,
        _ => 6,
    }
}

/// Registry of live listeners. Create one per node run; dropping it (or
/// removing entries) stops accounting for those listeners.
#[derive(Default)]
pub struct ListenerStatsRegistry {
    inner: Mutex<HashMap<String, Arc<ListenerStats>>>,
}

impl ListenerStatsRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register (or fetch) the stats entry for a listener key.
    pub fn entry(self: &Arc<Self>, key: &str, kind: &'static str, listen: &str, target: &str) -> Arc<ListenerStats> {
        let mut guard = self.inner.lock().unwrap();
        guard
            .entry(key.to_string())
            .or_insert_with(|| {
                Arc::new(ListenerStats {
                    key: key.to_string(),
                    kind,
                    listen: listen.to_string(),
                    target: target.to_string(),
                    active: AtomicI64::new(0),
                    total: AtomicU64::new(0),
                    rx_bytes: AtomicU64::new(0),
                    tx_bytes: AtomicU64::new(0),
                })
            })
            .clone()
    }

    /// Drop a listener's entry (used when a mapping is removed at runtime).
    pub fn remove(&self, key: &str) {
        self.inner.lock().unwrap().remove(key);
    }

    /// Clear every entry (used on node stop so a restart starts from zero).
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// Render the registry as the JSON array the Android Ports screen
    /// expects: [{"Key","Kind","Listen","Target","ActiveConns","TotalConns",
    /// "RXBytes","TXBytes"}], ordered by kind then listen then target —
    /// byte-for-byte the Go GetListenersJSON contract.
    pub fn to_json(&self) -> String {
        let guard = self.inner.lock().unwrap();
        let mut list: Vec<Arc<ListenerStats>> = guard.values().cloned().collect();
        drop(guard);
        list.sort_by(|a, b| {
            stats_kind_order(a.kind)
                .cmp(&stats_kind_order(b.kind))
                .then_with(|| a.listen.cmp(&b.listen))
                .then_with(|| a.target.cmp(&b.target))
        });
        let items: Vec<String> = list
            .iter()
            .map(|s| {
                format!(
                    r#"{{"Key":{key},"Kind":"{kind}","Listen":{listen},"Target":{target},"ActiveConns":{active},"TotalConns":{total},"RXBytes":{rx},"TXBytes":{tx}}}"#,
                    key = serde_json::to_string(&s.key).unwrap_or_else(|_| "\"\"".into()),
                    kind = s.kind,
                    listen = serde_json::to_string(&s.listen).unwrap_or_else(|_| "\"\"".into()),
                    target = serde_json::to_string(&s.target).unwrap_or_else(|_| "\"\"".into()),
                    active = s.active.load(Ordering::Relaxed).max(0),
                    total = s.total.load(Ordering::Relaxed),
                    rx = s.rx_bytes.load(Ordering::Relaxed),
                    tx = s.tx_bytes.load(Ordering::Relaxed),
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }
}

/// Guard that decrements the active-connection gauge exactly once when the
/// connection task finishes, however it exits (error, EOF, cancel, abort).
pub struct ConnGuard {
    stats: Option<Arc<ListenerStats>>,
}

impl ConnGuard {
    pub fn new(stats: Arc<ListenerStats>) -> Self {
        stats.conn_opened();
        Self { stats: Some(stats) }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(s) = self.stats.take() {
            s.conn_closed();
        }
    }
}

/// Direction of a relay leg relative to the Yggdrasil network.
#[derive(Clone, Copy)]
pub enum Dir {
    /// Bytes read from the Yggdrasil leg.
    Rx,
    /// Bytes written to the Yggdrasil leg.
    Tx,
}

/// Copy `src → dst`, adding every byte transferred to the listener entry
/// (RX = read from the network leg, TX = written to it), mirroring the Go
/// countingConn wrapper on the Yggdrasil-facing side of each relay.
pub async fn counting_copy<R, W>(
    mut src: R,
    mut dst: W,
    entry: Arc<ListenerStats>,
    dir: Dir,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        match dir {
            Dir::Rx => entry.rx_bytes.fetch_add(n as u64, Ordering::Relaxed),
            Dir::Tx => entry.tx_bytes.fetch_add(n as u64, Ordering::Relaxed),
        };
        total += n as u64;
    }
    Ok(total)
}
