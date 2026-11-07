use std::sync::Arc;
use std::time::Duration;

use crate::crypto::PublicKey;

/// Configuration for an ironwood PacketConn.
pub struct Config {
    /// How often to refresh our own tree announcement. Default: 4 minutes.
    pub router_refresh: Duration,
    /// Timeout before expiring a peer's tree info. Default: 5 minutes.
    pub router_timeout: Duration,
    /// Delay before sending a keepalive to idle peer. Default: 1 second.
    pub peer_keepalive_delay: Duration,
    /// How long a peer may stay silent, after we sent it something that expects
    /// an answer, before we probe it. Default: 3 seconds.
    pub peer_timeout: Duration,
    /// How many consecutive `peer_timeout` intervals of silence a peer is
    /// allowed before it is declared dead, so it is torn down after
    /// `peer_timeout * peer_probe_count`. A keepalive probe is sent at the end
    /// of every interval but the last. Default: 3, i.e. 9 seconds at the
    /// default interval.
    ///
    /// Retrying rather than dropping on the first expiry is what makes lossy or
    /// high-RTT paths usable: a single lost segment head-of-line blocks a TCP
    /// stream for seconds while the kernel backs off its retransmits, and a flat
    /// deadline shorter than that recovery tears down links TCP would have
    /// healed. A value of 1 restores the old drop-on-first-expiry behaviour.
    pub peer_probe_count: u32,
    /// Maximum size of a single peer message. Default: 1 MB.
    pub peer_max_message_size: u64,
    /// Optional transform applied to keys before bloom filter insertion.
    pub bloom_transform: Option<Arc<dyn Fn(PublicKey) -> PublicKey + Send + Sync>>,
    /// Callback invoked when a new path is discovered.
    pub path_notify: Option<Arc<dyn Fn(PublicKey) + Send + Sync>>,
    /// Timeout before expiring a cached path. Default: 1 minute.
    pub path_timeout: Duration,
    /// Minimum interval between path lookups to the same destination. Default: 1 second.
    pub path_throttle: Duration,
    /// Optional closed-network group password. When set, only peers configured
    /// with the same password can complete an encrypted session handshake.
    /// `None`/empty = open network (no change to the handshake). Default: `None`.
    pub group_password: Option<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            router_refresh: Duration::from_secs(4 * 60),
            router_timeout: Duration::from_secs(5 * 60),
            peer_keepalive_delay: Duration::from_secs(1),
            peer_timeout: Duration::from_secs(3),
            peer_probe_count: 3,
            peer_max_message_size: 1024 * 1024,
            bloom_transform: None,
            path_notify: None,
            path_timeout: Duration::from_secs(60),
            path_throttle: Duration::from_secs(1),
            group_password: None,
        }
    }
}

impl Config {
    pub fn with_router_refresh(mut self, d: Duration) -> Self {
        self.router_refresh = d;
        self
    }

    pub fn with_router_timeout(mut self, d: Duration) -> Self {
        self.router_timeout = d;
        self
    }

    pub fn with_peer_keepalive_delay(mut self, d: Duration) -> Self {
        self.peer_keepalive_delay = d;
        self
    }

    pub fn with_peer_timeout(mut self, d: Duration) -> Self {
        self.peer_timeout = d;
        self
    }

    /// Set how many `peer_timeout` intervals may be missed before disconnecting.
    /// Clamped to at least 1, since zero probes would drop every peer instantly.
    pub fn with_peer_probe_count(mut self, n: u32) -> Self {
        self.peer_probe_count = n.max(1);
        self
    }

    pub fn with_peer_max_message_size(mut self, size: u64) -> Self {
        self.peer_max_message_size = size;
        self
    }

    pub fn with_bloom_transform(
        mut self,
        f: impl Fn(PublicKey) -> PublicKey + Send + Sync + 'static,
    ) -> Self {
        self.bloom_transform = Some(Arc::new(f));
        self
    }

    pub fn with_path_notify(
        mut self,
        f: impl Fn(PublicKey) + Send + Sync + 'static,
    ) -> Self {
        self.path_notify = Some(Arc::new(f));
        self
    }

    pub fn with_path_timeout(mut self, d: Duration) -> Self {
        self.path_timeout = d;
        self
    }

    pub fn with_path_throttle(mut self, d: Duration) -> Self {
        self.path_throttle = d;
        self
    }

    /// Set a closed-network group password. All nodes that should be able to
    /// open sessions with each other must use the same password. An empty
    /// password leaves the network open (the handshake is unchanged).
    pub fn with_group_password(mut self, password: Vec<u8>) -> Self {
        self.group_password = if password.is_empty() {
            None
        } else {
            Some(password)
        };
        self
    }
}
