/// DNS + `.pk.ygg` name resolver using the Yggdrasil netstack.
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use yggdrasil::address::addr_for_key;

use crate::netstack::YggNetstack;

pub const NAME_MAPPING_SUFFIX: &str = ".pk.ygg";

/// Multi-nameserver tuning: overall per-server lookup budget, and how long to
/// stay on a fallback server before re-probing the preferred (first) one.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_PREFERRED_AFTER: Duration = Duration::from_secs(60);

/// One server's lookup outcome. `NoRecord` is an authoritative answer from a
/// responsive server (no AAAA record / NXDOMAIN) — unlike a transport
/// failure, it must not trigger failover.
enum DnsAnswer {
    Ip(Ipv6Addr),
    NoRecord,
}

/// One nameserver lookup: `Err` means the server was unreachable or silent
/// (fail over to the next one); `Ok(DnsAnswer::NoRecord)` is final.
trait DnsExchange {
    async fn lookup(&self, name: &str, nameserver: &str) -> Result<DnsAnswer, String>;
}

pub struct NameResolver {
    netstack: Arc<YggNetstack>,
    /// Nameserver list; single entry or empty keeps the historical behavior.
    nameservers: Vec<String>,
    /// Set only with 2+ servers: sticky cursor + preferred-server re-probe.
    failover: Option<FailoverState>,
}

impl NameResolver {
    pub fn new(netstack: Arc<YggNetstack>, nameserver: &str) -> Self {
        let nameservers = parse_nameservers(nameserver);
        let failover = if nameservers.len() > 1 {
            Some(FailoverState::new())
        } else {
            None
        };
        Self {
            netstack,
            nameservers,
            failover,
        }
    }

    /// Resolve a hostname or `.pk.ygg` name to an IPv6 address.
    pub async fn resolve(&self, name: &str) -> Result<Ipv6Addr, String> {
        // 1. Direct IP literal?
        if let Ok(ip) = name.parse::<Ipv6Addr>() {
            return Ok(ip);
        }

        // 2. `.pk.ygg` suffix → derive from public key.
        if name.ends_with(NAME_MAPPING_SUFFIX) {
            let stripped = name
                .trim_end_matches(NAME_MAPPING_SUFFIX)
                .rsplit('.')
                .next()
                .unwrap_or("");
            let bytes = hex::decode(stripped)
                .map_err(|e| format!("hex decode: {}", e))?;
            if bytes.len() != 32 {
                return Err(format!("public key must be 32 bytes, got {}", bytes.len()));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            let addr = addr_for_key(&pk);
            return Ok(Ipv6Addr::from(addr.0));
        }

        // 3. Forward DNS query via nameserver(s) through netstack.
        if self.nameservers.is_empty() {
            return Err(format!("no nameserver configured; cannot resolve '{}'", name));
        }
        if self.nameservers.len() == 1 {
            return match self.dns_lookup_ipv6(name, &self.nameservers[0]).await {
                Ok(DnsAnswer::Ip(ip)) => Ok(ip),
                Ok(DnsAnswer::NoRecord) => Err(format!("no AAAA record found for '{}'", name)),
                Err(e) => Err(e),
            };
        }
        let failover = self.failover.as_ref().unwrap();
        resolve_with_failover(
            self,
            name,
            &self.nameservers,
            failover,
            ATTEMPT_TIMEOUT,
        )
        .await
    }

    async fn dns_lookup_ipv6(&self, name: &str, nameserver: &str) -> Result<DnsAnswer, String> {
        // Parse nameserver as "[addr]:port" or "addr:port".
        let ns_addr: std::net::SocketAddr = nameserver
            .parse()
            .or_else(|_| format!("[{}]:53", nameserver).parse())
            .map_err(|_| format!("invalid nameserver address '{}'", nameserver))?;

        let query = build_dns_query(name, 28 /* AAAA */);

        // Try UDP first (DNS default transport). The first attempt may be
        // buffered while a DHT route lookup happens; if it times out we retry
        // once (the route should be established by then) before falling back
        // to TCP for truncated responses.
        let udp_result = match self.dns_lookup_udp(&query, ns_addr, 10).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::debug!("DNS UDP attempt 1 failed for '{}': {}; retrying", name, e);
                // Retry: route should be established now.
                self.dns_lookup_udp(&query, ns_addr, 10).await
            }
        };

        let resp = match udp_result {
            Ok(resp) => {
                // Check TC (truncated) bit in flags byte 2 bit 1.
                let truncated = resp.len() >= 3 && (resp[2] & 0x02) != 0;
                if truncated {
                    tracing::debug!("DNS UDP response truncated for '{}', retrying via TCP", name);
                    self.dns_lookup_tcp(&query, ns_addr).await?
                } else {
                    resp
                }
            }
            Err(e) => {
                tracing::debug!("DNS UDP failed for '{}': {}; trying TCP", name, e);
                self.dns_lookup_tcp(&query, ns_addr).await?
            }
        };

        match parse_dns_aaaa_response(&resp) {
            Some(ip) => Ok(DnsAnswer::Ip(ip)),
            None => Ok(DnsAnswer::NoRecord),
        }
    }

    async fn dns_lookup_udp(
        &self,
        query: &[u8],
        ns_addr: std::net::SocketAddr,
        timeout_secs: u64,
    ) -> Result<Vec<u8>, String> {
        let udp = self
            .netstack
            .open_udp()
            .map_err(|e| format!("UDP open: {}", e))?;

        udp.send_to(query, ns_addr)
            .await
            .map_err(|e| format!("DNS UDP send: {}", e))?;

        let mut buf = vec![0u8; 4096];
        let timeout = tokio::time::Duration::from_secs(timeout_secs);
        let (n, _) = tokio::time::timeout(timeout, udp.recv_from(&mut buf))
            .await
            .map_err(|_| "DNS UDP timeout".to_string())?
            .map_err(|e| format!("DNS UDP recv: {}", e))?;

        Ok(buf[..n].to_vec())
    }

    async fn dns_lookup_tcp(
        &self,
        query: &[u8],
        ns_addr: std::net::SocketAddr,
    ) -> Result<Vec<u8>, String> {
        // DNS-over-TCP uses a 2-byte length prefix.
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);

        let mut stream = self
            .netstack
            .dial_tcp(ns_addr)
            .await
            .map_err(|e| format!("DNS connect: {}", e))?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(&framed)
            .await
            .map_err(|e| format!("DNS write: {}", e))?;

        // Read response (2-byte length prefix).
        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| format!("DNS read len: {}", e))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp)
            .await
            .map_err(|e| format!("DNS read body: {}", e))?;

        Ok(resp)
    }
}

impl DnsExchange for NameResolver {
    async fn lookup(&self, name: &str, nameserver: &str) -> Result<DnsAnswer, String> {
        self.dns_lookup_ipv6(name, nameserver).await
    }
}

/// Split a comma-separated nameserver list, dropping empty entries; each
/// entry is `[addr]:port` or a bare address (port 53 is assumed later).
pub fn parse_nameservers(nameservers: &str) -> Vec<String> {
    nameservers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Sticky failover cursor over `n` servers: lookups start at the last server
/// that answered; the preferred (first) server is re-probed after
/// `retry_preferred_after` so a recovered primary is picked back up.
struct FailoverState {
    current: AtomicUsize,
    preferred_down: Mutex<Option<Instant>>,
    retry_preferred_after: Duration,
}

impl FailoverState {
    fn new() -> Self {
        Self::with_retry_after(RETRY_PREFERRED_AFTER)
    }

    fn with_retry_after(retry_preferred_after: Duration) -> Self {
        Self {
            current: AtomicUsize::new(0),
            preferred_down: Mutex::new(None),
            retry_preferred_after,
        }
    }

    fn start_index(&self) -> usize {
        let current = self.current.load(Ordering::Relaxed);
        if current != 0 {
            let down = *self.preferred_down.lock().unwrap();
            if down.is_some_and(|since| since.elapsed() >= self.retry_preferred_after) {
                // Re-probe the preferred server; if it is still down the
                // walk fails over again within this same lookup.
                self.current.store(0, Ordering::Relaxed);
                return 0;
            }
        }
        current
    }

    fn note_success(&self, idx: usize) {
        self.current.store(idx, Ordering::Relaxed);
        if idx == 0 {
            *self.preferred_down.lock().unwrap() = None;
        }
    }

    fn note_failure(&self, idx: usize, len: usize) {
        if idx == 0 {
            let mut down = self.preferred_down.lock().unwrap();
            if down.is_none() {
                *down = Some(Instant::now());
            }
        }
        // Advance the sticky cursor past the failed server.
        let _ = self.current.compare_exchange(
            idx,
            (idx + 1) % len,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

/// Walk the server list starting at the failover cursor's position, giving
/// each attempt its own deadline so a silent server cannot consume the
/// caller's whole budget. Transport failures move to the next server; an
/// authoritative no-record answer is returned as-is.
async fn resolve_with_failover<E: DnsExchange>(
    exchange: &E,
    name: &str,
    servers: &[String],
    failover: &FailoverState,
    attempt_timeout: Duration,
) -> Result<Ipv6Addr, String> {
    let start = failover.start_index();
    let mut last_err = String::new();
    for i in 0..servers.len() {
        let idx = (start + i) % servers.len();
        match tokio::time::timeout(
            attempt_timeout,
            exchange.lookup(name, &servers[idx]),
        )
        .await
        {
            Ok(Ok(DnsAnswer::Ip(ip))) => {
                failover.note_success(idx);
                return Ok(ip);
            }
            Ok(Ok(DnsAnswer::NoRecord)) => {
                failover.note_success(idx);
                return Err(format!("no AAAA record found for '{}'", name));
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    "DNS nameserver {} failed for '{}': {}",
                    servers[idx],
                    name,
                    e
                );
                failover.note_failure(idx, servers.len());
                last_err = e;
            }
            Err(_) => {
                tracing::debug!(
                    "DNS nameserver {} timed out for '{}' after {:?}",
                    servers[idx],
                    name,
                    attempt_timeout
                );
                failover.note_failure(idx, servers.len());
                last_err = format!("timeout after {:?}", attempt_timeout);
            }
        }
    }
    Err(format!(
        "all {} nameservers failed to lookup '{}': {}",
        servers.len(),
        name,
        last_err
    ))
}

// ── Minimal DNS wire format ───────────────────────────────────────────────────

fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);

    // Header: ID=1, QR=0(query), OPCODE=0, RD=1, 1 question
    msg.extend_from_slice(&[0x00, 0x01]); // ID
    msg.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Question: encode name as DNS labels
    for label in name.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00); // root label

    msg.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    msg
}

fn parse_dns_aaaa_response(buf: &[u8]) -> Option<Ipv6Addr> {
    if buf.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    // Skip the question section.
    let mut pos = 12;

    // Skip QDCOUNT questions (1 question).
    pos = skip_dns_name(buf, pos)?;
    pos += 4; // QTYPE + QCLASS

    // Parse answer RRs.
    for _ in 0..ancount {
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let _rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let _ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;

        if rtype == 28 && rdlength == 16 && pos + 16 <= buf.len() {
            // AAAA record
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[pos..pos + 16]);
            return Some(Ipv6Addr::from(octets));
        }
        pos += rdlength;
    }
    None
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NAME: &str = "failover.example.invalid";
    const TEST_IP: Ipv6Addr = Ipv6Addr::new(0x200, 0x1234, 0x5678, 0x9abc, 0, 0, 0, 1);

    /// Fake exchange keyed by nameserver address: "answer", "blackhole"
    /// (silent until the attempt deadline kills the future), "nxdomain" or
    /// "dead" (immediate transport error).
    struct FakeExchange {
        modes: Vec<(String, &'static str)>,
    }

    impl FakeExchange {
        fn mode(&self, nameserver: &str) -> &'static str {
            self.modes
                .iter()
                .find(|(addr, _)| addr == nameserver)
                .map(|(_, mode)| *mode)
                .unwrap_or("dead")
        }
    }

    impl DnsExchange for FakeExchange {
        async fn lookup(&self, _name: &str, nameserver: &str) -> Result<DnsAnswer, String> {
            match self.mode(nameserver) {
                "answer" => Ok(DnsAnswer::Ip(TEST_IP)),
                "nxdomain" => Ok(DnsAnswer::NoRecord),
                "blackhole" => {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    unreachable!("blackhole server must be cut off by the attempt deadline")
                }
                _ => Err(format!("unreachable server {}", nameserver)),
            }
        }
    }

    fn servers(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_nameservers_splits_trims_and_drops_empty() {
        assert!(parse_nameservers("").is_empty());
        assert!(parse_nameservers("  ").is_empty());
        assert_eq!(
            parse_nameservers("[308:1::]:53, 308:2:: ,, [308:3::]:5353"),
            servers(&["[308:1::]:53", "308:2::", "[308:3::]:5353"])
        );
        // A single entry (with or without trailing comma) stays a 1-list.
        assert_eq!(parse_nameservers("[308:1::]:53,"), servers(&["[308:1::]:53"]));
    }

    #[tokio::test]
    async fn failover_moves_to_next_server_on_timeout() {
        let dead = "[308:1::]:53";
        let live = "[308:2::]:53";
        let exchange = FakeExchange {
            modes: servers(&[dead, live])
                .into_iter()
                .zip(["blackhole", "answer"])
                .collect(),
        };
        let failover = FailoverState::new();
        let ip = resolve_with_failover(
            &exchange,
            TEST_NAME,
            &servers(&[dead, live]),
            &failover,
            Duration::from_millis(150),
        )
        .await
        .unwrap();
        assert_eq!(ip, TEST_IP);
        // Sticky cursor now sits on the server that answered.
        assert_eq!(failover.start_index(), 1);
    }

    #[tokio::test]
    async fn failover_moves_to_next_server_on_transport_error() {
        let dead = "[308:1::]:53";
        let live = "[308:2::]:53";
        let exchange = FakeExchange {
            modes: servers(&[dead, live])
                .into_iter()
                .zip(["dead", "answer"])
                .collect(),
        };
        let failover = FailoverState::new();
        resolve_with_failover(
            &exchange,
            TEST_NAME,
            &servers(&[dead, live]),
            &failover,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(failover.start_index(), 1);
    }

    #[tokio::test]
    async fn failover_sticks_to_answering_server() {
        let dead = "[308:1::]:53";
        let live = "[308:2::]:53";
        let exchange = FakeExchange {
            modes: servers(&[dead, live])
                .into_iter()
                .zip(["blackhole", "answer"])
                .collect(),
        };
        let failover = FailoverState::with_retry_after(Duration::from_secs(3600));
        let list = servers(&[dead, live]);
        resolve_with_failover(&exchange, TEST_NAME, &list, &failover, Duration::from_millis(150))
            .await
            .unwrap();
        // Second lookup starts at the live server: the dead one is never
        // contacted again (mode lookup would return "blackhole" only for it).
        let ip = resolve_with_failover(
            &exchange,
            TEST_NAME,
            &list,
            &failover,
            Duration::from_millis(150),
        )
        .await
        .unwrap();
        assert_eq!(ip, TEST_IP);
        assert_eq!(failover.start_index(), 1);
    }

    #[tokio::test]
    async fn preferred_server_reprobed_after_cooldown() {
        let dead = "[308:1::]:53";
        let live = "[308:2::]:53";
        let exchange = FakeExchange {
            modes: servers(&[dead, live])
                .into_iter()
                .zip(["blackhole", "answer"])
                .collect(),
        };
        // The preferred server stays "dead" forever here, but the cooldown
        // still resets the cursor so the next lookup starts at it again.
        let failover = FailoverState::with_retry_after(Duration::from_millis(100));
        let list = servers(&[dead, live]);
        resolve_with_failover(&exchange, TEST_NAME, &list, &failover, Duration::from_millis(150))
            .await
            .unwrap();
        assert_eq!(failover.start_index(), 1);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(failover.start_index(), 0);
    }

    #[tokio::test]
    async fn authoritative_no_record_does_not_fail_over() {
        let nx = "[308:1::]:53";
        let live = "[308:2::]:53";
        let exchange = FakeExchange {
            modes: servers(&[nx, live])
                .into_iter()
                .zip(["nxdomain", "answer"])
                .collect(),
        };
        let failover = FailoverState::new();
        let err = resolve_with_failover(
            &exchange,
            TEST_NAME,
            &servers(&[nx, live]),
            &failover,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert_eq!(err, format!("no AAAA record found for '{}'", TEST_NAME));
    }

    #[tokio::test]
    async fn all_servers_failing_returns_error() {
        let dead1 = "[308:1::]:53";
        let dead2 = "[308:2::]:53";
        let exchange = FakeExchange {
            modes: servers(&[dead1, dead2])
                .into_iter()
                .zip(["dead", "dead"])
                .collect(),
        };
        let failover = FailoverState::new();
        let err = resolve_with_failover(
            &exchange,
            TEST_NAME,
            &servers(&[dead1, dead2]),
            &failover,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(err.starts_with(&format!(
            "all 2 nameservers failed to lookup '{}'",
            TEST_NAME
        )));
    }

    #[test]
    fn dns_query_wire_format() {
        let q = build_dns_query("failover.example.invalid", 28);
        // Header: 1 question, RD=1.
        assert_eq!(&q[4..6], &[0, 1]);
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        // Question labels end with the root byte, then QTYPE AAAA / QCLASS IN.
        let question_len: usize = "failover.example.invalid"
            .split('.')
            .map(|l| 1 + l.len())
            .sum::<usize>()
            + 1; // root label
        assert_eq!(q.len(), 12 + question_len + 4);
        assert_eq!(q[q.len() - 5], 0); // root label terminator
        assert_eq!(&q[q.len() - 4..q.len() - 2], &28u16.to_be_bytes());
        assert_eq!(&q[q.len() - 2..], &[0, 1]);
    }

    #[test]
    fn parse_aaaa_response_extracts_answer() {
        // echo question + one AAAA record with a name pointer.
        let query = build_dns_query("failover.example.invalid", 28);
        let mut resp = query.clone();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x00;
        resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        let mut answer = Vec::new();
        answer.extend_from_slice(&[0xc0, 0x0c]); // NAME pointer
        answer.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
        answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        answer.extend_from_slice(&0u32.to_be_bytes()); // TTL
        answer.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
        answer.extend_from_slice(&TEST_IP.octets());
        resp.extend_from_slice(&answer);

        assert_eq!(parse_dns_aaaa_response(&resp), Some(TEST_IP));
        // No answers → None (treated as an authoritative no-record).
        let mut nx = query;
        nx[2] = 0x81;
        nx[3] = 0x03; // NXDOMAIN
        assert_eq!(parse_dns_aaaa_response(&nx), None);
        // Garbage → None.
        assert_eq!(parse_dns_aaaa_response(&[0u8; 4]), None);
    }
}
