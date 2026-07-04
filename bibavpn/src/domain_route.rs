//! Domain-based split routing for full-TUN clients (mobile).
//!
//! On a full-device TUN VPN (Android `VpnService` + tun2socks) the SOCKS `CONNECT`
//! that reaches the client carries only the **destination IP** — the hostname was
//! already resolved and is gone. To decide "bypass this domain" we must recover the
//! IP→domain association. We do it by snooping the DNS answers that flow through the
//! tunnel's own UDP path and keeping a short-lived `IP → domain` map (TTL'd). When a
//! TCP `CONNECT` to an IP arrives, we look the IP up, match the domain against the
//! bypass list, and route matches **directly** (outside the tunnel) instead of
//! through it.
//!
//! This module is transport-agnostic and pure (no I/O), so it is fully unit-tested;
//! wiring (feed DNS answers from the UDP relay, consult on SOCKS CONNECT) lives in
//! the client.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

/// Where a connection should egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Send through the encrypted tunnel (default).
    Tunnel,
    /// Connect directly from the device (split-tunnel bypass).
    Direct,
}

/// Clamp DNS TTLs into a sane window so a hostile/0 TTL can't thrash or pin forever.
const MIN_TTL_SECS: u64 = 30;
const MAX_TTL_SECS: u64 = 3600;
/// Hard cap on tracked IPs to bound memory under churn.
const MAX_ENTRIES: usize = 20_000;

/// A live `IP -> domain` map learned from DNS answers, with per-entry expiry.
///
/// `now_secs` is passed in by the caller (monotonic seconds) so the map is
/// deterministic and testable — no clock is read internally.
#[derive(Default)]
pub struct DomainRouteMap {
    inner: Mutex<HashMap<IpAddr, Entry>>,
}

struct Entry {
    domain: String,
    expires_at: u64,
}

impl DomainRouteMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record every A/AAAA answer in a DNS response, associating each returned IP
    /// with the **queried** name (so `example.com` matches even when it CNAMEs to a
    /// CDN host). `dns_msg` is the raw DNS message (UDP payload). Unparseable input
    /// is ignored. Returns how many IPs were recorded.
    pub fn record_dns_response(&self, dns_msg: &[u8], now_secs: u64) -> usize {
        let Some((qname, answers)) = parse_dns_answers(dns_msg) else {
            return 0;
        };
        if qname.is_empty() || answers.is_empty() {
            return 0;
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Opportunistic prune when large, then bound the size.
        if g.len() >= MAX_ENTRIES {
            g.retain(|_, e| e.expires_at > now_secs);
        }
        let mut n = 0;
        for (ip, ttl) in answers {
            if g.len() >= MAX_ENTRIES && !g.contains_key(&ip) {
                continue;
            }
            let ttl = (ttl as u64).clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            g.insert(
                ip,
                Entry {
                    domain: qname.clone(),
                    expires_at: now_secs.saturating_add(ttl),
                },
            );
            n += 1;
        }
        n
    }

    /// Domain last seen for `ip`, if the entry has not expired.
    pub fn lookup(&self, ip: IpAddr, now_secs: u64) -> Option<String> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.get(&ip)
            .filter(|e| e.expires_at > now_secs)
            .map(|e| e.domain.clone())
    }

    /// Drop expired entries.
    pub fn prune(&self, now_secs: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|_, e| e.expires_at > now_secs);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

/// True if `domain` equals a bypass entry or is a subdomain of one (case-insensitive).
/// `example.com` in the list matches `example.com` and `a.b.example.com`, but not
/// `notexample.com`.
pub fn matches_bypass(domain: &str, bypass: &[String]) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    bypass.iter().any(|raw| {
        let b = raw.trim().trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
        if b.is_empty() {
            return false;
        }
        d == b || d.ends_with(&format!(".{b}"))
    })
}

/// Decide how a SOCKS/CONNECT target should egress.
///
/// `host` may be a literal IP (as tun2socks emits after DNS) or a domain (desktop
/// SOCKS/HTTP CONNECT, where the hostname survives). Returns `Direct` only when we
/// can positively attribute the target to a bypass domain; otherwise `Tunnel`
/// (fail-safe: unknown → tunnel).
pub fn decide(host: &str, bypass: &[String], map: &DomainRouteMap, now_secs: u64) -> Route {
    if bypass.is_empty() {
        return Route::Tunnel;
    }
    // Domain literal (hostname survived): match directly.
    if host.parse::<IpAddr>().is_err() {
        return if matches_bypass(host, bypass) {
            Route::Direct
        } else {
            Route::Tunnel
        };
    }
    // IP literal: recover the domain from the DNS map.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(domain) = map.lookup(ip, now_secs) {
            if matches_bypass(&domain, bypass) {
                return Route::Direct;
            }
        }
    }
    Route::Tunnel
}

/// Minimal DNS response parser: returns the first question name (lowercased) and the
/// list of `(ip, ttl)` from A / AAAA answer records. Returns `None` on malformed
/// input. Bounds-checked; name-compression pointers are followed with a jump cap to
/// prevent loops.
pub fn parse_dns_answers(msg: &[u8]) -> Option<(String, Vec<(IpAddr, u32)>)> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    // First question name = the queried domain.
    let (qname, np) = read_name(msg, pos)?;
    pos = np;
    // qtype(2) + qclass(2)
    pos = pos.checked_add(4)?;
    if pos > msg.len() {
        return None;
    }
    // Skip any remaining questions.
    for _ in 1..qdcount {
        let (_n, np) = read_name(msg, pos)?;
        pos = np.checked_add(4)?;
        if pos > msg.len() {
            return None;
        }
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        let (_name, np) = read_name(msg, pos)?;
        pos = np;
        // type(2) class(2) ttl(4) rdlength(2) = 10 bytes
        if pos.checked_add(10)? > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        let rdend = pos.checked_add(rdlen)?;
        if rdend > msg.len() {
            return None;
        }
        match rtype {
            1 if rdlen == 4 => {
                let b = &msg[pos..pos + 4];
                out.push((
                    IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
                    ttl,
                ));
            }
            28 if rdlen == 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&msg[pos..pos + 16]);
                out.push((IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            _ => {}
        }
        pos = rdend;
    }
    Some((qname, out))
}

/// Read a DNS name starting at `start`; returns `(lowercased dotted name, position
/// just past the name in the *record stream*)`. Follows compression pointers but
/// caps total jumps.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0usize;
    let mut after_ptr: Option<usize> = None;
    loop {
        let len = *msg.get(pos)?;
        if len & 0xC0 == 0xC0 {
            // Pointer: next byte completes the 14-bit offset.
            let b2 = *msg.get(pos + 1)? as usize;
            let ptr = (((len & 0x3F) as usize) << 8) | b2;
            if after_ptr.is_none() {
                after_ptr = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 32 || ptr >= msg.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let len = len as usize;
        let s = pos.checked_add(1)?;
        let e = s.checked_add(len)?;
        if e > msg.len() {
            return None;
        }
        // Labels are ASCII; lossy is fine for matching.
        labels.push(String::from_utf8_lossy(&msg[s..e]).to_ascii_lowercase());
        pos = e;
        if labels.len() > 128 {
            return None;
        }
    }
    let end = after_ptr.unwrap_or(pos);
    Some((labels.join("."), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // Build a DNS response: 1 question (name, A/AAAA), then the given answers.
    // answers: (rtype, rdata)
    fn build(qname: &str, qtype: u16, answers: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&[0x81, 0x80]); // flags: response, RD/RA
        m.extend_from_slice(&1u16.to_be_bytes()); // qd
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // an
        m.extend_from_slice(&[0, 0, 0, 0]); // ns, ar
        let qstart = m.len();
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // class IN
        for (rtype, ttl, rdata) in answers {
            // Compression pointer back to the question name.
            m.push(0xC0);
            m.push(qstart as u8);
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&1u16.to_be_bytes()); // class IN
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn parse_a_record_with_compression() {
        let msg = build("example.com", 1, &[(1, 300, vec![93, 184, 216, 34])]);
        let (name, ans) = parse_dns_answers(&msg).expect("parse");
        assert_eq!(name, "example.com");
        assert_eq!(ans, vec![(ip("93.184.216.34"), 300)]);
    }

    #[test]
    fn parse_aaaa_record() {
        let mut rd = vec![0u8; 16];
        rd[15] = 1; // ::1
        let msg = build("v6.example.com", 28, &[(28, 120, rd)]);
        let (name, ans) = parse_dns_answers(&msg).expect("parse");
        assert_eq!(name, "v6.example.com");
        assert_eq!(ans, vec![(ip("::1"), 120)]);
    }

    #[test]
    fn parse_ignores_non_addr_records() {
        // A CNAME (type 5) answer plus an A answer: only the A yields an IP.
        let msg = build(
            "cdn.example.com",
            1,
            &[(5, 300, vec![0xC0, 0x0C]), (1, 300, vec![1, 2, 3, 4])],
        );
        let (name, ans) = parse_dns_answers(&msg).expect("parse");
        assert_eq!(name, "cdn.example.com");
        assert_eq!(ans, vec![(ip("1.2.3.4"), 300)]);
    }

    #[test]
    fn parse_rejects_truncated() {
        assert!(parse_dns_answers(&[0u8; 4]).is_none());
    }

    #[test]
    fn map_records_and_expires() {
        let map = DomainRouteMap::new();
        let msg = build("example.com", 1, &[(1, 300, vec![5, 6, 7, 8])]);
        assert_eq!(map.record_dns_response(&msg, 1000), 1);
        assert_eq!(map.lookup(ip("5.6.7.8"), 1100).as_deref(), Some("example.com"));
        // 300s TTL from t=1000 → expires at 1300.
        assert_eq!(map.lookup(ip("5.6.7.8"), 1301), None);
    }

    #[test]
    fn map_clamps_zero_ttl() {
        let map = DomainRouteMap::new();
        let msg = build("z.example", 1, &[(1, 0, vec![9, 9, 9, 9])]);
        map.record_dns_response(&msg, 0);
        // clamped up to MIN_TTL_SECS (30) → still valid at t=29.
        assert!(map.lookup(ip("9.9.9.9"), 29).is_some());
        assert!(map.lookup(ip("9.9.9.9"), 31).is_none());
    }

    #[test]
    fn matcher_suffix_rules() {
        let set = vec!["example.com".to_string(), ".video.net".to_string()];
        assert!(matches_bypass("example.com", &set));
        assert!(matches_bypass("a.b.example.com", &set));
        assert!(matches_bypass("cdn.video.net", &set));
        assert!(matches_bypass("EXAMPLE.COM", &set)); // case-insensitive
        assert!(!matches_bypass("notexample.com", &set));
        assert!(!matches_bypass("example.com.evil.net", &set));
        assert!(!matches_bypass("", &set));
    }

    #[test]
    fn decide_ip_via_map() {
        let map = DomainRouteMap::new();
        let bypass = vec!["example.com".to_string()];
        let msg = build("example.com", 1, &[(1, 300, vec![10, 0, 0, 1])]);
        map.record_dns_response(&msg, 100);
        // IP known to be example.com → Direct.
        assert_eq!(decide("10.0.0.1", &bypass, &map, 150), Route::Direct);
        // Unknown IP → Tunnel (fail-safe).
        assert_eq!(decide("10.0.0.2", &bypass, &map, 150), Route::Tunnel);
        // Expired mapping → Tunnel.
        assert_eq!(decide("10.0.0.1", &bypass, &map, 100_000), Route::Tunnel);
    }

    #[test]
    fn decide_domain_literal() {
        let map = DomainRouteMap::new();
        let bypass = vec!["example.com".to_string()];
        assert_eq!(decide("a.example.com", &bypass, &map, 0), Route::Direct);
        assert_eq!(decide("other.org", &bypass, &map, 0), Route::Tunnel);
    }

    #[test]
    fn decide_empty_bypass_is_tunnel() {
        let map = DomainRouteMap::new();
        assert_eq!(decide("example.com", &[], &map, 0), Route::Tunnel);
        assert_eq!(map.len(), 0);
    }
}
