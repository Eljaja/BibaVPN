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
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

    /// Record A/AAAA answers from a DNS response only when the message id and question
    /// name match the client's pending query and the name is on `bypass`. Does not
    /// replace a still-live mapping for an IP with a different normalized name.
    pub fn record_dns_response(
        &self,
        dns_msg: &[u8],
        expected_id: u16,
        expected_qname: &str,
        bypass: &[String],
        now_secs: u64,
    ) -> usize {
        if bypass.is_empty() {
            return 0;
        }
        let Some((resp_id, qname, answers)) = parse_dns_answers(dns_msg) else {
            return 0;
        };
        if resp_id != expected_id
            || normalize_domain(&qname) != normalize_domain(expected_qname)
            || !matches_bypass(&qname, bypass)
            || qname.is_empty()
            || answers.is_empty()
        {
            return 0;
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Opportunistic prune when large, then bound the size.
        if g.len() >= MAX_ENTRIES {
            g.retain(|_, e| e.expires_at > now_secs);
        }
        let domain = normalize_domain(&qname);
        let mut n = 0;
        for (ip, ttl) in answers {
            if let Some(existing) = g.get(&ip) {
                if existing.expires_at > now_secs
                    && normalize_domain(&existing.domain) != domain
                {
                    continue;
                }
            }
            if g.len() >= MAX_ENTRIES && !g.contains_key(&ip) {
                continue;
            }
            let ttl = (ttl as u64).clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            g.insert(
                ip,
                Entry {
                    domain: domain.clone(),
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

/// True when `host` is a literal loopback, RFC1918, CGNAT, ULA, or link-local address,
/// or the hostname `localhost` (case-insensitive; trailing `.` trimmed).
pub fn host_is_local_or_private(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .ok()
        .is_some_and(ip_is_local_or_private)
}

fn ip_is_local_or_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_local_or_private(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ipv4_is_local_or_private(v4);
            }
            let o = v6.octets();
            // ULA fc00::/7
            if o[0] & 0xfe == 0xfc {
                return true;
            }
            // link-local fe80::/10
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                return true;
            }
            false
        }
    }
}

fn ipv4_is_local_or_private(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    if a == 127 {
        return true;
    }
    if a == 10 {
        return true;
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && b == 168 {
        return true;
    }
    if a == 169 && b == 254 {
        return true;
    }
    // CGNAT 100.64.0.0/10 — explicit octets; do not use Ipv4Addr::is_shared.
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    false
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
    if host_is_local_or_private(host) {
        return Route::Direct;
    }
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

// ---------------------------------------------------------------------------
// Process-global glue (mirrors `outbound_protect`'s global-hook pattern), so the
// UDP relay and the SOCKS CONNECT path can share one map + bypass list without
// threading them through every config struct.
// ---------------------------------------------------------------------------

static GLOBAL_MAP: OnceLock<DomainRouteMap> = OnceLock::new();
static GLOBAL_BYPASS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The shared IP→domain map fed by the UDP DNS snoop.
pub fn global_map() -> &'static DomainRouteMap {
    GLOBAL_MAP.get_or_init(DomainRouteMap::new)
}

/// Install the bypass domain list (empty disables domain split routing entirely).
pub fn set_bypass_domains(domains: &[String]) {
    let cleaned: Vec<String> = domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    *GLOBAL_BYPASS.lock().unwrap_or_else(|p| p.into_inner()) = cleaned;
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True when a non-empty bypass domain list is installed.
pub fn bypass_domains_active() -> bool {
    !GLOBAL_BYPASS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty()
}

/// Match `domain` against the installed bypass list (suffix rules). No-op when empty.
pub fn matches_active_bypass(domain: &str) -> bool {
    let bypass = GLOBAL_BYPASS.lock().unwrap_or_else(|p| p.into_inner());
    if bypass.is_empty() {
        return false;
    }
    matches_bypass(domain, bypass.as_slice())
}

/// SOCKS/CONNECT convenience: should this target bypass the tunnel (go direct)?
/// Cheap no-op when no bypass domains are configured.
pub fn should_bypass(host: &str) -> bool {
    if host_is_local_or_private(host) {
        return true;
    }
    let bypass = GLOBAL_BYPASS.lock().unwrap_or_else(|p| p.into_inner());
    if bypass.is_empty() {
        return false;
    }
    decide(host, bypass.as_slice(), global_map(), now_secs()) == Route::Direct
}

/// UDP-relay convenience: learn IP→domain from a DNS response that matches a query
/// this client sent. No-op when domain split routing isn't configured.
pub fn record_dns(dns_msg: &[u8], expected_id: u16, expected_qname: &str) {
    let bypass = GLOBAL_BYPASS.lock().unwrap_or_else(|p| p.into_inner());
    if bypass.is_empty() {
        return;
    }
    global_map().record_dns_response(
        dns_msg,
        expected_id,
        expected_qname,
        bypass.as_slice(),
        now_secs(),
    );
}

/// TLS extension type for server_name (RFC 6066).
const TLS_EXT_SERVER_NAME: u16 = 0;
/// SNI `host_name` name type.
const SNI_HOST_NAME: u8 = 0;

/// Parse the first TLS record in `record` and return the ClientHello SNI hostname.
/// Returns `None` on malformed input, non-handshake records, missing SNI, or when
/// the SNI is an IP literal (v4/v6). Pure — no I/O.
pub fn extract_client_hello_sni(record: &[u8]) -> Option<String> {
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let end = 5usize.checked_add(rec_len)?;
    if record.len() < end {
        return None;
    }
    parse_handshake_client_hello_sni(&record[5..end])
}

fn parse_handshake_client_hello_sni(hs: &[u8]) -> Option<String> {
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    let body_end = 4usize.checked_add(hs_len)?;
    if hs.len() < body_end {
        return None;
    }
    parse_client_hello_body_sni(&hs[4..body_end])
}

fn parse_client_hello_body_sni(body: &[u8]) -> Option<String> {
    let mut pos = 2usize; // legacy version
    pos = pos.checked_add(32)?; // random
    if pos >= body.len() {
        return None;
    }
    let sid_len = body[pos] as usize;
    pos = pos.checked_add(1)?.checked_add(sid_len)?;
    if pos.checked_add(2)? > body.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos = pos.checked_add(2)?.checked_add(cs_len)?;
    if pos >= body.len() {
        return None;
    }
    let comp_len = body[pos] as usize;
    pos = pos.checked_add(1)?.checked_add(comp_len)?;
    if pos.checked_add(2)? > body.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_len)?;
    if ext_end > body.len() {
        return None;
    }
    parse_extensions_sni(&body[pos..ext_end])
}

fn parse_extensions_sni(exts: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos.checked_add(4)? <= exts.len() {
        let etype = u16::from_be_bytes([exts[pos], exts[pos + 1]]);
        let elen = u16::from_be_bytes([exts[pos + 2], exts[pos + 3]]) as usize;
        pos = pos.checked_add(4)?;
        let edata_end = pos.checked_add(elen)?;
        if edata_end > exts.len() {
            return None;
        }
        let edata = &exts[pos..edata_end];
        if etype == TLS_EXT_SERVER_NAME {
            if let Some(sni) = parse_sni_extension(edata) {
                return Some(sni);
            }
        }
        pos = edata_end;
    }
    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list_end = 2usize.checked_add(list_len)?;
    if list_end > data.len() {
        return None;
    }
    let mut pos = 2usize;
    while pos.checked_add(3)? <= list_end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos = pos.checked_add(3)?;
        let name_end = pos.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }
        if name_type == SNI_HOST_NAME {
            let name = String::from_utf8_lossy(&data[pos..name_end]);
            let host = name.trim_end_matches('.');
            if host.is_empty() || host.parse::<IpAddr>().is_ok() {
                return None;
            }
            return Some(host.to_ascii_lowercase());
        }
        pos = name_end;
    }
    None
}

fn normalize_domain(d: &str) -> String {
    d.trim_end_matches('.').to_ascii_lowercase()
}

/// Parse a DNS query: header id and the first question name (lowercased). Returns
/// `None` on malformed input or unparseable names (including compression loops).
pub fn parse_dns_query(msg: &[u8]) -> Option<(u16, String)> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let (qname, np) = read_name(msg, pos)?;
    pos = np;
    pos = pos.checked_add(4)?;
    if pos > msg.len() {
        return None;
    }
    Some((id, qname))
}

/// Minimal DNS response parser: returns the message id, first question name
/// (lowercased), and the list of `(ip, ttl)` from A / AAAA answer records. Returns
/// `None` on malformed input. Bounds-checked; name-compression pointers are followed
/// with a jump cap to prevent loops.
pub fn parse_dns_answers(msg: &[u8]) -> Option<(u16, String, Vec<(IpAddr, u32)>)> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
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
    Some((id, qname, out))
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
        build_with_id(0x1234, qname, qtype, answers)
    }

    fn build_with_id(id: u16, qname: &str, qtype: u16, answers: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
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

    fn build_query(id: u16, qname: &str) -> Vec<u8> {
        let qname = qname.trim_end_matches('.');
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&[0x01, 0x00]); // flags: standard query
        m.extend_from_slice(&1u16.to_be_bytes()); // qd
        m.extend_from_slice(&0u16.to_be_bytes()); // an
        m.extend_from_slice(&[0, 0, 0, 0]); // ns, ar
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        m.extend_from_slice(&1u16.to_be_bytes()); // class IN
        m
    }

    const BYPASS: &[&str] = &["example.com"];
    fn bypass_list() -> Vec<String> {
        BYPASS.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parse_a_record_with_compression() {
        let msg = build("example.com", 1, &[(1, 300, vec![93, 184, 216, 34])]);
        let (id, name, ans) = parse_dns_answers(&msg).expect("parse");
        assert_eq!(id, 0x1234);
        assert_eq!(name, "example.com");
        assert_eq!(ans, vec![(ip("93.184.216.34"), 300)]);
    }

    #[test]
    fn parse_aaaa_record() {
        let mut rd = vec![0u8; 16];
        rd[15] = 1; // ::1
        let msg = build("v6.example.com", 28, &[(28, 120, rd)]);
        let (id, name, ans) = parse_dns_answers(&msg).expect("parse");
        assert_eq!(id, 0x1234);
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
        let (id, name, ans) = parse_dns_answers(&msg).expect("parse");
        assert_eq!(id, 0x1234);
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
        let bypass = bypass_list();
        let msg = build("example.com", 1, &[(1, 300, vec![5, 6, 7, 8])]);
        assert_eq!(
            map.record_dns_response(&msg, 0x1234, "example.com", &bypass, 1000),
            1
        );
        assert_eq!(map.lookup(ip("5.6.7.8"), 1100).as_deref(), Some("example.com"));
        // 300s TTL from t=1000 → expires at 1300.
        assert_eq!(map.lookup(ip("5.6.7.8"), 1301), None);
    }

    #[test]
    fn map_clamps_zero_ttl() {
        let map = DomainRouteMap::new();
        let bypass = bypass_list();
        let msg = build("a.example.com", 1, &[(1, 0, vec![9, 9, 9, 9])]);
        map.record_dns_response(&msg, 0x1234, "a.example.com", &bypass, 0);
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
        let msg = build("example.com", 1, &[(1, 300, vec![203, 0, 113, 1])]);
        map.record_dns_response(&msg, 0x1234, "example.com", &bypass, 100);
        // IP known to be example.com → Direct.
        assert_eq!(decide("203.0.113.1", &bypass, &map, 150), Route::Direct);
        // Unknown IP → Tunnel (fail-safe).
        assert_eq!(decide("203.0.113.2", &bypass, &map, 150), Route::Tunnel);
        // Expired mapping → Tunnel.
        assert_eq!(decide("203.0.113.1", &bypass, &map, 100_000), Route::Tunnel);
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

    #[test]
    fn record_rejects_forged_bypass_qname() {
        let map = DomainRouteMap::new();
        let bypass = bypass_list();
        let msg = build("example.com", 1, &[(1, 300, vec![1, 2, 3, 4])]);
        assert_eq!(
            map.record_dns_response(&msg, 0x1234, "other.org", &bypass, 0),
            0
        );
        assert_eq!(decide("1.2.3.4", &bypass, &map, 0), Route::Tunnel);
    }

    #[test]
    fn record_rejects_id_mismatch() {
        let map = DomainRouteMap::new();
        let bypass = bypass_list();
        let msg = build("example.com", 1, &[(1, 300, vec![1, 2, 3, 4])]);
        assert_eq!(
            map.record_dns_response(&msg, 0xAAAA, "example.com", &bypass, 0),
            0
        );
        assert_eq!(map.lookup(ip("1.2.3.4"), 0), None);
    }

    #[test]
    fn record_accepts_legitimate_match() {
        let map = DomainRouteMap::new();
        let bypass = bypass_list();
        let msg = build("example.com", 1, &[(1, 300, vec![203, 0, 113, 1])]);
        assert_eq!(
            map.record_dns_response(&msg, 0x1234, "example.com", &bypass, 100),
            1
        );
        assert_eq!(decide("203.0.113.1", &bypass, &map, 150), Route::Direct);
    }

    #[test]
    fn decide_private_hosts_direct_even_with_empty_bypass() {
        let map = DomainRouteMap::new();
        let empty: Vec<String> = vec![];
        for host in [
            "192.168.88.1",
            "10.0.0.1",
            "172.16.1.1",
            "127.0.0.1",
            "localhost",
            "::1",
            "fc00::1",
            "::ffff:192.168.1.1",
            "100.64.1.1",
            "169.254.1.1",
            "fe80::1",
        ] {
            assert_eq!(
                decide(host, &empty, &map, 0),
                Route::Direct,
                "expected Direct for {host}"
            );
        }
        assert_eq!(decide("1.1.1.1", &empty, &map, 0), Route::Tunnel);
        assert_eq!(decide("example.com", &empty, &map, 0), Route::Tunnel);
    }

    #[test]
    fn should_bypass_private_with_empty_global_list() {
        set_bypass_domains(&[]);
        assert!(should_bypass("192.168.88.1"));
        set_bypass_domains(&[]);
    }

    #[test]
    fn record_skips_non_bypass_qname() {
        let map = DomainRouteMap::new();
        let bypass = bypass_list();
        let msg = build("other.org", 1, &[(1, 300, vec![8, 8, 8, 8])]);
        assert_eq!(
            map.record_dns_response(&msg, 0x1234, "other.org", &bypass, 0),
            0
        );
        assert_eq!(map.lookup(ip("8.8.8.8"), 0), None);
    }

    #[test]
    fn record_does_not_overwrite_live_different_name() {
        let map = DomainRouteMap::new();
        let bypass = vec!["example.com".to_string(), "cdn.example.com".to_string()];
        let first = build("example.com", 1, &[(1, 300, vec![1, 2, 3, 4])]);
        map.record_dns_response(&first, 0x1234, "example.com", &bypass, 1000);
        assert_eq!(
            map.lookup(ip("1.2.3.4"), 1100).as_deref(),
            Some("example.com")
        );

        let second = build("cdn.example.com", 1, &[(1, 300, vec![1, 2, 3, 4])]);
        assert_eq!(
            map.record_dns_response(&second, 0x1234, "cdn.example.com", &bypass, 1100),
            0
        );
        assert_eq!(
            map.lookup(ip("1.2.3.4"), 1100).as_deref(),
            Some("example.com")
        );

        // After expiry the other name may bind.
        assert_eq!(
            map.record_dns_response(&second, 0x1234, "cdn.example.com", &bypass, 1400),
            1
        );
        assert_eq!(
            map.lookup(ip("1.2.3.4"), 1400).as_deref(),
            Some("cdn.example.com")
        );
    }

    #[test]
    fn parse_dns_query_extracts_id_and_qname() {
        let msg = build_query(0xBEEF, "Example.COM.");
        let (id, qname) = parse_dns_query(&msg).expect("parse");
        assert_eq!(id, 0xBEEF);
        assert_eq!(qname, "example.com");
    }

    #[test]
    fn parse_dns_query_rejects_truncated() {
        assert!(parse_dns_query(&[0u8; 4]).is_none());
    }

    #[test]
    fn parse_dns_query_rejects_compression_loop() {
        // Pointer to self → read_name jump cap returns None.
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.push(0xC0);
        m.push(12);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        assert!(parse_dns_query(&m).is_none());
    }

    /// Build a minimal TLS handshake record containing a ClientHello with one SNI.
    fn tls_client_hello_with_sni(sni: &str) -> Vec<u8> {
        let mut ch = Vec::new();
        ch.push(0x01); // ClientHello
        let len_pos = ch.len();
        ch.extend_from_slice(&[0, 0, 0]); // handshake length placeholder
        let body_start = ch.len();
        ch.extend_from_slice(&[0x03, 0x03]); // legacy version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session id length
        ch.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        ch.extend_from_slice(&[1, 0]); // compression: null
        let sni_bytes = sni.as_bytes();
        let sni_list_len = 1 + 2 + sni_bytes.len();
        let sni_ext_data_len = 2 + sni_list_len;
        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes()); // server_name
        exts.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        exts.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        exts.push(0); // host_name
        exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(sni_bytes);
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);
        let body_len = ch.len() - body_start;
        ch[len_pos] = 0;
        ch[len_pos + 1] = ((body_len >> 8) & 0xff) as u8;
        ch[len_pos + 2] = (body_len & 0xff) as u8;
        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        record.extend_from_slice(&(ch.len() as u16).to_be_bytes());
        record.extend_from_slice(&ch);
        record
    }

    #[test]
    fn extract_sni_from_valid_client_hello() {
        let record = tls_client_hello_with_sni("example.com");
        assert_eq!(
            extract_client_hello_sni(&record).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn extract_sni_truncated_or_non_handshake() {
        let record = tls_client_hello_with_sni("example.com");
        assert!(extract_client_hello_sni(&record[..4]).is_none());
        let mut app_data = record.clone();
        app_data[0] = 0x17; // application data
        assert!(extract_client_hello_sni(&app_data).is_none());
        let mut no_ext = tls_client_hello_with_sni("example.com");
        // Strip extensions block (last bytes) to simulate no SNI.
        no_ext.truncate(no_ext.len().saturating_sub(20));
        assert!(extract_client_hello_sni(&no_ext).is_none());
    }

    #[test]
    fn extract_sni_ignores_ip_literals() {
        let v4 = tls_client_hello_with_sni("93.184.216.34");
        assert!(extract_client_hello_sni(&v4).is_none());
        let v6 = tls_client_hello_with_sni("2001:db8::1");
        assert!(extract_client_hello_sni(&v6).is_none());
    }

    #[test]
    fn sni_suffix_matches_bypass_list() {
        let bypass = vec!["example.com".to_string()];
        let record = tls_client_hello_with_sni("a.example.com");
        let sni = extract_client_hello_sni(&record).expect("sni");
        assert!(matches_bypass(&sni, &bypass));
        let other = tls_client_hello_with_sni("notexample.com");
        let sni2 = extract_client_hello_sni(&other).expect("sni");
        assert!(!matches_bypass(&sni2, &bypass));
    }
}
