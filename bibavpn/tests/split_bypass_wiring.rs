//! `split_bypass_domains` in the start JSON must actually reach `domain_route`'s
//! process-global bypass list. The field and the DNS snoop both existed for a while, but
//! nothing ever populated the field, so domain split routing was dead code on every
//! platform — this test pins the wiring shut.
//!
//! Deliberately its own integration binary: `set_bypass_domains` mutates process-global
//! state, and any other test parsing a start JSON without the field would clear it.

use bibavpn::domain_route;
use bibavpn::start_json_config::local_client_options_from_json_str;

const PSK: &str = "0123456789abcdef0123456789abcdef";

/// Minimal DNS response: one question, one A answer pointing at `ip`.
fn dns_a_response(qname: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&[0x12, 0x34]); // id
    m.extend_from_slice(&[0x81, 0x80]); // flags: response, RD/RA
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&1u16.to_be_bytes()); // ancount
    m.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    let qstart = m.len();
    for label in qname.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    m.push(0xC0); // answer name: compression pointer back to the question
    m.push(qstart as u8);
    m.extend_from_slice(&1u16.to_be_bytes()); // type A
    m.extend_from_slice(&1u16.to_be_bytes()); // class IN
    m.extend_from_slice(&ttl.to_be_bytes());
    m.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    m.extend_from_slice(&ip);
    m
}

#[test]
fn split_bypass_domains_from_start_json_reaches_domain_route() {
    // Entries arrive from the preset API in mixed shapes: bare host, leading dot, mixed case.
    let j = format!(
        r#"{{"server":"127.0.0.1:8443","token":"t","psk":"{PSK}",
             "split_bypass_domains":["example.com","  .Video.NET "]}}"#
    );
    local_client_options_from_json_str(&j).expect("parse start json");

    // Hostname survives (desktop SOCKS / HTTP CONNECT): match directly.
    assert!(domain_route::should_bypass("example.com"));
    assert!(domain_route::should_bypass("a.b.example.com"));
    assert!(domain_route::should_bypass("EXAMPLE.COM"));
    assert!(domain_route::should_bypass("cdn.video.net"));

    // Not a suffix match — must stay in the tunnel.
    assert!(!domain_route::should_bypass("notexample.com"));
    assert!(!domain_route::should_bypass("example.com.evil.net"));
    assert!(!domain_route::should_bypass("other.org"));

    // Full-TUN case: tun2socks hands us a bare IP. With nothing learned yet the fail-safe
    // must keep it on the tunnel rather than leaking it direct.
    assert!(!domain_route::should_bypass("93.184.216.34"));

    // Once the UDP relay snoops a DNS answer for a bypassed domain, that IP goes direct.
    // This is what `excludeRoute` cannot do: the association is learned live, so a CDN
    // rotating addresses keeps working without reconnecting.
    domain_route::record_dns(&dns_a_response("example.com", [93, 184, 216, 34], 3600));
    assert!(domain_route::should_bypass("93.184.216.34"));

    // An IP belonging to a domain that is not on the list stays tunneled.
    domain_route::record_dns(&dns_a_response("other.org", [198, 51, 100, 7], 3600));
    assert!(!domain_route::should_bypass("198.51.100.7"));
}

#[test]
fn absent_split_bypass_domains_leaves_routing_untouched() {
    // Same process as the test above would fight over the global list, so this case is
    // asserted through the pure decision function instead of the global convenience wrapper.
    let map = domain_route::DomainRouteMap::new();
    assert_eq!(
        domain_route::decide("example.com", &[], &map, 0),
        domain_route::Route::Tunnel
    );
}
