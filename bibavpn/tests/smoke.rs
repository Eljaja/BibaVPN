//! Lightweight integration smoke tests (no live server).

use bibavpn::protocol::*;
use bibavpn::tcp_mux::{decode_mux_record, encode_mux_record, MUX_FLAG_DATA, MUX_FLAG_RST};

#[test]
fn strict_parsers_integration_smoke() {
    let mut a = encode_v3_auth("tok").unwrap();
    a.push(0);
    assert!(decode_v3_auth(&a).is_err());

    let rec = encode_mux_record(7, MUX_FLAG_DATA, b"z");
    assert_eq!(decode_mux_record(&rec).unwrap().0, 7);
    let mut bad = rec.clone();
    bad.push(1);
    assert!(decode_mux_record(&bad).is_err());
}

#[test]
fn v3_open_status_flags_roundtrip() {
    let open = encode_v3_open_with_flags("host.test", 443, OPEN_FLAG_STATUS).unwrap();
    let (h, p, flags) = decode_v3_open_with_flags(&open).unwrap();
    assert_eq!(h, "host.test");
    assert_eq!(p, 443);
    assert_eq!(flags & OPEN_FLAG_STATUS, OPEN_FLAG_STATUS);
}

#[test]
fn mux_rst_record_empty_payload() {
    let rec = encode_mux_record(12, MUX_FLAG_RST, &[]);
    let (sid, flags, pl) = decode_mux_record(&rec).unwrap();
    assert_eq!(sid, 12);
    assert_eq!(flags, MUX_FLAG_RST);
    assert!(pl.is_empty());
}
