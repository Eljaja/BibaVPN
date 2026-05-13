//! Lightweight integration smoke tests (no live server).

use bibavpn::protocol::*;
use bibavpn::tcp_mux::{decode_mux_record, encode_mux_record, MUX_FLAG_DATA};

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
