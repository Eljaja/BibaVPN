//! Cross-module wire checks (no live server).

use bibavpn::crypto_layer::{build_ack, build_hello_v3, SessionCrypto};
use bibavpn::frame::{PadMode, AdaptivePadState};
use bibavpn::protocol::{
    decode_v3_auth, encode_v3_auth, encode_v3_mux_open, encode_v3_udp_mux_open, is_v3_mux_open,
    is_v3_udp_mux_open,
};
use bibavpn::tcp_mux::{decode_mux_record, encode_mux_open, encode_mux_record, is_mux_open, MUX_FLAG_DATA};
use bibavpn::{read_padded_frame_borrow, write_padded_frame, write_padded_frame_with_mode_state};
use std::sync::Arc;

fn session() -> Arc<SessionCrypto> {
    let (c, _hello) = build_hello_v3();
    let psk = "integration-psk";
    let dom = "test.domain";
    let (_ack, s) = build_ack(psk, dom, &c).unwrap();
    Arc::new(SessionCrypto::new(psk, dom, &c, &s, 8))
}

#[test]
fn v3_auth_inside_padded_aead_roundtrip() {
    let crypto = session();
    let auth = encode_v3_auth("secret-token").unwrap();
    let mut wire = Vec::new();
    write_padded_frame_with_mode_state(&mut wire, &auth, 32, PadMode::Random, None).unwrap();
    let sealed = crypto.seal_client_to_server(&wire).unwrap();
    let opened = crypto.open_client_to_server(&sealed).unwrap();
    let inner = read_padded_frame_borrow(&opened).unwrap();
    assert_eq!(decode_v3_auth(inner).unwrap(), "secret-token");
}

#[test]
fn mux_open_magic_distinct_from_v3_ctrl_opcodes() {
    assert!(is_mux_open(encode_mux_open().as_slice()));
    assert!(is_v3_mux_open(encode_v3_mux_open().as_slice()));
    assert!(is_v3_udp_mux_open(encode_v3_udp_mux_open().as_slice()));
    assert_ne!(encode_mux_open(), encode_v3_mux_open());
}

#[test]
fn mux_data_record_survives_pad_and_aead() {
    let crypto = session();
    let rec = encode_mux_record(5, MUX_FLAG_DATA, b"chunk");
    let mut wire = Vec::new();
    let mut adaptive = AdaptivePadState::default();
    write_padded_frame_with_mode_state(
        &mut wire,
        &rec,
        24,
        PadMode::Adaptive,
        Some(&mut adaptive),
    )
    .unwrap();
    let sealed = crypto.seal_client_to_server(&wire).unwrap();
    let opened = crypto.open_client_to_server(&sealed).unwrap();
    let inner = read_padded_frame_borrow(&opened).unwrap();
    let (sid, flags, payload) = decode_mux_record(inner).unwrap();
    assert_eq!(sid, 5);
    assert_eq!(flags, MUX_FLAG_DATA);
    assert_eq!(payload, b"chunk");
}

#[test]
fn v3_open_host_port_through_aead() {
    use bibavpn::protocol::{decode_v3_open_with_flags, encode_v3_open_with_flags, OPEN_FLAG_STATUS};

    let crypto = session();
    let open = encode_v3_open_with_flags("example.org", 443, OPEN_FLAG_STATUS).unwrap();
    let mut wire = Vec::new();
    write_padded_frame_with_mode_state(&mut wire, &open, 16, PadMode::Random, None).unwrap();
    let sealed = crypto.seal_client_to_server(&wire).unwrap();
    let opened = crypto.open_client_to_server(&sealed).unwrap();
    let inner = read_padded_frame_borrow(&opened).unwrap();
    let (host, port, flags) = decode_v3_open_with_flags(inner).unwrap();
    assert_eq!(host, "example.org");
    assert_eq!(port, 443);
    assert_ne!(flags & OPEN_FLAG_STATUS, 0);
}

#[test]
fn v3_open_err_through_aead() {
    use bibavpn::protocol::{decode_v3_open_err, encode_v3_open_err};

    let crypto = session();
    let err = encode_v3_open_err("host unreachable").unwrap();
    let mut wire = Vec::new();
    write_padded_frame(&mut wire, &err, 8).unwrap();
    let sealed = crypto.seal_server_to_client(&wire).unwrap();
    let opened = crypto.open_server_to_client(&sealed).unwrap();
    let inner = read_padded_frame_borrow(&opened).unwrap();
    assert_eq!(decode_v3_open_err(inner).unwrap(), "host unreachable");
}
