#![no_main]

use bibavpn::protocol::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_auth(data);
    let _ = decode_open(data);
    let _ = decode_open_with_flags(data);
    let _ = decode_open_err(data);
    let _ = decode_v3_auth(data);
    let _ = decode_v3_open(data);
    let _ = decode_v3_open_with_flags(data);
    let _ = decode_v3_open_err(data);
    let _ = decode_udp_req(data);
    let _ = decode_udp_rep(data);
    let _ = parse_socks5_udp_datagram(data);
    let _ = classify_v3_first_channel(data);
});
