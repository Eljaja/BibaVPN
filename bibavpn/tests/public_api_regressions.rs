//! Public-API regressions for start JSON parsing, invite decoding, and the
//! small host/path parsers shared by the CLI, desktop app, and Android JNI.
//!
//! These deliberately go through the re-exported crate surface (not
//! `crate::…` internals) so an accidental visibility/behaviour change breaks
//! here as well as the caller binaries.

use bibavpn::local_client::{
    normalize_ws_path, parse_host_port, parse_ws_header, DEFAULT_CLIENT_MAX_WS_BINARY,
    DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use bibavpn::start_json_config::{
    local_client_options_from_json_str, local_client_options_from_json_str_with_binds,
};
use bibavpn::{decode_invite_v1, encode_invite_v1, InviteV1, PadMode};

const PSK: &str = "0123456789abcdef0123456789abcdef";
const BASE: &str = r#"{"server":"127.0.0.1:8443","token":"strong-token","psk":"0123456789abcdef0123456789abcdef"}"#;

fn invite_from_json(v: serde_json::Value) -> InviteV1 {
    serde_json::from_value(v).expect("invite fixture")
}

#[test]
fn start_json_defaults_are_stable() {
    let o = local_client_options_from_json_str(BASE).expect("defaults parse");
    assert_eq!(o.server_host, "127.0.0.1");
    assert_eq!(o.server_port, 8443);
    assert_eq!(o.socks_bind, "127.0.0.1:1080");
    assert_eq!(o.http_proxy_bind, None);
    assert_eq!(o.ws_path, "/ws");
    assert_eq!(o.proto, 3);
    assert_eq!(o.proto_domain, "default");
    assert_eq!(o.max_pad, 64);
    assert_eq!(o.max_ws_binary, DEFAULT_CLIENT_MAX_WS_BINARY);
    assert_eq!(o.ws_ping_secs, 25);
    assert_eq!(o.ws_parallel, 1);
    assert!(o.use_tcp_mux);
    assert_eq!(o.pad_mode, PadMode::Adaptive);
    assert!(!o.insecure_tls);
    assert_eq!(o.udp_max_pad, None);
    assert_eq!(o.udp_max_ws_binary, None);
    assert_eq!(
        o.udp_mux_reply_timeout_secs,
        DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS
    );
    // No profile/fingerprint in the JSON or invite: Chrome 132+ is the client default.
    assert_eq!(o.tls_profile, bibavpn::TlsClientProfile::Chrome132);
    assert_eq!(o.sni, "127.0.0.1");
}

#[test]
fn start_json_rejects_unusable_server_addresses() {
    for server in [
        "127.0.0.1",  // no port at all
        "127.0.0.1:", // empty port
        "127.0.0.1:notaport",
        "127.0.0.1:70000", // outside u16
        "   ",             // server is required without an invite
    ] {
        let j = format!(r#"{{"server":"{server}","token":"strong-token","psk":"{PSK}"}}"#);
        assert!(
            local_client_options_from_json_str(&j).is_err(),
            "accepted server {server:?}"
        );
    }
}

#[test]
fn start_json_normalizes_ws_path_and_clamps_ws_parallel() {
    let mut json: serde_json::Value = serde_json::from_str(BASE).unwrap();
    json["ws_path"] = "metrics".into();
    json["ws_parallel"] = 0.into();
    let o = local_client_options_from_json_str(&json.to_string()).unwrap();
    assert_eq!(o.ws_path, "/metrics");
    assert_eq!(o.ws_parallel, 1);

    json["ws_path"] = "  ".into();
    json["ws_parallel"] = 9.into();
    let o = local_client_options_from_json_str(&json.to_string()).unwrap();
    assert_eq!(o.ws_path, "/ws");
    assert_eq!(o.ws_parallel, 4);

    json["ws_path"] = "/custom".into();
    json["ws_parallel"] = 3.into();
    let o = local_client_options_from_json_str(&json.to_string()).unwrap();
    assert_eq!(o.ws_path, "/custom");
    assert_eq!(o.ws_parallel, 3);
}

#[test]
fn start_json_rejects_unknown_enum_labels() {
    for (field, value) in [
        ("pad_mode", "not-a-mode"),
        ("stealth_profile", "turbo"),
        ("tls_stack", "gnutls"),
        ("decoy_mode", "cinema"),
        ("desync_mode", "chaos"),
        ("tcp_fooling", "magic"),
    ] {
        let mut json: serde_json::Value = serde_json::from_str(BASE).unwrap();
        json[field] = value.into();
        assert!(
            local_client_options_from_json_str(&json.to_string()).is_err(),
            "accepted {field}={value:?}"
        );
    }
}

#[test]
fn start_json_socks_auth_requires_both_fields() {
    let j = format!(
        r#"{{"server":"127.0.0.1:8443","token":"strong-token","psk":"{PSK}","socks_auth_user":"alice"}}"#
    );
    assert!(local_client_options_from_json_str(&j).is_err());

    let j = format!(
        r#"{{"server":"127.0.0.1:8443","token":"strong-token","psk":"{PSK}","socks_auth_password":"hunter2"}}"#
    );
    assert!(local_client_options_from_json_str(&j).is_err());

    let j = format!(
        r#"{{"server":"127.0.0.1:8443","token":"strong-token","psk":"{PSK}","socks_auth_user":"alice","socks_auth_password":"hunter2"}}"#
    );
    let o = local_client_options_from_json_str(&j).unwrap();
    assert_eq!(
        o.socks_auth,
        Some(("alice".to_string(), "hunter2".to_string()))
    );
}

#[test]
fn start_json_with_binds_overrides_and_clears_http_proxy() {
    let json = format!(
        r#"{{"server":"127.0.0.1:8443","token":"strong-token","psk":"{PSK}","socks_bind":"127.0.0.1:1","http_proxy":"127.0.0.1:2"}}"#
    );
    let o = local_client_options_from_json_str_with_binds(
        &json,
        "127.0.0.1:0".to_string(),
        Some("127.0.0.1:0".to_string()),
    )
    .unwrap();
    assert_eq!(o.socks_bind, "127.0.0.1:0");
    assert_eq!(o.http_proxy_bind.as_deref(), Some("127.0.0.1:0"));

    let o = local_client_options_from_json_str_with_binds(&json, "127.0.0.1:9".to_string(), None)
        .unwrap();
    assert_eq!(o.socks_bind, "127.0.0.1:9");
    assert_eq!(o.http_proxy_bind, None);
}

#[test]
fn start_json_with_binds_rejects_non_object_json() {
    assert!(
        local_client_options_from_json_str_with_binds("[]", "127.0.0.1:0".into(), None).is_err()
    );
    assert!(
        local_client_options_from_json_str_with_binds("{", "127.0.0.1:0".into(), None).is_err()
    );
}

#[test]
fn start_json_invite_json_disagreements_fail_closed() {
    let invite = invite_from_json(serde_json::json!({
        "v": 1,
        "server": "vpn.example:443",
        "sni": "vpn.example",
        "token": "invite-token",
        "psk": PSK,
        "decoy_max": 8,
        "max_pad": 64,
        "max_ws_binary": 1400,
        "ws_ping_secs": 25,
        "insecure": false,
        "tls_profile": "default",
    }));
    let uri = encode_invite_v1(&invite, "passphrase-test").unwrap();

    let mismatched_psk = format!(
        r#"{{"from_invite":"{uri}","invite_passphrase":"passphrase-test","psk":"ffffffffffffffffffffffffffffffff"}}"#
    );
    assert!(local_client_options_from_json_str(&mismatched_psk).is_err());

    let mismatched_token = format!(
        r#"{{"from_invite":"{uri}","invite_passphrase":"passphrase-test","token":"other-token"}}"#
    );
    assert!(local_client_options_from_json_str(&mismatched_token).is_err());

    let wrong_passphrase =
        format!(r#"{{"from_invite":"{uri}","invite_passphrase":"not-the-passphrase"}}"#);
    assert!(local_client_options_from_json_str(&wrong_passphrase).is_err());

    let ok = format!(r#"{{"from_invite":"{uri}","invite_passphrase":"passphrase-test"}}"#);
    let o = local_client_options_from_json_str(&ok).unwrap();
    assert_eq!(o.token, "invite-token");
    assert_eq!(o.server_host, "vpn.example");
    assert_eq!(o.server_port, 443);
    assert_eq!(o.psk.as_deref(), Some(PSK));
}

#[test]
fn invite_decoder_rejects_garbage_without_panicking() {
    for uri in [
        "",
        "biba://",
        "biba://!!!!",
        "biba:",
        "not-an-invite",
        "biba://AA",     // blob version 0
        "biba://Cg",     // blob version 10
        "  biba://AA  ", // trimmed then still unsupported
    ] {
        assert!(
            decode_invite_v1(uri, "passphrase").is_err(),
            "accepted malformed invite {uri:?}"
        );
    }
}

#[test]
fn invite_decoder_accepts_prefixed_and_raw_base64() {
    let invite = invite_from_json(serde_json::json!({
        "v": 1,
        "server": "203.0.113.9:8443",
        "sni": "vpn.example.com",
        "token": "invite-token",
        "psk": PSK,
        "decoy_max": 0,
        "max_pad": 16,
        "max_ws_binary": 1400,
        "ws_ping_secs": 25,
        "insecure": true,
        "tls_profile": "chrome-132",
    }));
    let uri = encode_invite_v1(&invite, "passphrase").unwrap();
    let raw = uri.strip_prefix("biba://").unwrap();

    assert_eq!(decode_invite_v1(&uri, "passphrase").unwrap(), invite);
    assert_eq!(
        decode_invite_v1(&format!("  {uri}\n"), "passphrase").unwrap(),
        invite
    );
    assert_eq!(decode_invite_v1(raw, "passphrase").unwrap(), invite);
}

#[test]
fn host_port_and_header_parsers_fail_closed() {
    assert_eq!(
        parse_host_port("vpn.example:443").unwrap(),
        ("vpn.example".to_string(), 443)
    );
    assert!(parse_host_port("vpn.example").is_err());
    assert!(parse_host_port("vpn.example:").is_err());
    assert!(parse_host_port("vpn.example:65536").is_err());

    assert_eq!(
        parse_ws_header("X-Test:  value  ").unwrap(),
        ("X-Test".to_string(), "value".to_string())
    );
    assert!(parse_ws_header("no-colon").is_err());

    assert_eq!(normalize_ws_path("ws"), "/ws");
    assert_eq!(normalize_ws_path(" /ws "), "/ws");
    assert_eq!(normalize_ws_path(""), "/ws");
    assert_eq!(normalize_ws_path("//double"), "//double");
}

#[test]
fn start_json_reality_is_all_or_nothing() {
    // Base64 of 32 zero bytes: only used to satisfy the 32-byte X25519 key parser.
    const PUBKEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    let invite = invite_from_json(serde_json::json!({
        "v": 1,
        "server": "203.0.113.9:443",
        "sni": "vpn.example.com",
        "token": "invite-token",
        "decoy_max": 0,
        "max_pad": 16,
        "max_ws_binary": 1400,
        "ws_ping_secs": 25,
        "insecure": false,
        "tls_profile": "default",
        "reality_target": "vk.com:443",
    }));
    let uri = encode_invite_v1(&invite, "passphrase").unwrap();
    let json = format!(r#"{{"from_invite":"{uri}","invite_passphrase":"passphrase"}}"#);
    assert!(
        local_client_options_from_json_str(&json).is_err(),
        "REALITY without a public key must fail closed"
    );

    let invite = invite_from_json(serde_json::json!({
        "v": 1,
        "server": "203.0.113.9:443",
        "sni": "vpn.example.com",
        "token": "invite-token",
        "decoy_max": 0,
        "max_pad": 16,
        "max_ws_binary": 1400,
        "ws_ping_secs": 25,
        "insecure": false,
        "tls_profile": "default",
        "reality_target": "vk.com:443",
        "reality_public_key": PUBKEY,
    }));
    let uri = encode_invite_v1(&invite, "passphrase").unwrap();
    let json = format!(r#"{{"from_invite":"{uri}","invite_passphrase":"passphrase"}}"#);
    let o = local_client_options_from_json_str(&json).expect("REALITY invite without PSK");
    assert_eq!(o.psk, None);
    assert_eq!(o.reality_target.as_deref(), Some("vk.com:443"));
    assert_eq!(o.reality_public_key, Some([0u8; 32]));
    assert_eq!(o.sni, "vk.com", "outer SNI must follow reality_target");
}

#[test]
fn protocol_udp_framing_and_channel_classifier_roundtrip() {
    use bibavpn::protocol::{
        build_socks5_udp_datagram, classify_v3_first_channel, decode_udp_rep, decode_udp_req,
        encode_udp_rep, encode_udp_req, encode_v3_auth, encode_v3_mux_open, encode_v3_open,
        encode_v3_open_ok, encode_v3_udp_mux_open, parse_socks5_udp_datagram, V3FirstChannelKind,
    };

    for (host, port) in [("example.com", 53), ("192.0.2.1", 9), ("2001:db8::1", 5353)] {
        let datagram = build_socks5_udp_datagram(host, port, b"dns-query").unwrap();
        let (got_host, got_port, payload) = parse_socks5_udp_datagram(&datagram).unwrap();
        assert_eq!(got_host, host);
        assert_eq!(got_port, port);
        assert_eq!(payload, b"dns-query");

        let req = encode_udp_req(0x0102_0304_0506_0708, host, port, b"dns-query").unwrap();
        let (xid, req_host, req_port, req_payload) = decode_udp_req(&req).unwrap();
        assert_eq!(xid, 0x0102_0304_0506_0708);
        assert_eq!(req_host, host);
        assert_eq!(req_port, port);
        assert_eq!(req_payload, b"dns-query");

        let rep = encode_udp_rep(xid, host, port, b"answer").unwrap();
        let (rep_xid, rep_host, rep_port, rep_payload) = decode_udp_rep(&rep).unwrap();
        assert_eq!(rep_xid, xid);
        assert_eq!(rep_host, host);
        assert_eq!(rep_port, port);
        assert_eq!(rep_payload, b"answer");
    }

    assert_eq!(
        classify_v3_first_channel(&encode_v3_mux_open()),
        V3FirstChannelKind::Mux
    );
    assert_eq!(
        classify_v3_first_channel(&encode_v3_udp_mux_open()),
        V3FirstChannelKind::UdpMux
    );
    assert!(matches!(
        classify_v3_first_channel(&encode_v3_open("example.org", 443).unwrap()),
        V3FirstChannelKind::TcpOpen { port: 443, .. }
    ));
    assert_eq!(
        classify_v3_first_channel(&encode_v3_open_ok()),
        V3FirstChannelKind::NotChannelOpen
    );
    assert_eq!(
        classify_v3_first_channel(&encode_v3_auth("token").unwrap()),
        V3FirstChannelKind::NotChannelOpen
    );
}

#[test]
fn padded_frame_enforces_public_payload_cap() {
    let mut out = Vec::new();
    // Frame format is a u24 length: 0xFF_FFFF is the largest representable payload.
    let max_payload = vec![0u8; 0xFF_FFFF];
    bibavpn::write_padded_frame(&mut out, &max_payload, 0).unwrap();
    assert_eq!(
        bibavpn::read_padded_frame_borrow(&out).unwrap().len(),
        max_payload.len()
    );
    assert!(bibavpn::write_padded_frame(&mut Vec::new(), &[0u8; 0x100_0000], 0).is_err());
}
