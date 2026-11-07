use bibavpn::{local_client_options_from_json_str, encode_invite_v1, InviteV1};

#[test]
fn mesh_requires_an_endpoint_and_keeps_direct_mode_default() {
    let base = r#"{"server":"vpn.example:443","token":"secret-token","psk":"0123456789abcdef0123456789abcdef"}"#;
    let direct = local_client_options_from_json_str(base).unwrap();
    assert!(direct.yb_mesh_endpoint.is_none());
    let mut value: serde_json::Value = serde_json::from_str(base).unwrap();
    value["yb_mesh_enabled"] = true.into();
    assert!(local_client_options_from_json_str(&value.to_string()).is_err());

    let old = r#"{"v":1,"server":"vpn.example:443","sni":"vpn.example","token":"secret-token","psk":"0123456789abcdef0123456789abcdef","decoy_max":0,"max_pad":64,"max_ws_binary":1400,"ws_ping_secs":25,"insecure":true,"tls_profile":"default","yb_mesh":{"endpoint":"[201:db8::42]:8443"}}"#;
    let invite: InviteV1 = serde_json::from_str(old).unwrap();
    let uri = encode_invite_v1(&invite, "test-password").unwrap();
    let json = serde_json::json!({"from_invite":uri,"invite_passphrase":"test-password","yb_mesh_enabled":true});
    let options = local_client_options_from_json_str(&json.to_string()).unwrap();
    assert_eq!(options.yb_mesh_endpoint.as_deref(), Some("[201:db8::42]:8443"));
    assert_eq!(options.server_host, "vpn.example");
}
