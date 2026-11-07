use bibavpn::{decode_invite_v1, encode_invite_v1, InviteV1};

#[test]
fn mesh_endpoint_survives_encrypted_invite_and_is_optional() {
    let old = r#"{"v":1,"server":"vpn.example:443","sni":"vpn.example","token":"t","psk":"p","decoy_max":0,"max_pad":64,"max_ws_binary":1400,"ws_ping_secs":25,"insecure":true,"tls_profile":"default"}"#;
    let mut invite: InviteV1 = serde_json::from_str(old).unwrap();
    assert!(invite.yb_mesh.is_none());
    invite.yb_mesh = Some(serde_json::from_str(r#"{"endpoint":"[201:db8::42]:8443"}"#).unwrap());
    let uri = encode_invite_v1(&invite, "test-password").unwrap();
    assert_eq!(decode_invite_v1(&uri, "test-password").unwrap(), invite);
}

#[test]
fn mint_cli_embeds_and_validates_mesh_endpoint() {
    fn mint(endpoint: &str) -> std::process::Output {
        std::process::Command::new(env!("CARGO_BIN_EXE_bibavpn-mint-invite"))
            .env("INVITE_PUBLIC", "vpn.example:443")
            .env("BIBA_VPN_TOKEN", "test-token")
            .env("BIBA_VPN_PSK", "0123456789abcdef0123456789abcdef")
            .env("BIBA_INVITE_PASSPHRASE", "test-password")
            .env("BIBA_YB_MESH_ENDPOINT", endpoint)
            .output().unwrap()
    }
    let result = mint("[201:db8::42]:8443");
    assert!(result.status.success());
    let uri = String::from_utf8(result.stdout).unwrap();
    let invite = decode_invite_v1(uri.trim(), "test-password").unwrap();
    assert_eq!(invite.yb_mesh.unwrap().endpoint, "[201:db8::42]:8443");
    assert!(!mint("127.0.0.1:8443").status.success());
}

#[test]
fn mint_cli_can_embed_pinned_certificate() {
    let cert = std::env::temp_dir().join(format!("bibavpn-test-cert-{}", std::process::id()));
    std::fs::write(&cert, "test certificate").unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_bibavpn-mint-invite"))
        .env("INVITE_PUBLIC", "vpn.example:443")
        .env("BIBA_VPN_TOKEN", "test-token")
        .env("BIBA_VPN_PSK", "0123456789abcdef0123456789abcdef")
        .env("BIBA_INVITE_PASSPHRASE", "test-password")
        .env("INVITE_PIN_CERT_FILE", &cert)
        .output().unwrap();
    std::fs::remove_file(cert).unwrap();
    assert!(result.status.success());
    let uri = String::from_utf8(result.stdout).unwrap();
    let invite = decode_invite_v1(uri.trim(), "test-password").unwrap();
    assert!(!invite.insecure);
    assert_eq!(invite.pin_cert_pem.as_deref(), Some("test certificate"));
}
