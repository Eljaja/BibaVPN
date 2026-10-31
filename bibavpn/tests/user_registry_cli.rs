use std::process::Command;

#[test]
fn server_exposes_user_registry_option() {
    let output = Command::new(env!("CARGO_BIN_EXE_bibavpn-server"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--users-file"));
}

#[test]
fn admin_tool_is_available() {
    assert!(
        option_env!("CARGO_BIN_EXE_bibavpn-users").is_some(),
        "missing user administration binary"
    );
}

#[test]
fn admin_add_list_disable_enable_and_mint() {
    use bibavpn::invite_uri::decode_invite_v1;
    let dir = std::env::temp_dir().join(format!("biba-admin-{}", rand::random::<u64>()));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("users.json");
    let admin = env!("CARGO_BIN_EXE_bibavpn-users");
    let run = |args: &[&str]| {
        Command::new(admin)
            .arg("--users-file")
            .arg(&file)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["add", "alice", "--max-concurrent", "2"])
        .status
        .success());
    let registry = bibavpn::users::load_users(&file).unwrap();
    assert_eq!(registry.users.len(), 1);
    assert_eq!(registry.users[0].max_concurrent, Some(2));
    let output = run(&["list"]);
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&registry.users[0].token));
    assert!(run(&["disable", "alice"]).status.success());
    assert!(!bibavpn::users::load_users(&file).unwrap().users[0].enabled);
    assert!(!run(&["mint", "alice"]).status.success());
    assert!(run(&["enable", "alice"]).status.success());
    assert!(!run(&["add", "alice"]).status.success());
    assert!(!run(&["add", "bob", "--max-concurrent", "0"])
        .status
        .success());
    let minted = Command::new(admin)
        .arg("--users-file")
        .arg(&file)
        .args(["mint", "alice"])
        .env("INVITE_PUBLIC", "localhost:8443")
        .env("INVITE_REALITY_TARGET", "example.com:443")
        .env(
            "INVITE_REALITY_PUBLIC_KEY",
            "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=",
        )
        .env("INVITE_REALITY_SHORT_ID", "0102030405060708")
        .env("BIBA_VPN_PSK", "example-psk")
        .env("BIBA_INVITE_PASSPHRASE", "example-passphrase")
        .output()
        .unwrap();
    assert!(
        minted.status.success(),
        "{}",
        String::from_utf8_lossy(&minted.stderr)
    );
    let invite = decode_invite_v1(
        String::from_utf8_lossy(&minted.stdout).trim(),
        "example-passphrase",
    )
    .unwrap();
    assert_eq!(invite.token, registry.users[0].token);
    assert!(!invite.insecure);
    assert_eq!(invite.reality_target.as_deref(), Some("example.com:443"));
    assert_eq!(invite.reality_public_key_parsed().unwrap(), Some([42; 32]));
    assert_eq!(
        invite.reality_short_id_parsed().unwrap(),
        Some([1, 2, 3, 4, 5, 6, 7, 8])
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
