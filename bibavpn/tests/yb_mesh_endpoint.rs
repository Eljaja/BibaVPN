#[test]
fn mesh_endpoint_must_be_a_yggdrasil_socket() {
    use bibavpn::yb_mesh::parse_endpoint;
    assert!(parse_endpoint("[201:db8::42]:8443").is_ok());
    for invalid in ["203.0.113.7:443", "[2001:db8::1]:443", "[201:db8::42]:0", "example.com:443"] {
        assert!(parse_endpoint(invalid).is_err(), "accepted {invalid}");
    }
}
