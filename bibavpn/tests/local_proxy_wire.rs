//! Wire-level regressions for the two local proxy frontends (SOCKS5 and HTTP).
//!
//! Everything runs over a real `127.0.0.1:0` TCP pair: no external network, no
//! tunnel, no certificate. These catch parser regressions that unit tests on
//! the private helpers cannot see (e.g. an accidental early read/short read).

use std::time::Duration;

use bibavpn::http_connect::{http_proxy_handshake, try_serve_health_check, HttpProxyHandshake};
use bibavpn::socks5::{
    is_benign_handshake_abort, socks5_read_command, socks5_reply_ok, socks5_reply_udp_associate,
    SocksCommand,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (client.expect("connect"), server.expect("accept").0)
}

/// SOCKS5 CONNECT request with a domain ATYP.
fn socks_connect_domain(host: &str, port: u16) -> Vec<u8> {
    let mut v = vec![5, 1, 0, 3, host.len() as u8];
    v.extend_from_slice(host.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

#[tokio::test]
async fn socks_connect_domain_roundtrip() {
    let (mut client, mut server) = pair().await;
    let (reply, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0]);
                client
                    .write_all(&socks_connect_domain("example.com", 443))
                    .await
                    .unwrap();
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                reply
            },
            async {
                match socks5_read_command(&mut server, None).await.unwrap() {
                    SocksCommand::Connect { host, port } => {
                        assert_eq!(host, "example.com");
                        assert_eq!(port, 443);
                    }
                    other => panic!("expected Connect, got {other:?}"),
                }
                socks5_reply_ok(&mut server).await.unwrap();
            }
        )
    })
    .await
    .expect("socks connect timed out");
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn socks_connect_ipv6_literal_roundtrip() {
    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                let mut req = vec![5, 1, 0, 4];
                req.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                req.extend_from_slice(&8443u16.to_be_bytes());
                client.write_all(&req).await.unwrap();
            },
            async {
                match socks5_read_command(&mut server, None).await.unwrap() {
                    SocksCommand::Connect { host, port } => {
                        assert_eq!(host, "::1");
                        assert_eq!(port, 8443);
                    }
                    other => panic!("expected Connect, got {other:?}"),
                }
            }
        )
    })
    .await
    .expect("socks ipv6 timed out");
}

#[tokio::test]
async fn socks_udp_associate_returns_relay_address() {
    let (mut client, mut server) = pair().await;
    let (relay_port, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0]);
                client
                    .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply[..4], &[5, 0, 0, 1]);
                assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
                u16::from_be_bytes([reply[8], reply[9]])
            },
            async {
                match socks5_read_command(&mut server, None).await.unwrap() {
                    SocksCommand::UdpAssociate { host, port } => {
                        assert_eq!(host, "0.0.0.0");
                        assert_eq!(port, 0);
                    }
                    other => panic!("expected UdpAssociate, got {other:?}"),
                }
                socks5_reply_udp_associate(&mut server, 4242).await.unwrap();
            }
        )
    })
    .await
    .expect("socks udp associate timed out");
    assert_eq!(relay_port, 4242);
}

#[tokio::test]
async fn socks_rfc1929_auth_success_and_failure() {
    let auth = ("alice".to_string(), "hunter2".to_string());

    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client.write_all(&[5, 1, 2]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 2]);
                let mut creds = vec![1, 5];
                creds.extend_from_slice(b"alice");
                creds.push(7);
                creds.extend_from_slice(b"hunter2");
                client.write_all(&creds).await.unwrap();
                let mut ok = [0u8; 2];
                client.read_exact(&mut ok).await.unwrap();
                assert_eq!(ok, [1, 0]);
                client
                    .write_all(&socks_connect_domain("example.org", 80))
                    .await
                    .unwrap();
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            },
            async {
                assert!(matches!(
                    socks5_read_command(&mut server, Some(&auth)).await.unwrap(),
                    SocksCommand::Connect { .. }
                ));
                socks5_reply_ok(&mut server).await.unwrap();
            }
        )
    })
    .await
    .expect("socks auth success timed out");

    let (mut client, mut server) = pair().await;
    let ((), server_err) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client.write_all(&[5, 1, 2]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                let mut creds = vec![1, 5];
                creds.extend_from_slice(b"alice");
                creds.push(5);
                creds.extend_from_slice(b"wrong");
                client.write_all(&creds).await.unwrap();
                let mut denied = [0u8; 2];
                client.read_exact(&mut denied).await.unwrap();
                assert_eq!(denied, [1, 1]);
            },
            async {
                socks5_read_command(&mut server, Some(&auth))
                    .await
                    .expect_err("wrong password must fail")
                    .to_string()
            }
        )
    })
    .await
    .expect("socks auth failure timed out");
    assert!(
        server_err.contains("username/password rejected"),
        "{server_err}"
    );
}

#[tokio::test]
async fn socks_rejects_method_downgrade_and_bad_version() {
    let auth = ("alice".to_string(), "hunter2".to_string());

    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0xff], "server must refuse no-auth");
            },
            async {
                let err = socks5_read_command(&mut server, Some(&auth))
                    .await
                    .expect_err("no-auth must be refused");
                assert!(err.to_string().contains("username/password"), "{err}");
            }
        )
    })
    .await
    .expect("socks downgrade timed out");

    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client.write_all(&[4, 1, 0]).await.unwrap();
            },
            async {
                let err = socks5_read_command(&mut server, None)
                    .await
                    .expect_err("SOCKS4 must be refused");
                assert!(
                    err.to_string().contains("unsupported socks version"),
                    "{err}"
                );
            }
        )
    })
    .await
    .expect("socks version timed out");
}

#[tokio::test]
async fn socks_peer_close_is_classified_benign() {
    let (client, mut server) = pair().await;
    drop(client);
    let err = tokio::time::timeout(IO_TIMEOUT, socks5_read_command(&mut server, None))
        .await
        .expect("timed out waiting for eof")
        .expect_err("eof must be an error");
    assert!(
        is_benign_handshake_abort(&err),
        "probe close should be benign: {err:#}"
    );
}

#[tokio::test]
async fn http_connect_preserves_early_client_bytes() {
    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client
                    .write_all(
                        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n\x16\x03\x01\x00\x05",
                    )
                    .await
                    .unwrap();
                // Give the server's BufReader a chance to see the prefetch bytes.
                tokio::time::sleep(Duration::from_millis(20)).await;
                let mut reply = [0u8; 39];
                client.read_exact(&mut reply).await.unwrap();
                assert!(reply.starts_with(b"HTTP/1.1 200 "));
            },
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                match http_proxy_handshake(&mut server).await.unwrap() {
                    HttpProxyHandshake::Connect {
                        host,
                        port,
                        client_prefetch,
                    } => {
                        assert_eq!(host, "example.com");
                        assert_eq!(port, 443);
                        assert_eq!(client_prefetch, b"\x16\x03\x01\x00\x05");
                    }
                    other => panic!("expected Connect, got {other:?}"),
                }
                bibavpn::http_connect::reply_connect_ok(&mut server)
                    .await
                    .unwrap();
            }
        )
    })
    .await
    .expect("http connect timed out");
}

#[tokio::test]
async fn http_absolute_form_is_rewritten_for_origin() {
    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client
                    .write_all(
                        b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\nBODY",
                    )
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            },
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                match http_proxy_handshake(&mut server).await.unwrap() {
                    HttpProxyHandshake::ForwardHttp {
                        host,
                        port,
                        to_origin,
                    } => {
                        assert_eq!(host, "example.com");
                        assert_eq!(port, 80);
                        assert!(
                            to_origin.starts_with(b"GET /path?q=1 HTTP/1.1\r\n"),
                            "request line not rewritten: {:?}",
                            String::from_utf8_lossy(&to_origin)
                        );
                        assert!(
                            to_origin.windows(18).any(|w| w == b"Host: example.com\r"),
                            "Host header lost: {:?}",
                            String::from_utf8_lossy(&to_origin)
                        );
                        assert!(to_origin.ends_with(b"BODY"), "body prefix lost");
                    }
                    other => panic!("expected ForwardHttp, got {other:?}"),
                }
            }
        )
    })
    .await
    .expect("http absolute form timed out");
}

#[tokio::test]
async fn http_absolute_https_is_refused() {
    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client
                    .write_all(b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    .await
                    .unwrap();
            },
            async {
                let err = http_proxy_handshake(&mut server)
                    .await
                    .expect_err("https absolute URI must be refused");
                assert!(
                    err.to_string().contains("unsupported proxy URI scheme"),
                    "{err}"
                );
            }
        )
    })
    .await
    .expect("http https absolute timed out");
}

#[tokio::test]
async fn http_health_check_does_not_open_a_tunnel() {
    let (mut client, mut server) = pair().await;
    let (body, handled) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client
                    .write_all(b"GET /bibavpn-health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await
                    .unwrap();
                // The handler keeps the TcpStream alive until the join
                // completes, so wait for the known body instead of EOF.
                let mut body = Vec::new();
                let mut chunk = [0u8; 128];
                while !body.ends_with(b"ok") {
                    let n = client.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "connection closed before health body");
                    body.extend_from_slice(&chunk[..n]);
                }
                body
            },
            async { try_serve_health_check(&mut server).await.unwrap() }
        )
    })
    .await
    .expect("health check timed out");
    assert!(handled);
    let text = String::from_utf8_lossy(&body);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    assert!(text.ends_with("ok"), "{text}");
}

#[tokio::test]
async fn http_health_check_ignores_other_requests() {
    let (mut client, mut server) = pair().await;
    let (_, ()) = tokio::time::timeout(IO_TIMEOUT, async {
        tokio::join!(
            async {
                client
                    .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    .await
                    .unwrap();
            },
            async {
                assert!(!try_serve_health_check(&mut server).await.unwrap());
                // Non-health prefix must not consume the request: the CONNECT
                // parser still sees it.
                assert!(matches!(
                    http_proxy_handshake(&mut server).await.unwrap(),
                    HttpProxyHandshake::Connect { .. }
                ));
            }
        )
    })
    .await
    .expect("health passthrough timed out");
}
