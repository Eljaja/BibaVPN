//! ICMPv6 echo ("ping") sessions over the in-netstack Yggdrasil interface.
//!
//! The probes travel through smoltcp's ICMP socket and the yggdrasil core
//! exactly like any other netstack traffic — no TUN device is involved.

use std::future::Future;
use std::net::Ipv6Addr;
use std::pin::pin;
use std::time::Duration;

use tokio::time::Instant;

use crate::netstack::YggNetstack;

/// Echo payload size (bytes) — matches the 56-byte data of a classic
/// `ping(1)` default, keeping packets far below the 1280-byte MTU.
pub const PING_PAYLOAD_LEN: usize = 56;

/// One reported event of a ping session.
#[derive(Debug, Clone, PartialEq)]
pub enum PingEvent {
    /// Result of one sent probe. `rtt` is `None` on timeout, with `error`
    /// carrying the reason.
    Probe {
        seq: u16,
        rtt: Option<Duration>,
        error: Option<String>,
    },
    /// The session ended.
    Done { reason: PingDoneReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingDoneReason {
    /// All `count` probes were sent.
    Completed,
    /// Stopped by the caller before the count ran out.
    Stopped,
    /// A netstack/socket error aborted the session.
    Failed,
}

/// Validate that `addr` is a Yggdrasil address (inside 200::/7).
pub fn is_ygg_address(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0x0200
}

/// Run a ping session against `dst`, reporting every probe through
/// `on_event`. Sends `count` probes (0 = until stopped) with `interval`
/// between them, each waiting up to `timeout` for its reply. Resolves when
/// the session completes, is stopped (the `stop` future fires), or fails.
///
/// The first probe to a never-contacted destination can be delayed by the
/// overlay's first-contact path lookup and session handshake; it is
/// reported as-is (typically a timeout).
pub async fn run_ping<S, F>(
    ns: &YggNetstack,
    dst: Ipv6Addr,
    count: u32,
    timeout: Duration,
    interval: Duration,
    stop: S,
    mut on_event: F,
) where
    S: Future<Output = ()>,
    F: FnMut(PingEvent),
{
    let sock = match ns.open_icmp() {
        Ok(s) => s,
        Err(e) => {
            on_event(PingEvent::Done {
                reason: PingDoneReason::Failed,
            });
            tracing::warn!("ping: could not open ICMP socket: {}", e);
            return;
        }
    };

    let payload: Vec<u8> = {
        let mut p = Vec::with_capacity(PING_PAYLOAD_LEN);
        while p.len() < PING_PAYLOAD_LEN {
            p.extend_from_slice(b"yggstack-ng ping ");
        }
        p.truncate(PING_PAYLOAD_LEN);
        p
    };
    let mut reply_buf = vec![0u8; 1500];

    let mut stop = pin!(stop);
    let mut seq: u16 = 0;
    let mut sent: u32 = 0;

    loop {
        if count != 0 && sent >= count {
            on_event(PingEvent::Done {
                reason: PingDoneReason::Completed,
            });
            return;
        }

        seq = seq.wrapping_add(1);
        if let Err(e) = sock.send_echo(dst, seq, &payload).await {
            tracing::warn!("ping: send failed: {}", e);
            on_event(PingEvent::Done {
                reason: PingDoneReason::Failed,
            });
            return;
        }
        sent += 1;

        let started = Instant::now();
        let mut rtt = None;
        let mut stopped = false;
        'recv: loop {
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                break; // probe timed out
            };
            let reply = tokio::select! {
                () = &mut stop => {
                    stopped = true;
                    None
                }
                r = tokio::time::timeout(remaining, sock.recv_reply(&mut reply_buf)) => {
                    match r {
                        Ok(Ok(reply)) => Some(reply),
                        Ok(Err(e)) => {
                            tracing::warn!("ping: recv failed: {}", e);
                            on_event(PingEvent::Done {
                                reason: PingDoneReason::Failed,
                            });
                            return;
                        }
                        Err(_) => None, // per-probe timeout
                    }
                }
            };
            if stopped {
                // The in-flight probe is cancelled, not lost: report no
                // result for it, just end the session.
                break 'recv;
            }
            let Some((reply_seq, _src)) = reply else {
                break; // timed out
            };
            if reply_seq == seq {
                rtt = Some(started.elapsed());
                break;
            }
            // A late reply to an earlier probe: drain it and keep waiting.
        }

        if stopped {
            on_event(PingEvent::Done {
                reason: PingDoneReason::Stopped,
            });
            return;
        }

        match rtt {
            Some(rtt) => on_event(PingEvent::Probe {
                seq,
                rtt: Some(rtt),
                error: None,
            }),
            None => on_event(PingEvent::Probe {
                seq,
                rtt: None,
                error: Some("timeout".to_string()),
            }),
        }

        if count == 0 || sent < count {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                () = &mut stop => {
                    on_event(PingEvent::Done {
                        reason: PingDoneReason::Stopped,
                    });
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_ygg(a: &str) -> bool {
        is_ygg_address(&a.parse().unwrap())
    }

    #[test]
    fn ygg_range_check() {
        assert!(is_ygg("200::1"));
        assert!(is_ygg("203:5bdc:26f3:1c34:51d9:2a5f:6676:6b1e"));
        assert!(is_ygg("324::abcd"));
        assert!(!is_ygg("::1"));
        assert!(!is_ygg("2001:db8::1"));
        assert!(!is_ygg("fe80::1"));
    }
}
