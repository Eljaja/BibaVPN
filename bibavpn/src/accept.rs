//! Shared `accept(2)` error classification for server and local client listeners.

use std::time::Duration;

/// Pause after an accept error that would otherwise repeat immediately.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What the accept loop does after a failed `accept(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptRecovery {
    /// Per-connection failure (peer vanished, signal): retry immediately.
    RetryNow,
    /// Sleep before retrying, otherwise the loop spins at 100% CPU for as long
    /// as the condition lasts. `exhaustion` marks the out-of-descriptors /
    /// out-of-buffers class so the log says so.
    RetryAfterBackoff { exhaustion: bool },
}

impl AcceptRecovery {
    pub fn backoff(self) -> Option<Duration> {
        match self {
            AcceptRecovery::RetryNow => None,
            AcceptRecovery::RetryAfterBackoff { .. } => Some(ACCEPT_BACKOFF),
        }
    }

    pub fn is_exhaustion(self) -> bool {
        matches!(self, AcceptRecovery::RetryAfterBackoff { exhaustion: true })
    }
}

/// True for raw OS errors meaning "out of descriptors or kernel buffers".
/// These have no distinct `std::io::ErrorKind` on stable Rust, so they are
/// matched numerically; the values are per-platform ABI constants.
#[cfg(unix)]
pub fn is_accept_resource_exhaustion(code: i32) -> bool {
    // EMFILE, ENFILE and ENOMEM share values across Linux and the BSDs;
    // ENOBUFS does not.
    const EMFILE: i32 = 24;
    const ENFILE: i32 = 23;
    const ENOMEM: i32 = 12;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENOBUFS: i32 = 105;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const ENOBUFS: i32 = 55;
    matches!(code, EMFILE | ENFILE | ENOMEM | ENOBUFS)
}

#[cfg(windows)]
pub fn is_accept_resource_exhaustion(code: i32) -> bool {
    // WSAEMFILE, WSAENOBUFS, WSAETOOMANYREFS.
    matches!(code, 10024 | 10055 | 10059)
}

#[cfg(not(any(unix, windows)))]
pub fn is_accept_resource_exhaustion(_code: i32) -> bool {
    false
}

/// Classify an `accept(2)` error. Never fatal: see the accept loop comment.
pub fn classify_accept_error(e: &std::io::Error) -> AcceptRecovery {
    use std::io::ErrorKind;
    match e.kind() {
        // Cheap and clearly per-connection: the next accept can succeed at once.
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::Interrupted
        | ErrorKind::WouldBlock => AcceptRecovery::RetryNow,
        // ENOMEM where the platform maps it to a kind.
        ErrorKind::OutOfMemory => AcceptRecovery::RetryAfterBackoff { exhaustion: true },
        // EMFILE/ENFILE/ENOBUFS have no stable `ErrorKind`, so check the raw
        // code. Unrecognised errors back off as well: losing 100ms of accept
        // throughput is cheaper than spinning on an error we do not know.
        _ => AcceptRecovery::RetryAfterBackoff {
            exhaustion: e.raw_os_error().is_some_and(is_accept_resource_exhaustion),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn transient_per_connection_accept_errors_retry_immediately() {
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
        ] {
            let r = classify_accept_error(&Error::from(kind));
            assert_eq!(r, AcceptRecovery::RetryNow, "kind {kind:?}");
            assert_eq!(r.backoff(), None, "kind {kind:?}");
            assert!(!r.is_exhaustion(), "kind {kind:?}");
        }
    }

    #[test]
    fn out_of_memory_accept_error_backs_off() {
        let r = classify_accept_error(&Error::from(ErrorKind::OutOfMemory));
        assert_eq!(r, AcceptRecovery::RetryAfterBackoff { exhaustion: true });
        assert_eq!(r.backoff(), Some(ACCEPT_BACKOFF));
    }

    #[test]
    fn unknown_accept_error_backs_off_without_exhaustion_flag() {
        let r = classify_accept_error(&Error::from(ErrorKind::PermissionDenied));
        assert_eq!(r, AcceptRecovery::RetryAfterBackoff { exhaustion: false });
        assert_eq!(r.backoff(), Some(ACCEPT_BACKOFF));
    }

    // Raw codes for the current platform: EMFILE, ENFILE, ENOMEM, ENOBUFS
    // (WSAEMFILE, WSAENOBUFS, WSAETOOMANYREFS on Windows). Most have no stable
    // `ErrorKind`, which is the case the raw-code rule exists for.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const EXHAUSTION_CODES: &[i32] = &[24, 23, 12, 105];
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    const EXHAUSTION_CODES: &[i32] = &[24, 23, 12, 55];
    #[cfg(windows)]
    const EXHAUSTION_CODES: &[i32] = &[10024, 10055, 10059];
    #[cfg(not(any(unix, windows)))]
    const EXHAUSTION_CODES: &[i32] = &[];

    #[test]
    fn descriptor_exhaustion_accept_errors_back_off() {
        for &code in EXHAUSTION_CODES {
            let r = classify_accept_error(&Error::from_raw_os_error(code));
            assert!(
                r.is_exhaustion(),
                "errno {code} should be exhaustion: {r:?}"
            );
            assert_eq!(r.backoff(), Some(ACCEPT_BACKOFF), "errno {code}");
        }
    }

    #[test]
    fn accept_backoff_is_short() {
        assert!(ACCEPT_BACKOFF >= Duration::from_millis(50));
        assert!(ACCEPT_BACKOFF <= Duration::from_millis(250));
    }
}
