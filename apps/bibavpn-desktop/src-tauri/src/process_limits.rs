//! Raise soft `RLIMIT_NOFILE` on Unix desktop (Linux + macOS).

pub const WANT_NOFILE: u64 = 50_000;

/// Pure helper for unit tests: never lowers `cur`; caps at `min(want, hard)` when hard is finite.
pub fn desired_nofile_soft(cur: u64, hard: u64, want: u64) -> u64 {
    let cap = if hard == u64::MAX { want } else { want.min(hard) };
    cap.max(cur)
}

/// Raise the soft descriptor limit toward [`WANT_NOFILE`], capped by the hard limit.
pub fn init_process_limits() {
    use libc::{getrlimit, rlimit, setrlimit, RLIMIT_NOFILE, RLIM_INFINITY};

    unsafe {
        let mut lim: rlimit = std::mem::zeroed();
        if getrlimit(RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let cur = lim.rlim_cur as u64;
        let hard = if lim.rlim_max == RLIM_INFINITY {
            u64::MAX
        } else {
            lim.rlim_max as u64
        };
        let target = desired_nofile_soft(cur, hard, WANT_NOFILE);
        if target > cur {
            lim.rlim_cur = target as libc::rlim_t;
            let _ = setrlimit(RLIMIT_NOFILE, &lim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_nofile_soft_never_lowers_current() {
        assert_eq!(desired_nofile_soft(10_000, 100_000, WANT_NOFILE), WANT_NOFILE);
        assert_eq!(desired_nofile_soft(60_000, 100_000, WANT_NOFILE), 60_000);
    }

    #[test]
    fn desired_nofile_soft_caps_at_hard_when_finite() {
        assert_eq!(desired_nofile_soft(1024, 4096, WANT_NOFILE), 4096);
        assert_eq!(desired_nofile_soft(1024, 4096, 2000), 2000);
    }

    #[test]
    fn desired_nofile_soft_uses_want_when_hard_is_infinite() {
        assert_eq!(
            desired_nofile_soft(1024, u64::MAX, WANT_NOFILE),
            WANT_NOFILE
        );
    }
}
