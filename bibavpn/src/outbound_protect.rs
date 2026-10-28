//! Optional hook: mark outbound TCP sockets before `connect` (Android `VpnService.protect`).

use std::io;

#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(unix)]
use std::sync::{Arc, Mutex};

#[cfg(unix)]
type Hook = Arc<dyn Fn(RawFd) -> io::Result<()> + Send + Sync>;

#[cfg(unix)]
static HOOK: Mutex<Option<Hook>> = Mutex::new(None);

/// Install or clear the pre-connect hook (e.g. JNI → `VpnService.protect`).
#[cfg(unix)]
pub fn set_hook(hook: Option<Hook>) {
    *HOOK.lock().unwrap_or_else(|p| p.into_inner()) = hook;
}

#[cfg(unix)]
fn apply_hook(fd: RawFd) -> io::Result<()> {
    // Clone the Arc and release the lock before calling into foreign code. A slow
    // or re-entrant JNI hook must not block every other connect (and a panicking
    // hook must not poison the global).
    let hook = HOOK.lock().unwrap_or_else(|p| p.into_inner()).clone();
    match hook {
        Some(f) => f(fd),
        None => Ok(()),
    }
}

#[cfg(unix)]
pub async fn tcp_connect_host_protected(
    host: &str,
    port: u16,
) -> io::Result<tokio::net::TcpStream> {
    let mut last_err: Option<io::Error> = None;
    for addr in tokio::net::lookup_host((host, port)).await? {
        match tcp_connect_socket_protected(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "tcp_connect_host_protected: no addresses",
        )
    }))
}

#[cfg(unix)]
async fn tcp_connect_socket_protected(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    apply_hook(socket.as_raw_fd())?;
    socket.set_nodelay(true)?;
    socket.connect(addr).await
}

#[cfg(not(unix))]
pub fn set_hook(_hook: Option<()>) {}

#[cfg(not(unix))]
pub async fn tcp_connect_host_protected(
    host: &str,
    port: u16,
) -> io::Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect((host, port)).await
}

#[cfg(all(test, unix))]
mod tests {
    use super::{apply_hook, set_hook};
    use std::sync::Arc;
    use std::time::Duration;

    /// The hook runs without the registry lock held, so it may call back into
    /// `set_hook` (a JNI hook that disables itself) without deadlocking.
    #[test]
    fn hook_may_clear_itself_without_deadlock() {
        set_hook(Some(Arc::new(|_fd| {
            set_hook(None);
            Ok(())
        })));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(apply_hook(0).is_ok());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap_or(false),
            "hook deadlocked while trying to clear itself"
        );
        set_hook(None);
        assert!(apply_hook(0).is_ok());
    }
}
