//! Optional platform hook applied before every outbound peer TCP connect.
use std::io;

#[cfg(unix)]
use std::{os::fd::AsRawFd, sync::{Arc, Mutex}};

#[cfg(unix)]
type Hook = Arc<dyn Fn(i32) -> io::Result<()> + Send + Sync>;
#[cfg(unix)]
static HOOK: Mutex<Option<Hook>> = Mutex::new(None);

#[cfg(unix)]
pub fn set_hook(hook: Option<Hook>) {
    *HOOK.lock().unwrap_or_else(|e| e.into_inner()) = hook;
}

pub async fn connect(target: &str) -> io::Result<tokio::net::TcpStream> {
    #[cfg(unix)]
    {
        let mut last_error = None;
        for addr in tokio::net::lookup_host(target).await? {
            let socket = if addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            let hook = HOOK.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(hook) = hook {
                hook(socket.as_raw_fd())?;
            } else if cfg!(target_os = "android") {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Android peer socket protection is unavailable"));
            }
            match socket.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer has no addresses")))
    }
    #[cfg(not(unix))]
    tokio::net::TcpStream::connect(target).await
}
