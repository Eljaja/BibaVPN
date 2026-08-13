//! JNI client thread slot: idle, live, or stopping (shutdown sent, join pending).

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::watch;

/// How long stop / start-wait blocks before failing closed.
pub const PRODUCTION_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum ClientSlot {
    Live {
        shutdown_tx: watch::Sender<bool>,
        thread: JoinHandle<()>,
        done_rx: Receiver<()>,
    },
    Stopping {
        thread: JoinHandle<()>,
        done_rx: Receiver<()>,
    },
}

enum JoinWait {
    Joined,
    Timeout(ClientSlot),
}

fn wait_join(stopping: ClientSlot, timeout: Duration) -> JoinWait {
    let ClientSlot::Stopping { thread, done_rx } = stopping else {
        panic!("wait_join expects Stopping");
    };
    match done_rx.recv_timeout(timeout) {
        // Sender dropped: thread body returned.
        Err(RecvTimeoutError::Disconnected) => {
            let _ = thread.join();
            JoinWait::Joined
        }
        // Channel is never written to; timeout means thread still running.
        Ok(()) | Err(RecvTimeoutError::Timeout) => {
            tracing::warn!(
                "stop: client thread still running after {:?}; keeping stopping slot (shutdown already signalled)",
                timeout
            );
            JoinWait::Timeout(ClientSlot::Stopping { thread, done_rx })
        }
    }
}

/// Tracks at most one client thread and enforces bounded join on stop / start.
pub struct ClientSlotManager {
    slot: Option<ClientSlot>,
    join_timeout: Duration,
}

impl ClientSlotManager {
    pub fn new(join_timeout: Duration) -> Self {
        Self {
            slot: None,
            join_timeout,
        }
    }

    pub fn is_idle(&self) -> bool {
        self.slot.is_none()
    }

    #[cfg(test)]
    pub fn live_thread_count_for_test(&self) -> usize {
        match &self.slot {
            None => 0,
            Some(ClientSlot::Live { thread, .. }) => {
                if thread.is_finished() {
                    0
                } else {
                    1
                }
            }
            Some(ClientSlot::Stopping { thread, .. }) => {
                if thread.is_finished() {
                    0
                } else {
                    1
                }
            }
        }
    }

    /// Prepare for a new client: wait out a stopping slot or join a dead live thread.
    /// Returns `Err("already running")` if a thread is still alive after the bounded wait.
    pub fn try_prepare_start(&mut self, clear_hook: impl Fn()) -> Result<(), &'static str> {
        loop {
            let Some(slot) = self.slot.take() else {
                return Ok(());
            };
            match slot {
                ClientSlot::Live {
                    shutdown_tx,
                    thread,
                    done_rx,
                } => {
                    if !thread.is_finished() {
                        self.slot = Some(ClientSlot::Live {
                            shutdown_tx,
                            thread,
                            done_rx,
                        });
                        return Err("already running");
                    }
                    let _ = thread.join();
                    drop(shutdown_tx);
                    clear_hook();
                }
                ClientSlot::Stopping { thread, done_rx } => {
                    match wait_join(ClientSlot::Stopping { thread, done_rx }, self.join_timeout)
                    {
                        JoinWait::Joined => clear_hook(),
                        JoinWait::Timeout(stopping) => {
                            self.slot = Some(stopping);
                            return Err("already running");
                        }
                    }
                }
            }
        }
    }

    pub fn install_live(
        &mut self,
        shutdown_tx: watch::Sender<bool>,
        thread: JoinHandle<()>,
        done_rx: Receiver<()>,
    ) {
        self.slot = Some(ClientSlot::Live {
            shutdown_tx,
            thread,
            done_rx,
        });
    }

    /// Signal shutdown (if live), wait up to [`Self::join_timeout`], then join or keep stopping.
    pub fn stop(&mut self, clear_hook: impl FnOnce()) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        let stopping = match slot {
            ClientSlot::Live {
                shutdown_tx,
                thread,
                done_rx,
            } => {
                let _ = shutdown_tx.send(true);
                ClientSlot::Stopping { thread, done_rx }
            }
            ClientSlot::Stopping { thread, done_rx } => ClientSlot::Stopping { thread, done_rx },
        };
        match wait_join(stopping, self.join_timeout) {
            JoinWait::Joined => clear_hook(),
            JoinWait::Timeout(stopping) => self.slot = Some(stopping),
        }
    }

    /// Join a live slot after a failed start (e.g. SOCKS bind timeout). Same stopping semantics.
    pub fn abort_pending_start(&mut self, clear_hook: impl FnOnce()) {
        self.stop(clear_hook);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    const TEST_JOIN_TIMEOUT: Duration = Duration::from_millis(100);

    fn spawn_dummy(sleep: Duration, shutdown: watch::Receiver<bool>) -> (JoinHandle<()>, Receiver<()>) {
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let _done_tx = done_tx;
            let deadline = Instant::now() + sleep;
            while Instant::now() < deadline {
                if *shutdown.borrow() {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        (handle, done_rx)
    }

    fn spawn_ignore_shutdown(sleep: Duration) -> (JoinHandle<()>, Receiver<()>) {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        spawn_dummy(sleep, shutdown_rx)
    }

    #[test]
    fn stop_timeout_leaves_stopping_slot() {
        let hook_cleared = Arc::new(AtomicBool::new(false));
        let hook_flag = hook_cleared.clone();
        let mut mgr = ClientSlotManager::new(TEST_JOIN_TIMEOUT);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (thread, done_rx) = spawn_ignore_shutdown(Duration::from_secs(30));
        mgr.install_live(shutdown_tx, thread, done_rx);

        mgr.stop(|| hook_flag.store(true, Ordering::SeqCst));

        assert!(!mgr.is_idle());
        assert!(!hook_cleared.load(Ordering::SeqCst));
        assert_eq!(mgr.live_thread_count_for_test(), 1);
    }

    #[test]
    fn start_after_stop_timeout_fails_closed() {
        let hook_cleared = Arc::new(AtomicBool::new(false));
        let hook_flag = hook_cleared.clone();
        let mut mgr = ClientSlotManager::new(TEST_JOIN_TIMEOUT);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (thread, done_rx) = spawn_ignore_shutdown(Duration::from_secs(30));
        mgr.install_live(shutdown_tx, thread, done_rx);
        mgr.stop(|| hook_flag.store(true, Ordering::SeqCst));
        assert!(!mgr.is_idle());

        let err = mgr.try_prepare_start(|| {}).unwrap_err();
        assert_eq!(err, "already running");
        assert_eq!(mgr.live_thread_count_for_test(), 1);
        assert!(!hook_cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn start_waits_for_stopping_thread_then_succeeds_once() {
        let hook_cleared = Arc::new(AtomicBool::new(false));
        let hook_flag = hook_cleared.clone();
        let mut mgr = ClientSlotManager::new(Duration::from_millis(100));
        let exit = Arc::new(AtomicBool::new(false));
        let exit_flag = exit.clone();
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let thread = thread::spawn(move || {
            let _done_tx = done_tx;
            while !exit_flag.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(5));
            }
        });
        mgr.install_live(shutdown_tx, thread, done_rx);
        mgr.stop(|| {});
        assert!(!mgr.is_idle());

        exit.store(true, Ordering::SeqCst);
        assert!(
            mgr.try_prepare_start(|| hook_flag.store(true, Ordering::SeqCst))
                .is_ok()
        );
        assert!(hook_cleared.load(Ordering::SeqCst));

        let (shutdown_tx2, _) = watch::channel(false);
        let (thread2, done_rx2) = spawn_ignore_shutdown(Duration::from_millis(10));
        mgr.install_live(shutdown_tx2, thread2, done_rx2);
        assert_eq!(mgr.live_thread_count_for_test(), 1);
    }

    #[test]
    fn stop_join_clears_slot_and_hook() {
        let hook_cleared = Arc::new(AtomicBool::new(false));
        let hook_flag = hook_cleared.clone();
        let mut mgr = ClientSlotManager::new(TEST_JOIN_TIMEOUT);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (thread, done_rx) = spawn_dummy(Duration::from_millis(10), shutdown_rx);
        mgr.install_live(shutdown_tx, thread, done_rx);

        mgr.stop(|| hook_flag.store(true, Ordering::SeqCst));

        assert!(mgr.is_idle());
        assert!(hook_cleared.load(Ordering::SeqCst));
    }

    #[test]
    fn start_after_successful_stop_succeeds() {
        let mut mgr = ClientSlotManager::new(TEST_JOIN_TIMEOUT);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (thread, done_rx) = spawn_dummy(Duration::from_millis(10), shutdown_rx);
        mgr.install_live(shutdown_tx, thread, done_rx);
        mgr.stop(|| {});

        assert!(mgr.try_prepare_start(|| {}).is_ok());
        let (shutdown_tx2, _) = watch::channel(false);
        let (thread2, done_rx2) = spawn_ignore_shutdown(Duration::from_millis(10));
        mgr.install_live(shutdown_tx2, thread2, done_rx2);
        assert_eq!(mgr.live_thread_count_for_test(), 1);
    }

    #[test]
    fn live_thread_still_running_rejects_start() {
        let mut mgr = ClientSlotManager::new(TEST_JOIN_TIMEOUT);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (thread, done_rx) = spawn_dummy(Duration::from_secs(30), shutdown_rx);
        mgr.install_live(shutdown_tx, thread, done_rx);

        let err = mgr.try_prepare_start(|| {}).unwrap_err();
        assert_eq!(err, "already running");
        assert_eq!(mgr.live_thread_count_for_test(), 1);
    }

    #[test]
    fn never_two_live_threads() {
        let mut mgr = ClientSlotManager::new(TEST_JOIN_TIMEOUT);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (thread, done_rx) = spawn_ignore_shutdown(Duration::from_secs(30));
        mgr.install_live(shutdown_tx, thread, done_rx);

        assert_eq!(mgr.live_thread_count_for_test(), 1);
        assert_eq!(mgr.try_prepare_start(|| {}).unwrap_err(), "already running");
        assert_eq!(mgr.live_thread_count_for_test(), 1);
    }

    #[test]
    fn double_stop_on_stopping_waits_again() {
        let hook_cleared = Arc::new(AtomicBool::new(false));
        let hook_flag = hook_cleared.clone();
        let mut mgr = ClientSlotManager::new(TEST_JOIN_TIMEOUT);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (thread, done_rx) = spawn_ignore_shutdown(Duration::from_secs(30));
        mgr.install_live(shutdown_tx, thread, done_rx);
        mgr.stop(|| {});
        assert!(!mgr.is_idle());
        assert!(!hook_cleared.load(Ordering::SeqCst));

        mgr.stop(|| hook_flag.store(true, Ordering::SeqCst));
        assert!(!mgr.is_idle());
        assert!(!hook_cleared.load(Ordering::SeqCst));
    }
}
