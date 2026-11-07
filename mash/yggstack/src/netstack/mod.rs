pub mod device;
pub mod frag;

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;

use smoltcp::iface::{Config as SmolConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{icmp, tcp, udp, Socket};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv6Address, Ipv6Cidr,
};
#[cfg(feature = "ckr")]
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use yggdrasil::ipv6rwc::ReadWriteCloser;

use self::device::YggDevice;
use self::frag::FragReassembler;

// ── Time helper ───────────────────────────────────────────────────────────────

fn smoltcp_now() -> SmolInstant {
    use std::time::{SystemTime, UNIX_EPOCH};
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;
    SmolInstant::from_micros(micros)
}

// ── Pending connect command ───────────────────────────────────────────────────

struct PendingConnect {
    handle: SocketHandle,
    remote: IpEndpoint,
    local_port: u16,
    result_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
}

// ── Listener state ────────────────────────────────────────────────────────────

/// Number of sockets kept in LISTEN state per listener. A smoltcp socket can
/// run only one TCP handshake at a time: while it sits in SYN-RECEIVED a
/// second SYN matches no listening socket and the interface answers RST,
/// which the dialing side sees as an instant "connection refused". A pool
/// lets concurrent handshakes proceed in parallel; every established socket
/// moves to the accept queue and is replaced with a fresh listener.
/// Cost: each socket preallocates 2×64 KiB buffers (1 MiB per listener).
const LISTEN_POOL: usize = 8;

/// Reap a listen-pool socket whose handshake never completed after this long.
const SYN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A dropped TcpStream closes with FIN and is reaped once the socket reaches
/// Closed. If the peer never answers the FIN the socket is removed after
/// this grace period instead of lingering in FIN-WAIT forever.
const CLOSE_GRACE: Duration = Duration::from_secs(60);

/// Tracks a listener's socket pool and its accept queue.
struct TcpListenerEntry {
    listen_ep: IpListenEndpoint,
    /// Pool of listening sockets. `syn_since` records when a socket left
    /// LISTEN state (SYN received) so stuck half-handshakes can be reaped.
    listen_pool: Vec<(SocketHandle, Option<SmolInstant>)>,
    /// Fully-established sockets waiting to be accepted.
    accept_queue: VecDeque<SocketHandle>,
    /// Wakers for tasks blocked on accept().
    accept_wakers: Vec<Waker>,
}

// ── Netstack shared state ─────────────────────────────────────────────────────

/// Lock the netstack state, tolerating a poisoned mutex — a panicking task
/// must not turn later teardown (Drop paths, shutdown) into a process abort.
fn lock_state(state: &Mutex<NetstackState>) -> std::sync::MutexGuard<'_, NetstackState> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

struct NetstackState {
    iface: Interface,
    device: YggDevice,
    sockets: SocketSet<'static>,
    /// All tasks that are waiting on any socket event.
    wakers: Vec<Waker>,
    /// Pending TCP connect commands.
    pending_connects: Vec<PendingConnect>,
    /// Active TCP listeners.
    listeners: Vec<TcpListenerEntry>,
    /// Sockets whose TcpStream was dropped: closed with FIN, removed once
    /// the close handshake completes (or CLOSE_GRACE passes).
    closing: Vec<(SocketHandle, SmolInstant)>,
    /// Set by YggNetstack::shutdown(): the poll loop exits and every
    /// in-flight socket operation fails instead of pending.
    closed: bool,
}

impl NetstackState {
    /// Return the number of milliseconds until the next mandatory poll.
    fn poll_delay_ms(&mut self) -> u64 {
        match self.iface.poll_delay(smoltcp_now(), &self.sockets) {
            Some(d) => d.total_millis().min(50),
            None => 50,
        }
    }

    /// Run one smoltcp poll cycle and return any outgoing raw IPv6 packets.
    /// Also services listeners and drains wakers (caller must fire them after
    /// releasing the lock).
    fn run_poll(&mut self) -> (Vec<Vec<u8>>, Vec<Waker>) {
        static POLL_COUNT: AtomicU64 = AtomicU64::new(0);
        let now = smoltcp_now();
        loop {
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            if self.device.rx_queue.is_empty() {
                break;
            }
        }
        self.service_listeners();
        self.reap_closing_sockets();
        let tx: Vec<Vec<u8>> = self.device.tx_queue.drain(..).collect();
        let wakers: Vec<Waker> = std::mem::take(&mut self.wakers);
        // Periodic stats: every 500 polls (~5 sec)
        if POLL_COUNT
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(500)
        {
            let mut tcp_count = 0u32;
            let mut udp_count = 0u32;
            for (_, socket) in self.sockets.iter() {
                match socket {
                    Socket::Tcp(_) => tcp_count += 1,
                    Socket::Udp(_) => udp_count += 1,
                    _ => {}
                }
            }
            // Read RSS from /proc/self/statm (pages, page_size=4096)
            let rss_mb = std::fs::read_to_string("/proc/self/statm")
                .ok()
                .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
                .map(|pages| pages * 4096 / 1024 / 1024)
                .unwrap_or(0);
            tracing::info!(
                "[b{}] netstack: rss={}MB tcp={} udp={} rx_q={} tx_q={} wakers={}",
                crate::BUILD_NUM,
                rss_mb,
                tcp_count,
                udp_count,
                self.device.rx_queue.len(),
                tx.len(),
                wakers.len(),
            );
        }
        (tx, wakers)
    }

    /// Process pending TCP connect commands (must be called before poll()).
    fn process_connects(&mut self) {
        let connects: Vec<PendingConnect> = std::mem::take(&mut self.pending_connects);
        for cmd in connects {
            let cx = self.iface.context();
            let socket = self.sockets.get_mut::<tcp::Socket>(cmd.handle);
            let result = socket
                .connect(cx, cmd.remote, cmd.local_port)
                .map_err(|e| format!("{:?}", e));
            let _ = cmd.result_tx.send(result);
        }
    }

    /// Create a new TCP socket with standard buffers.
    fn new_tcp_socket(&mut self) -> SocketHandle {
        let rx = tcp::SocketBuffer::new(vec![0u8; 65536]);
        let tx = tcp::SocketBuffer::new(vec![0u8; 65536]);
        self.sockets.add(tcp::Socket::new(rx, tx))
    }

    /// Create a new UDP socket with standard buffers.
    fn new_udp_socket(&mut self) -> SocketHandle {
        let rx_meta = vec![udp::PacketMetadata::EMPTY; 64];
        let tx_meta = vec![udp::PacketMetadata::EMPTY; 64];
        let rx_data = vec![0u8; 65536];
        let tx_data = vec![0u8; 65536];
        self.sockets.add(udp::Socket::new(
            udp::PacketBuffer::new(rx_meta, rx_data),
            udp::PacketBuffer::new(tx_meta, tx_data),
        ))
    }

    /// Service all listeners: move sockets whose handshake completed to the
    /// accept queue, reap half-handshakes stuck in SYN-RECEIVED, and keep the
    /// pool topped up so a concurrent SYN always finds a LISTEN socket.
    fn service_listeners(&mut self) {
        let now = smoltcp_now();
        for entry in &mut self.listeners {
            // Move established sockets to the accept queue.
            let mut queued = false;
            let mut i = 0;
            while i < entry.listen_pool.len() {
                let handle = entry.listen_pool[i].0;
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if socket.may_recv() && socket.may_send() {
                    tracing::debug!(
                        "listener {}: established -> accept queue",
                        entry.listen_ep.port
                    );
                    entry.listen_pool.swap_remove(i);
                    entry.accept_queue.push_back(handle);
                    queued = true;
                } else {
                    i += 1;
                }
            }
            if queued {
                // Wake tasks waiting for accept().
                for w in entry.accept_wakers.drain(..) {
                    w.wake();
                }
            }
            // Track and reap half-open handshakes: a SYN whose ACK never
            // arrives would otherwise hold its pool slot forever.
            let mut i = 0;
            while i < entry.listen_pool.len() {
                let handle = entry.listen_pool[i].0;
                let listening =
                    self.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Listen;
                if listening {
                    entry.listen_pool[i].1 = None;
                    i += 1;
                    continue;
                }
                match entry.listen_pool[i].1 {
                    None => {
                        entry.listen_pool[i].1 = Some(now);
                        i += 1;
                    }
                    Some(t) => {
                        if now - t > SYN_HANDSHAKE_TIMEOUT.into() {
                            tracing::debug!(
                                "listener {}: reaping stuck handshake",
                                entry.listen_ep.port
                            );
                            self.sockets.get_mut::<tcp::Socket>(handle).abort();
                            self.sockets.remove(handle);
                            entry.listen_pool.swap_remove(i);
                        } else {
                            i += 1;
                        }
                    }
                }
            }
            // Top the pool back up so LISTEN_POOL sockets are in LISTEN.
            let mut in_listen = entry
                .listen_pool
                .iter()
                .filter(|(_, since)| since.is_none())
                .count();
            while in_listen < LISTEN_POOL {
                entry
                    .listen_pool
                    .push((new_listen_socket(&mut self.sockets, entry.listen_ep), None));
                in_listen += 1;
            }
        }
    }

    /// Remove sockets queued for closing once their FIN handshake completes
    /// (State::Closed), or force-abort them after CLOSE_GRACE so a peer that
    /// never answers the FIN cannot leak sockets.
    fn reap_closing_sockets(&mut self) {
        let now = smoltcp_now();
        let mut i = 0;
        while i < self.closing.len() {
            let (handle, since) = self.closing[i];
            let done = self.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed;
            let expired = now - since > CLOSE_GRACE.into();
            if done || expired {
                if !done {
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                }
                self.sockets.remove(handle);
                self.closing.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }
}

// ── YggNetstack ───────────────────────────────────────────────────────────────

/// Maximum time to wait for a dialed TCP connection to become ESTABLISHED.
/// Matches the Go yggstack, which bounds every dial (forwards and SOCKS)
/// with a 10-second timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct YggNetstack {
    state: Arc<Mutex<NetstackState>>,
    /// Signal the poll loop to run immediately.
    poll_wakeup: Arc<Notify>,
    /// Background task handles, joined by [YggNetstack::shutdown].
    tasks: Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
    pub our_addr: Ipv6Addr,
    pub mtu: usize,
}

impl YggNetstack {
    /// Create a netstack backed by the given `ReadWriteCloser` and start
    /// background tasks.  `our_addr` is our Yggdrasil IPv6 address and `mtu`
    /// is the transport MTU (from `Core::mtu()`).
    pub fn new(
        rwc: Arc<ReadWriteCloser>,
        our_addr: Ipv6Addr,
        mtu: u64,
        #[cfg(feature = "ckr")] ckr_config: Option<&yggdrasil::config::TunnelRoutingConfig>,
    ) -> Arc<Self> {
        let mtu = (mtu as usize).min(65535);

        let mut device = YggDevice::new(mtu);

        // Configure smoltcp interface.
        let mut cfg = SmolConfig::new(HardwareAddress::Ip);
        cfg.random_seed = rand::random();

        let now = smoltcp_now();
        let mut iface = Interface::new(cfg, &mut device, now);

        // Assign our Yggdrasil address.
        let ip6 = Ipv6Address::from_bytes(&our_addr.octets());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::Ipv6(Ipv6Cidr::new(ip6, 128)));
        });

        // Default IPv6 route so smoltcp routes outgoing packets through our device.
        iface
            .routes_mut()
            .add_default_ipv6_route(ip6)
            .expect("failed to add default route");

        // CKR: if an IPv4 address is configured, assign it and add a default route.
        #[cfg(feature = "ckr")]
        if let Some(ckr) = ckr_config.filter(|c| c.enable && !c.ipv4_address.is_empty()) {
            if let Some((ip4, prefix)) = parse_ipv4_cidr(&ckr.ipv4_address) {
                iface.update_ip_addrs(|addrs| {
                    let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(ip4, prefix)));
                });
                iface
                    .routes_mut()
                    .add_default_ipv4_route(ip4)
                    .expect("failed to add default IPv4 route");
                tracing::info!("CKR: assigned IPv4 address {}", ckr.ipv4_address);
            } else {
                tracing::warn!("CKR: could not parse ipv4_address '{}'", ckr.ipv4_address);
            }
        }

        let state = Arc::new(Mutex::new(NetstackState {
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            wakers: Vec::new(),
            pending_connects: Vec::new(),
            listeners: Vec::new(),
            closing: Vec::new(),
            closed: false,
        }));

        let poll_wakeup = Arc::new(Notify::new());

        let ns = Arc::new(Self {
            state: state.clone(),
            poll_wakeup: poll_wakeup.clone(),
            tasks: Mutex::new(None),
            our_addr,
            mtu,
        });

        ns.spawn_tasks(rwc);
        ns
    }

    fn spawn_tasks(self: &Arc<Self>, rwc: Arc<ReadWriteCloser>) {
        // Task 1: continuously read from RWC → queue packets for smoltcp.
        let (pkt_tx, mut pkt_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
        let reader = {
            let rwc2 = rwc.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match rwc2.read(&mut buf).await {
                        Ok(data)
                            if !data.is_empty() && pkt_tx.send(data.to_vec()).await.is_err() =>
                        {
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            })
        };

        // Task 2: smoltcp poll loop.
        let state = self.state.clone();
        let poll_wakeup = self.poll_wakeup.clone();
        let mut frag_reassembler = FragReassembler::new();

        let poller = tokio::spawn(async move {
            loop {
                // Determine how long to sleep before the next forced poll.
                // Exit promptly once the netstack is shut down.
                let (closed, delay_ms) = {
                    let mut s = lock_state(&state);
                    (s.closed, s.poll_delay_ms())
                };
                if closed {
                    break;
                }

                // Wait for a new packet, the timeout, or an explicit wakeup.
                tokio::select! {
                    maybe = pkt_rx.recv() => {
                        match maybe {
                            Some(pkt) => {
                                if let Some(reassembled) = frag_reassembler.feed(pkt) {
                                    let mut s = lock_state(&state);
                                    s.device.rx_queue.push_back(reassembled);
                                }
                            }
                            None => break, // RWC reader task closed
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)) => {}
                    _ = poll_wakeup.notified() => {}
                }

                // Drain any additional packets that arrived concurrently.
                while let Ok(pkt) = pkt_rx.try_recv() {
                    if let Some(reassembled) = frag_reassembler.feed(pkt) {
                        let mut s = lock_state(&state);
                        s.device.rx_queue.push_back(reassembled);
                    }
                }

                // Run smoltcp, collect outgoing packets and wakers.
                let (tx_pkts, wakers) = {
                    let mut s = lock_state(&state);
                    s.process_connects();
                    s.run_poll()
                };

                // Fire wakers outside the lock.
                for w in wakers {
                    w.wake();
                }

                // Send outgoing packets to Yggdrasil (outside lock).
                for pkt in tx_pkts {
                    let _ = rwc.write(&pkt).await;
                }
            }
        });

        *self.tasks.lock().unwrap_or_else(|e| e.into_inner()) = Some(vec![reader, poller]);
    }

    /// Shut the netstack down: every in-flight socket operation fails, dial
    /// stragglers are released instead of living out their connect timeout,
    /// and the background tasks are joined. Idempotent; called from engine
    /// stop() so nothing from an old engine generation keeps running.
    pub async fn shutdown(&self) {
        let wakers = {
            let mut s = lock_state(&self.state);
            s.closed = true;
            // Fail queued connect commands: dropping the senders breaks the
            // dialers' oneshot channels.
            s.pending_connects.clear();
            // Wake everything blocked on a socket event so blocked reads,
            // writes and accepts re-poll instead of pending forever.
            let mut wakers: Vec<Waker> = std::mem::take(&mut s.wakers);
            for entry in &mut s.listeners {
                wakers.append(&mut entry.accept_wakers);
            }
            // Abort every TCP socket: pending wait_connected()/poll_read see
            // the Closed state and return an error.
            let tcp_handles: Vec<SocketHandle> = s
                .sockets
                .iter()
                .filter(|(_, sock)| matches!(sock, Socket::Tcp(_)))
                .map(|(h, _)| h)
                .collect();
            for h in tcp_handles {
                s.sockets.get_mut::<tcp::Socket>(h).abort();
            }
            s.listeners.clear();
            s.closing.clear();
            wakers
        };
        for w in wakers {
            w.wake();
        }
        self.poll_wakeup.notify_one();

        let tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(tasks) = tasks {
            for mut task in tasks {
                join_with_grace(&mut task).await;
            }
        }
    }

    // ── Public dial / listen API ──────────────────────────────────────────────

    /// Dial a TCP connection to a remote address.
    /// For Yggdrasil-only builds accepts IPv6 only; with the `ckr` feature
    /// also accepts IPv4 (routed via Crypto-Key Routing).
    pub async fn dial_tcp(&self, remote: SocketAddr) -> io::Result<TcpStream> {
        let remote_ep = match remote {
            SocketAddr::V6(a) => {
                let ip6 = Ipv6Address::from_bytes(&a.ip().octets());
                IpEndpoint::new(IpAddress::Ipv6(ip6), a.port())
            }
            #[cfg(feature = "ckr")]
            SocketAddr::V4(a) => {
                let ip4 = Ipv4Address::from_bytes(&a.ip().octets());
                IpEndpoint::new(IpAddress::Ipv4(ip4), a.port())
            }
            #[cfg(not(feature = "ckr"))]
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected IPv6 address",
                ))
            }
        };

        // Pick a random local ephemeral port.
        let local_port: u16 = rand::random::<u16>() % 16384 + 49152;

        // Create TCP socket.
        let handle = {
            let mut s = lock_state(&self.state);
            s.new_tcp_socket()
        };

        // Queue the connect command for the poll loop.
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        {
            let mut s = lock_state(&self.state);
            s.pending_connects.push(PendingConnect {
                handle,
                remote: remote_ep,
                local_port,
                result_tx,
            });
        }
        self.poll_wakeup.notify_one();

        // Wait for the connect() call to be processed.
        result_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "netstack closed"))?
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;

        // Wait for ESTABLISHED state.
        let stream = TcpStream {
            handle,
            state: self.state.clone(),
            poll_wakeup: self.poll_wakeup.clone(),
        };

        // Bound the handshake wait: with no working overlay route (e.g.
        // right after a node restart, before the first peer link is up) the
        // SYN would be retransmitted forever and callers would pile up
        // instead of failing fast and retrying once links are healthy.
        // Dropping the stream on timeout aborts and removes the socket.
        match tokio::time::timeout(CONNECT_TIMEOUT, stream.wait_connected()).await {
            Ok(result) => result.map(|_| stream),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "netstack connect timed out",
            )),
        }
    }

    /// Dial a generic connection (network can be "tcp", "tcp6").
    pub async fn dial_context(&self, network: &str, address: &str) -> io::Result<TcpStream> {
        let addr: SocketAddr = address
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{}", e)))?;
        match network {
            "tcp" | "tcp6" => self.dial_tcp(addr).await,
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported network {}", network),
            )),
        }
    }

    /// Start a TCP listener on the given Yggdrasil address/port.
    pub fn listen_tcp(&self, port: u16) -> io::Result<TcpListener> {
        let ip6 = Ipv6Address::from_bytes(&self.our_addr.octets());
        let listen_ep = IpListenEndpoint {
            addr: Some(IpAddress::Ipv6(ip6)),
            port,
        };

        {
            let mut s = lock_state(&self.state);
            // Validate the endpoint on the first socket so listen() errors
            // surface as before, then fill out the pool.
            let first = s.new_tcp_socket();
            s.sockets
                .get_mut::<tcp::Socket>(first)
                .listen(listen_ep)
                .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, format!("{:?}", e)))?;
            let mut listen_pool = vec![(first, None)];
            for _ in 1..LISTEN_POOL {
                listen_pool.push((new_listen_socket(&mut s.sockets, listen_ep), None));
            }
            s.listeners.push(TcpListenerEntry {
                listen_ep,
                listen_pool,
                accept_queue: VecDeque::new(),
                accept_wakers: Vec::new(),
            });
        }

        Ok(TcpListener {
            port,
            state: self.state.clone(),
            poll_wakeup: self.poll_wakeup.clone(),
        })
    }

    /// Bind a UDP socket on the given Yggdrasil address/port.
    pub fn bind_udp(&self, port: u16) -> io::Result<UdpSocket> {
        let ip6 = Ipv6Address::from_bytes(&self.our_addr.octets());
        let listen_ep = IpListenEndpoint {
            addr: Some(IpAddress::Ipv6(ip6)),
            port,
        };

        let handle = {
            let mut s = lock_state(&self.state);
            let h = s.new_udp_socket();
            s.sockets
                .get_mut::<udp::Socket>(h)
                .bind(listen_ep)
                .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, format!("{:?}", e)))?;
            h
        };

        Ok(UdpSocket {
            handle,
            state: self.state.clone(),
            poll_wakeup: self.poll_wakeup.clone(),
        })
    }

    /// Create a UDP socket bound to an ephemeral local port, suitable for
    /// sending to a remote Yggdrasil address and receiving replies.
    pub fn open_udp(&self) -> io::Result<UdpSocket> {
        let handle = {
            let mut s = lock_state(&self.state);
            let h = s.new_udp_socket();
            // smoltcp requires a socket to be bound before it can send; pick a
            // random ephemeral local port (bind addr = None means any interface).
            let local_port: u16 = rand::random::<u16>() % 16384 + 49152;
            let listen_ep = IpListenEndpoint {
                addr: None,
                port: local_port,
            };
            s.sockets
                .get_mut::<udp::Socket>(h)
                .bind(listen_ep)
                .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, format!("{:?}", e)))?;
            h
        };
        Ok(UdpSocket {
            handle,
            state: self.state.clone(),
            poll_wakeup: self.poll_wakeup.clone(),
        })
    }

    /// Open an ICMPv6 echo socket bound to a random identifier, suitable
    /// for pinging remote Yggdrasil addresses. Replies are matched to the
    /// bound identifier by smoltcp's ICMP socket layer.
    pub fn open_icmp(&self) -> io::Result<PingSocket> {
        let ident: u16 = rand::random();
        let handle = {
            let mut s = lock_state(&self.state);
            let rx_meta = vec![icmp::PacketMetadata::EMPTY; 8];
            let tx_meta = vec![icmp::PacketMetadata::EMPTY; 8];
            let rx_data = vec![0u8; 2048];
            let tx_data = vec![0u8; 2048];
            let h = s.sockets.add(icmp::Socket::new(
                icmp::PacketBuffer::new(rx_meta, rx_data),
                icmp::PacketBuffer::new(tx_meta, tx_data),
            ));
            s.sockets
                .get_mut::<icmp::Socket>(h)
                .bind(icmp::Endpoint::Ident(ident))
                .map_err(|e| io::Error::new(io::ErrorKind::AddrInUse, format!("{:?}", e)))?;
            h
        };
        self.poll_wakeup.notify_one();
        Ok(PingSocket {
            handle,
            ident,
            our_addr: self.our_addr,
            state: self.state.clone(),
            poll_wakeup: self.poll_wakeup.clone(),
        })
    }
}

// ── TcpStream ─────────────────────────────────────────────────────────────────

pub struct TcpStream {
    handle: SocketHandle,
    state: Arc<Mutex<NetstackState>>,
    poll_wakeup: Arc<Notify>,
}

impl TcpStream {
    /// Wait until the socket reaches ESTABLISHED state.
    async fn wait_connected(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut s = lock_state(&self.state);
            let sock = s.sockets.get::<tcp::Socket>(self.handle);
            match sock.state() {
                tcp::State::Established => Poll::Ready(Ok(())),
                tcp::State::Closed | tcp::State::TimeWait | tcp::State::CloseWait => {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "connection refused",
                    )))
                }
                _ => {
                    s.wakers.push(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        {
            let mut s = lock_state(&self.state);
            let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
            let state = sock.state();
            // close() sends FIN after any queued data. abort() would send an
            // RST that destroys data still in flight to the receiver —
            // observed as intermittent empty responses under load, because
            // relays drop their stream the moment one direction finishes and
            // the RST could overtake the last data packets.
            sock.close();
            s.closing.push((self.handle, smoltcp_now()));
            tracing::debug!("TcpStream dropped (state={:?}), queued for close", state);
        }
        self.poll_wakeup.notify_one();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut s = lock_state(&self.state);
        let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);

        if sock.can_recv() {
            let filled = buf.initialize_unfilled();
            match sock.recv_slice(filled) {
                Ok(0) => {}
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("{:?}", e),
                    )))
                }
            }
        }

        if !sock.may_recv() {
            tracing::debug!("tcp read EOF: state={:?}", sock.state());
            return Poll::Ready(Ok(())); // EOF — covers all closing/closed states
        }

        s.wakers.push(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut s = lock_state(&self.state);
        let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);

        if !sock.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "socket closed",
            )));
        }

        if sock.can_send() {
            match sock.send_slice(data) {
                Ok(n) => {
                    drop(s);
                    self.poll_wakeup.notify_one();
                    return Poll::Ready(Ok(n));
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("{:?}", e),
                    )))
                }
            }
        }

        s.wakers.push(cx.waker().clone());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_wakeup.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut s = lock_state(&self.state);
        s.sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(s);
        self.poll_wakeup.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ── TcpListener ───────────────────────────────────────────────────────────────

pub struct TcpListener {
    port: u16,
    state: Arc<Mutex<NetstackState>>,
    poll_wakeup: Arc<Notify>,
}

impl TcpListener {
    pub async fn accept(&self) -> io::Result<TcpStream> {
        let port = self.port;
        let state = self.state.clone();
        let poll_wakeup = self.poll_wakeup.clone();
        std::future::poll_fn(move |cx| {
            let mut s = lock_state(&state);
            let idx = s.listeners.iter().position(|e| e.listen_ep.port == port);
            if let Some(i) = idx {
                if let Some(handle) = s.listeners[i].accept_queue.pop_front() {
                    return Poll::Ready(Ok(TcpStream {
                        handle,
                        state: state.clone(),
                        poll_wakeup: poll_wakeup.clone(),
                    }));
                }
                // Register waker so service_listeners() can wake us.
                s.listeners[i].accept_wakers.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }
}

// ── UdpSocket ─────────────────────────────────────────────────────────────────

pub struct UdpSocket {
    handle: SocketHandle,
    state: Arc<Mutex<NetstackState>>,
    poll_wakeup: Arc<Notify>,
}

impl UdpSocket {
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::poll_fn(|cx| {
            let mut s = lock_state(&self.state);
            let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
            if sock.can_recv() {
                return Poll::Ready(match sock.recv_slice(buf) {
                    Ok((n, meta)) => {
                        let addr = match meta.endpoint.addr {
                            IpAddress::Ipv6(a) => {
                                let octets: [u8; 16] = a.as_bytes().try_into().unwrap();
                                SocketAddr::V6(SocketAddrV6::new(
                                    Ipv6Addr::from(octets),
                                    meta.endpoint.port,
                                    0,
                                    0,
                                ))
                            }
                            _ => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "non-IPv6 source",
                                )))
                            }
                        };
                        Ok((n, addr))
                    }
                    Err(e) => Err(io::Error::other(format!("{:?}", e))),
                });
            }
            // Register waker so we're woken after the next smoltcp poll.
            s.wakers.push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target_ip = match target {
            SocketAddr::V6(a) => Ipv6Address::from_bytes(&a.ip().octets()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected IPv6 address",
                ))
            }
        };
        let endpoint = IpEndpoint::new(IpAddress::Ipv6(target_ip), target.port());

        std::future::poll_fn(|cx| {
            let mut s = lock_state(&self.state);
            let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
            if sock.can_send() {
                return Poll::Ready(match sock.send_slice(buf, endpoint) {
                    Ok(()) => {
                        drop(s);
                        self.poll_wakeup.notify_one();
                        Ok(buf.len())
                    }
                    Err(e) => Err(io::Error::other(format!("{:?}", e))),
                });
            }
            s.wakers.push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        lock_state(&self.state).sockets.remove(self.handle);
    }
}

// ── PingSocket ────────────────────────────────────────────────────────────────

/// ICMPv6 echo socket over the netstack. Sends echo requests to arbitrary
/// Yggdrasil addresses and receives the matching echo replies (matched by
/// the bound identifier), mirroring [UdpSocket]'s lock/wake pattern.
pub struct PingSocket {
    handle: SocketHandle,
    /// The identifier bound into every request/reply of this socket.
    pub ident: u16,
    our_addr: Ipv6Addr,
    state: Arc<Mutex<NetstackState>>,
    poll_wakeup: Arc<Notify>,
}

impl PingSocket {
    /// Queue one echo request with the given sequence number and payload.
    /// The packet is built with smoltcp's wire types; checksums are computed
    /// on dispatch by the interface.
    pub async fn send_echo(&self, dst: Ipv6Addr, seq: u16, payload: &[u8]) -> io::Result<()> {
        let repr = smoltcp::wire::Icmpv6Repr::EchoRequest {
            ident: self.ident,
            seq_no: seq,
            data: payload,
        };
        let mut packet = vec![0u8; repr.buffer_len()];
        repr.emit(
            &IpAddress::Ipv6(Ipv6Address::from_bytes(&self.our_addr.octets())),
            &IpAddress::Ipv6(Ipv6Address::from_bytes(&dst.octets())),
            &mut smoltcp::wire::Icmpv6Packet::new_unchecked(&mut packet),
            &ChecksumCapabilities::ignored(),
        );

        std::future::poll_fn(|cx| {
            let mut s = lock_state(&self.state);
            if s.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "netstack closed",
                )));
            }
            let sock = s.sockets.get_mut::<icmp::Socket>(self.handle);
            if sock.can_send() {
                return Poll::Ready(
                    match sock.send_slice(
                        &packet,
                        IpAddress::Ipv6(Ipv6Address::from_bytes(&dst.octets())),
                    ) {
                        Ok(()) => {
                            drop(s);
                            self.poll_wakeup.notify_one();
                            Ok(())
                        }
                        Err(e) => Err(io::Error::other(format!("{:?}", e))),
                    },
                );
            }
            s.wakers.push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Wait for the next queued echo reply. Returns the reply's sequence
    /// number and source address; replies for other sequence numbers can
    /// arrive late and must be drained by the caller.
    pub async fn recv_reply(&self, buf: &mut [u8]) -> io::Result<(u16, Ipv6Addr)> {
        let (n, src) = std::future::poll_fn(|cx| {
            let mut s = lock_state(&self.state);
            if s.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "netstack closed",
                )));
            }
            let sock = s.sockets.get_mut::<icmp::Socket>(self.handle);
            if sock.can_recv() {
                return Poll::Ready(match sock.recv_slice(buf) {
                    Ok((n, src)) => Ok((n, src)),
                    Err(e) => Err(io::Error::other(format!("{:?}", e))),
                });
            }
            s.wakers.push(cx.waker().clone());
            Poll::Pending
        })
        .await?;

        let src_ip = match src {
            IpAddress::Ipv6(a) => {
                let octets: [u8; 16] = a.as_bytes().try_into().unwrap();
                Ipv6Addr::from(octets)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-IPv6 echo reply",
                ))
            }
        };
        let packet = smoltcp::wire::Icmpv6Packet::new_unchecked(&buf[..n]);
        let seq = packet.echo_seq_no();
        Ok((seq, src_ip))
    }
}

impl Drop for PingSocket {
    fn drop(&mut self) {
        lock_state(&self.state).sockets.remove(self.handle);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Wait for a background task to finish with a grace period, then abort it.
async fn join_with_grace(handle: &mut tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(Duration::from_secs(2), &mut *handle)
        .await
        .is_err()
    {
        handle.abort();
        let _ = handle.await;
    }
}

/// Create a socket in LISTEN state on the given endpoint.
fn new_listen_socket(sockets: &mut SocketSet, ep: IpListenEndpoint) -> SocketHandle {
    let rx = tcp::SocketBuffer::new(vec![0u8; 65536]);
    let tx = tcp::SocketBuffer::new(vec![0u8; 65536]);
    let mut sock = tcp::Socket::new(rx, tx);
    let _ = sock.listen(ep);
    sockets.add(sock)
}

/// Parse an IPv4 CIDR string like "10.99.0.1/24" into a smoltcp address +
/// prefix length.  Returns `None` on any parse error.
#[cfg(feature = "ckr")]
fn parse_ipv4_cidr(cidr: &str) -> Option<(Ipv4Address, u8)> {
    let (addr_str, prefix_str) = cidr.split_once('/')?;
    let addr: std::net::Ipv4Addr = addr_str.trim().parse().ok()?;
    let prefix: u8 = prefix_str.trim().parse().ok()?;
    Some((Ipv4Address::from_bytes(&addr.octets()), prefix))
}
