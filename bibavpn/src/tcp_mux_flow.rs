//! Optional byte-credit extension and bounded, independent duplex stream pumps.
use super::*;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Mutex as StdMutex;

use anyhow::{bail, Context};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use crate::frame::AdaptivePadState;
use crate::retry::{maybe_server_ack_and_rtt_mask, maybe_ws_send_jitter, ws_ping_period_duration};
use crate::{read_padded_frame_into, write_padded_frame_with_mode_state};

const OPEN_CREDIT: u8 = 0x20;
const MAX_STREAMS: usize = 256;
// Reserve before OPEN, without allocating the bytes: admitted windows cannot overcommit memory.
const RECEIVE_BUDGET: usize = 64 * 1024 * 1024;
const OUTPUT_BUDGET: usize = 8 * 1024 * 1024;
const MAX_QUEUED_RECORDS: usize = 8192;
const NEGOTIATION_WAIT: Duration = Duration::from_millis(300);
const MAX_PEER_WINDOW: u32 = 16 * 1024 * 1024;
const CAP_MAGIC: &[u8; 4] = b"BFC1";

fn capability(kind: u8) -> Vec<u8> {
    let mut bytes = CAP_MAGIC.to_vec();
    bytes.push(kind);
    bytes.extend_from_slice(&MUX_INITIAL_WINDOW.to_be_bytes());
    bytes
}

fn parse_capability(payload: &[u8], kind: u8) -> Option<u32> {
    if payload.len() != 9 || &payload[..4] != CAP_MAGIC || payload[4] != kind {
        return None;
    }
    let window = u32::from_be_bytes(payload[5..9].try_into().ok()?);
    (window > 0 && window <= MAX_PEER_WINDOW).then_some(window)
}

#[derive(Clone, Copy)]
enum Negotiation {
    Pending,
    Legacy,
    Credit(u32),
}

struct ReceiveState {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    credit: u32,
    fin: bool,
}

struct Flow {
    epoch: u64,
    negotiated: bool,
    send_limit: u32,
    send_available: StdMutex<u32>,
    send_ready: Notify,
    receive: StdMutex<ReceiveState>,
    receive_ready: Notify,
    cancelled: watch::Sender<bool>,
    output_valid: AtomicBool,
    // Held through pending connect, both pumps, and any outstanding output records.
    _reservation: OwnedSemaphorePermit,
}

impl Flow {
    fn new(epoch: u64, peer_window: Option<u32>, reservation: OwnedSemaphorePermit) -> Arc<Self> {
        let limit = peer_window.unwrap_or(0);
        Arc::new(Self {
            epoch,
            negotiated: peer_window.is_some(),
            send_limit: limit,
            send_available: StdMutex::new(limit),
            send_ready: Notify::new(),
            receive: StdMutex::new(ReceiveState {
                queue: VecDeque::new(),
                bytes: 0,
                credit: MUX_INITIAL_WINDOW,
                fin: false,
            }),
            receive_ready: Notify::new(),
            cancelled: watch::channel(false).0,
            output_valid: AtomicBool::new(true),
            _reservation: reservation,
        })
    }

    fn cancel(&self, preserve_output: bool) {
        if !preserve_output {
            self.output_valid.store(false, Ordering::Release);
        }
        self.cancelled.send_replace(true);
        let mut state = self.receive.lock().unwrap();
        state.queue.clear();
    }

    fn enqueue(&self, payload: Vec<u8>, fin: bool) -> anyhow::Result<()> {
        let mut state = self.receive.lock().unwrap();
        if state.fin || *self.cancelled.borrow() {
            bail!("DATA after stream FIN/reset");
        }
        if !payload.is_empty() {
            if payload.len() > state.credit as usize
                || state.bytes.saturating_add(payload.len()) > MUX_INITIAL_WINDOW as usize
                || state.queue.len() >= MAX_QUEUED_RECORDS
            {
                bail!("mux receive window exceeded");
            }
            state.credit -= payload.len() as u32;
            state.bytes += payload.len();
            state.queue.push_back(payload);
        }
        state.fin = fin;
        drop(state);
        self.receive_ready.notify_one();
        Ok(())
    }

    async fn receive(&self) -> Option<Vec<u8>> {
        loop {
            let ready = self.receive_ready.notified();
            {
                let mut state = self.receive.lock().unwrap();
                if let Some(data) = state.queue.pop_front() {
                    // Count bytes until write_all completes, not merely until dequeued.
                    return Some(data);
                }
                if state.fin {
                    return None;
                }
            }
            ready.await;
        }
    }

    fn consumed(&self, bytes: usize) {
        let mut state = self.receive.lock().unwrap();
        state.bytes -= bytes;
        if !self.negotiated {
            state.credit += bytes as u32;
        }
    }

    fn add_credit(&self, payload: &[u8]) -> anyhow::Result<()> {
        if !self.negotiated {
            return Ok(());
        }
        if payload.len() != 4 {
            bail!("malformed mux credit");
        }
        let amount = u32::from_be_bytes(payload.try_into().unwrap());
        let mut available = self.send_available.lock().unwrap();
        if amount == 0 || amount > self.send_limit - *available {
            bail!("invalid mux credit increment");
        }
        *available += amount;
        drop(available);
        self.send_ready.notify_one();
        Ok(())
    }

    async fn take_credit(&self, requested: usize) -> usize {
        if !self.negotiated {
            return requested;
        }
        loop {
            let ready = self.send_ready.notified();
            {
                let mut available = self.send_available.lock().unwrap();
                if *available > 0 {
                    let amount = requested.min(*available as usize);
                    *available -= amount as u32;
                    return amount;
                }
            }
            ready.await;
        }
    }
}

struct Record {
    sid: u32,
    flags: u8,
    payload: Vec<u8>,
    flow: Option<Arc<Flow>>,
    _bytes: Option<OwnedSemaphorePermit>,
}

enum Output {
    Record(Record),
    Pong(Bytes),
}

pub(super) struct Endpoint {
    client: bool,
    cfg: MuxClientConfig,
    timing: ServerWsOutTiming,
    streams: StdMutex<HashMap<u32, Arc<Flow>>>,
    receive_budget: Arc<Semaphore>,
    output_budget: Arc<Semaphore>,
    output: mpsc::Sender<Output>,
    control: mpsc::Sender<Output>,
    output_rx: StdMutex<Option<mpsc::Receiver<Output>>>,
    control_rx: StdMutex<Option<mpsc::Receiver<Output>>>,
    next_sid: AtomicU32,
    next_epoch: AtomicU64,
    closed: AtomicBool,
    negotiation: watch::Sender<Negotiation>,
    negotiation_deadline: Instant,
    session_stop: watch::Sender<bool>,
}

struct SessionGuard<'a>(&'a Endpoint);

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

impl Endpoint {
    pub(super) fn new(client: bool, cfg: MuxClientConfig, timing: ServerWsOutTiming) -> Arc<Self> {
        let (output, output_rx) = mpsc::channel(512);
        let (control, control_rx) = mpsc::channel(512);
        Arc::new(Self {
            client,
            cfg,
            timing,
            streams: StdMutex::new(HashMap::new()),
            receive_budget: Arc::new(Semaphore::new(RECEIVE_BUDGET)),
            output_budget: Arc::new(Semaphore::new(OUTPUT_BUDGET)),
            output,
            control,
            output_rx: StdMutex::new(Some(output_rx)),
            control_rx: StdMutex::new(Some(control_rx)),
            next_sid: AtomicU32::new(1),
            next_epoch: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            negotiation: watch::channel(Negotiation::Pending).0,
            negotiation_deadline: Instant::now() + NEGOTIATION_WAIT,
            session_stop: watch::channel(false).0,
        })
    }

    fn allocate(&self, sid: u32, peer_window: Option<u32>) -> anyhow::Result<Arc<Flow>> {
        let mut streams = self.streams.lock().unwrap();
        if sid == 0 || self.closed.load(Ordering::Acquire) || streams.contains_key(&sid) {
            bail!("mux stream unavailable");
        }
        if streams.len() >= MAX_STREAMS {
            bail!("mux stream limit");
        }
        let reservation = self
            .receive_budget
            .clone()
            .try_acquire_many_owned(MUX_INITIAL_WINDOW)
            .context("mux session receive budget exhausted")?;
        let flow = Flow::new(
            self.next_epoch.fetch_add(1, Ordering::Relaxed),
            peer_window,
            reservation,
        );
        streams.insert(sid, flow.clone());
        Ok(flow)
    }

    fn get(&self, sid: u32) -> Option<Arc<Flow>> {
        self.streams.lock().unwrap().get(&sid).cloned()
    }

    fn remove(&self, sid: u32, epoch: u64) -> bool {
        self.finish(sid, epoch, false)
    }

    fn finish(&self, sid: u32, epoch: u64, preserve_output: bool) -> bool {
        let mut streams = self.streams.lock().unwrap();
        if streams.get(&sid).is_some_and(|flow| flow.epoch == epoch) {
            let flow = streams.remove(&sid).unwrap();
            flow.cancel(preserve_output);
            true
        } else {
            false
        }
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.session_stop.send_replace(true);
        self.output_budget.close();
        let mut streams = self.streams.lock().unwrap();
        for (_, flow) in streams.drain() {
            flow.cancel(false);
        }
        self.negotiation.send_if_modified(|state| {
            if matches!(state, Negotiation::Pending) {
                *state = Negotiation::Legacy;
                true
            } else {
                false
            }
        });
    }

    fn control(
        &self,
        sid: u32,
        flags: u8,
        payload: Vec<u8>,
        flow: Option<Arc<Flow>>,
    ) -> anyhow::Result<()> {
        // Never wait on the shared reader. Saturated control output terminates the session.
        self.control
            .try_send(Output::Record(Record {
                sid,
                flags,
                payload,
                flow,
                _bytes: None,
            }))
            .map_err(|_| anyhow::anyhow!("mux control queue exhausted or closed"))
    }

    async fn send(
        &self,
        sid: u32,
        flags: u8,
        payload: Vec<u8>,
        flow: Arc<Flow>,
    ) -> anyhow::Result<()> {
        let bytes = self
            .output_budget
            .clone()
            .acquire_many_owned((payload.len() + 9) as u32)
            .await?;
        self.output
            .send(Output::Record(Record {
                sid,
                flags,
                payload,
                flow: Some(flow),
                _bytes: Some(bytes),
            }))
            .await
            .map_err(|_| anyhow::Error::new(MuxWriterStopped))
    }

    async fn peer_window(&self) -> Option<u32> {
        let mut state = self.negotiation.subscribe();
        loop {
            match *state.borrow_and_update() {
                Negotiation::Credit(window) => return Some(window),
                Negotiation::Legacy => return None,
                Negotiation::Pending => {}
            }
            tokio::select! {
                _ = state.changed() => {},
                _ = tokio::time::sleep_until(self.negotiation_deadline) => {
                    self.negotiation.send_if_modified(|value| {
                        if matches!(value, Negotiation::Pending) {
                            *value = Negotiation::Legacy; true
                        } else { false }
                    });
                }
            }
        }
    }

    pub(super) async fn open_stream(
        self: &Arc<Self>,
        local: TcpStream,
        host: String,
        port: u16,
        prefix: Vec<u8>,
    ) -> Result<(), MuxOpenStreamDropped> {
        let window = self.peer_window().await;
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let prepare = || -> anyhow::Result<_> {
            if prefix.len() > MUX_INITIAL_WINDOW as usize {
                bail!("mux uplink prefix too large");
            }
            let payload = encode_mux_open_target(&host, port)?;
            let flow = self.allocate(sid, window)?;
            Ok((payload, flow))
        };
        let (payload, flow) = match prepare() {
            Ok(value) => value,
            Err(err) => return Err(MuxOpenStreamDropped { local, err }),
        };
        let flags = MUX_FLAG_OPEN | if window.is_some() { OPEN_CREDIT } else { 0 };
        if let Err(err) = self.send(sid, flags, payload, flow.clone()).await {
            self.remove(sid, flow.epoch);
            return Err(MuxOpenStreamDropped { local, err });
        }
        let endpoint = self.clone();
        tokio::spawn(async move {
            endpoint.bridge(local, sid, flow, prefix).await;
        });
        Ok(())
    }

    async fn bridge<S>(self: &Arc<Self>, socket: S, sid: u32, flow: Arc<Flow>, prefix: Vec<u8>)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (mut read, mut write) = tokio::io::split(socket);
        let max_chunk = crate::frame::max_tcp_payload_per_ws_message(
            self.cfg.transport_v2,
            self.cfg.decoy_max,
            self.cfg.max_pad,
            self.cfg.max_ws_binary,
        )
        .saturating_sub(9)
        .clamp(1, 64 * 1024);
        let mut cancelled = flow.cancelled.subscribe();
        let uplink = async {
            let mut buffer = vec![0; max_chunk];
            let mut prefix = std::io::Cursor::new(prefix);
            loop {
                // Read independently of a blocked local write; at most one chunk buffered per stream.
                let n = if prefix.position() < prefix.get_ref().len() as u64 {
                    let n = std::io::Read::read(&mut prefix, &mut buffer)?;
                    if prefix.position() == prefix.get_ref().len() as u64 {
                        prefix = std::io::Cursor::new(Vec::new());
                    }
                    n
                } else {
                    read.read(&mut buffer).await?
                };
                if n == 0 {
                    self.send(sid, MUX_FLAG_CLOSE, Vec::new(), flow.clone())
                        .await?;
                    return Ok::<_, anyhow::Error>(());
                }
                let mut offset = 0;
                while offset < n {
                    let take = flow.take_credit(n - offset).await;
                    self.send(
                        sid,
                        MUX_FLAG_DATA,
                        buffer[offset..offset + take].to_vec(),
                        flow.clone(),
                    )
                    .await?;
                    offset += take;
                }
            }
        };
        let downlink = async {
            let mut pending_credit = 0u32;
            while let Some(data) = flow.receive().await {
                write.write_all(&data).await?;
                let len = data.len();
                drop(data);
                flow.consumed(len);
                if flow.negotiated {
                    pending_credit += len as u32;
                    let empty = flow.receive.lock().unwrap().queue.is_empty();
                    if pending_credit >= MUX_INITIAL_WINDOW / 8 || empty {
                        self.control(
                            sid,
                            MUX_FLAG_WIN,
                            pending_credit.to_be_bytes().to_vec(),
                            Some(flow.clone()),
                        )?;
                        flow.receive.lock().unwrap().credit += pending_credit;
                        pending_credit = 0;
                    }
                }
            }
            write.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let result = tokio::select! {
            result = async {
                // Negotiated CLOSE is directional FIN; legacy CLOSE still closes both halves.
                if flow.negotiated {
                    tokio::try_join!(uplink, downlink).map(|_| ())
                } else {
                    tokio::select! { result = uplink => result, result = downlink => result }
                }
            } => result,
            _ = cancelled.wait_for(|closed| *closed) => Ok(()),
        };
        if self.finish(sid, flow.epoch, result.is_ok()) && result.is_err() {
            tracing::debug!(target: "bibavpn_mux", stream_id = sid, "mux stream I/O failed: {result:?}");
            if self.control(sid, MUX_FLAG_RST, Vec::new(), None).is_err() {
                self.shutdown();
            }
        }
    }

    async fn dispatch(
        self: &Arc<Self>,
        sid: u32,
        flags: u8,
        payload: Vec<u8>,
        connect_timeout: Duration,
    ) -> anyhow::Result<()> {
        if flags == MUX_FLAG_WIN && sid == 0 {
            if self.client {
                if let Some(window) = parse_capability(&payload, 2) {
                    self.negotiation.send_if_modified(|state| {
                        if matches!(state, Negotiation::Pending) {
                            *state = Negotiation::Credit(window);
                            true
                        } else {
                            false
                        }
                    });
                }
            } else if let Some(window) = parse_capability(&payload, 1) {
                self.negotiation.send_replace(Negotiation::Credit(window));
                self.control(0, MUX_FLAG_WIN, capability(2), None)?;
            }
            return Ok(());
        }
        if flags & MUX_FLAG_OPEN != 0 && !self.client {
            let window = if flags & OPEN_CREDIT != 0 {
                match *self.negotiation.borrow() {
                    Negotiation::Credit(window) => Some(window),
                    _ => {
                        self.control(sid, MUX_FLAG_RST, Vec::new(), None)?;
                        return Ok(());
                    }
                }
            } else {
                None
            };
            let target = decode_mux_open_target(&payload);
            let flow = if target.is_ok() {
                self.allocate(sid, window)
            } else {
                Err(anyhow::anyhow!("invalid target"))
            };
            let flow = match flow {
                Ok(flow) => flow,
                Err(_) => {
                    self.control(sid, MUX_FLAG_RST, Vec::new(), None)?;
                    return Ok(());
                }
            };
            let (host, port) = target.unwrap();
            let endpoint = self.clone();
            tokio::spawn(async move {
                let mut cancelled = flow.cancelled.subscribe();
                let connect = tokio::select! {
                    result = tokio::time::timeout(connect_timeout, TcpStream::connect((host.as_str(), port))) => result,
                    _ = cancelled.wait_for(|closed| *closed) => return,
                };
                match connect {
                    Ok(Ok(socket)) => {
                        let _ = socket.set_nodelay(true);
                        endpoint.bridge(socket, sid, flow, Vec::new()).await;
                    }
                    _ => {
                        if endpoint.remove(sid, flow.epoch)
                            && endpoint
                                .control(sid, MUX_FLAG_RST, Vec::new(), None)
                                .is_err()
                        {
                            endpoint.shutdown();
                        }
                    }
                }
            });
            return Ok(());
        }
        const KNOWN: u8 = MUX_FLAG_OPEN
            | MUX_FLAG_DATA
            | MUX_FLAG_CLOSE
            | MUX_FLAG_RST
            | MUX_FLAG_WIN
            | OPEN_CREDIT;
        static FLAGS_LOG: crate::log_ratelimit::LogEvery =
            crate::log_ratelimit::LogEvery::new(8, 64);
        if (flags == 0 || flags & !KNOWN != 0) && FLAGS_LOG.should_emit() {
            tracing::warn!(target: "bibavpn_mux", stream_id = sid, flags, "mux unknown flags");
        }
        let Some(flow) = self.get(sid) else {
            if flags & MUX_FLAG_DATA != 0 && !payload.is_empty() && !self.client {
                self.control(sid, MUX_FLAG_RST, Vec::new(), None)?;
            }
            return Ok(());
        };
        // RST aborts immediately. DATA|FIN retains ordering through the receive queue.
        if flags & MUX_FLAG_RST != 0 {
            self.remove(sid, flow.epoch);
            return Ok(());
        }
        let result = if flow.negotiated && flags & MUX_FLAG_WIN != 0 && flags != MUX_FLAG_WIN {
            Err(anyhow::anyhow!("mixed mux WIN flags"))
        } else if flags == MUX_FLAG_WIN {
            flow.add_credit(&payload)
        } else if flags & MUX_FLAG_DATA != 0 || flags & MUX_FLAG_CLOSE != 0 {
            let data = if flags & MUX_FLAG_DATA != 0 {
                payload
            } else {
                Vec::new()
            };
            flow.enqueue(data, flags & MUX_FLAG_CLOSE != 0)
        } else {
            Ok(())
        };
        if result.is_err() && self.remove(sid, flow.epoch) {
            self.control(sid, MUX_FLAG_RST, Vec::new(), None)?;
        }
        Ok(())
    }

    pub(super) async fn run<S>(
        self: &Arc<Self>,
        ws: WebSocketStream<S>,
        crypto: Option<SharedCrypto>,
        shutdown: Option<watch::Receiver<bool>>,
        connect_timeout: Duration,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _session_guard = SessionGuard(self);
        let (mut sink, mut reader) = ws.split();
        let mut output = self
            .output_rx
            .lock()
            .unwrap()
            .take()
            .expect("one session writer");
        let mut control = self
            .control_rx
            .lock()
            .unwrap()
            .take()
            .expect("one control writer");
        if self.client {
            self.control(0, MUX_FLAG_WIN, capability(1), None)?;
        }
        let writer = async {
            let mut adaptive = AdaptivePadState::default();
            let mut wire = Vec::new();
            let mut record = Vec::new();
            let mut ping_at = Instant::now() + self.ping_period();
            let mut dummy_at = Instant::now() + self.dummy_period();
            loop {
                let command = tokio::select! {
                    command = control.recv() => command,
                    command = output.recv() => command,
                    _ = tokio::time::sleep_until(ping_at), if self.cfg.ws_ping_secs > 0 => {
                        sink.send(Message::Ping(Bytes::new())).await?;
                        ping_at = Instant::now() + self.ping_period();
                        continue;
                    }
                    _ = tokio::time::sleep_until(dummy_at), if self.cfg.dummy_interval_secs > 0 => {
                        if self.client {
                            // Preserve the producer and writer jitter of client dummy frames.
                            maybe_ws_send_jitter(self.cfg.send_jitter()).await;
                        } else {
                            maybe_server_ack_and_rtt_mask(self.timing).await;
                        }
                        maybe_ws_send_jitter(self.cfg.send_jitter()).await;
                        wire.clear();
                        write_padded_frame_with_mode_state(&mut wire, &[], self.cfg.max_pad, self.cfg.pad_mode, Some(&mut adaptive))?;
                        let blob = self.seal(&wire, &crypto)?;
                        if blob.len() <= self.cfg.max_ws_binary { sink.send(Message::Binary(blob)).await?; }
                        dummy_at = Instant::now() + self.dummy_period();
                        continue;
                    }
                };
                let Some(command) = command else {
                    break;
                };
                let mut next = Some(command);
                // Bounded batches ensure flush and timers run even under continuous producers.
                for _ in 0..64 {
                    let command = match next.take() {
                        Some(command) => command,
                        None => match control.try_recv().or_else(|_| output.try_recv()) {
                            Ok(command) => command,
                            Err(_) => break,
                        },
                    };
                    match command {
                        Output::Pong(payload) => sink.feed(Message::Pong(payload)).await?,
                        Output::Record(command) => {
                            if let Some(flow) = &command.flow {
                                if !flow.output_valid.load(Ordering::Acquire)
                                    || self
                                        .get(command.sid)
                                        .is_some_and(|current| current.epoch != flow.epoch)
                                {
                                    continue;
                                }
                            }
                            // Normal FIN completion retains its queued DATA and CLOSE.
                            record.clear();
                            write_mux_record_to(
                                &mut record,
                                command.sid,
                                command.flags,
                                &command.payload,
                            );
                            wire.clear();
                            write_padded_frame_with_mode_state(
                                &mut wire,
                                &record,
                                self.cfg.max_pad,
                                self.cfg.pad_mode,
                                Some(&mut adaptive),
                            )?;
                            let blob = self.seal(&wire, &crypto)?;
                            if blob.len() > self.cfg.max_ws_binary {
                                bail!("mux ws binary cap");
                            }
                            if command.flags != MUX_FLAG_DATA && command.flags != MUX_FLAG_WIN {
                                if !self.client {
                                    maybe_server_ack_and_rtt_mask(self.timing).await;
                                }
                                maybe_ws_send_jitter(self.cfg.send_jitter()).await;
                            }
                            if let Some(activity) = &self.cfg.activity {
                                activity.touch();
                            }
                            sink.feed(Message::Binary(blob)).await?;
                        }
                    }
                }
                sink.flush().await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let receiver = async {
            while let Some(message) = reader.next().await {
                match message? {
                    Message::Binary(blob) => {
                        if blob.len() > self.cfg.max_ws_binary.saturating_mul(4) {
                            bail!("oversized mux binary");
                        }
                        let raw = match &crypto {
                            Some(crypto) if self.client => crypto.open_server_to_client(&blob)?,
                            Some(crypto) => crypto.open_client_to_server(&blob)?,
                            None => blob.to_vec(),
                        };
                        let inner = read_padded_frame_into(raw)?;
                        if inner.is_empty() {
                            continue;
                        }
                        let (sid, flags, payload) = decode_mux_record(&inner)?;
                        if let Some(activity) = &self.cfg.activity {
                            activity.touch();
                        }
                        self.dispatch(sid, flags, payload, connect_timeout).await?;
                    }
                    Message::Ping(payload) => {
                        self.control
                            .try_send(Output::Pong(payload))
                            .map_err(|_| anyhow::anyhow!("mux pong queue exhausted"))?;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        let stop = async {
            if let Some(mut shutdown) = shutdown {
                let _ = shutdown.wait_for(|closed| *closed).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let mut session_stop = self.session_stop.subscribe();
        let result = tokio::select! {
            result = writer => result, result = receiver => result, _ = stop => Ok(()),
            _ = session_stop.wait_for(|closed| *closed) => Err(anyhow::anyhow!("mux session stopped")),
        };
        self.shutdown();
        result
    }

    fn seal(&self, wire: &[u8], crypto: &Option<SharedCrypto>) -> anyhow::Result<Bytes> {
        Ok(Bytes::from(match crypto {
            Some(crypto) if self.client => crypto.seal_client_to_server(wire)?,
            Some(crypto) => crypto.seal_server_to_client(wire)?,
            None => wire.to_vec(),
        }))
    }

    fn ping_period(&self) -> Duration {
        ws_ping_period_duration(
            self.cfg.ws_ping_secs.max(1),
            self.cfg.ws_ping_jitter_percent,
        )
    }

    fn dummy_period(&self) -> Duration {
        use rand::Rng;
        let base = self.cfg.dummy_interval_secs.max(1);
        Duration::from_secs(
            rand::thread_rng().gen_range((base / 2).max(1)..=base.saturating_mul(3) / 2),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::protocol::Role;

    fn config() -> MuxClientConfig {
        MuxClientConfig {
            max_pad: 0,
            decoy_max: 0,
            max_ws_binary: 65536,
            ws_ping_secs: 0,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            transport_v2: false,
            pad_mode: PadMode::Random,
            dummy_interval_secs: 0,
            activity: None,
        }
    }

    fn endpoint(client: bool) -> Arc<Endpoint> {
        Endpoint::new(client, config(), ServerWsOutTiming::default())
    }

    async fn write_test_payload(socket: &mut TcpStream, byte: u8, len: usize) {
        // Keep initial packets small: developer machines can inspect loopback TCP packets.
        // This affects only fixtures, never tunnel socket behavior.
        socket.set_nodelay(true).unwrap();
        let prefix = len.min(8);
        for _ in 0..prefix {
            socket.write_all(&[byte]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        socket.write_all(&vec![byte; len - prefix]).await.unwrap();
    }

    async fn ws_pair() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        tokio::join!(
            WebSocketStream::from_raw_socket(a, Role::Client, None),
            WebSocketStream::from_raw_socket(b, Role::Server, None),
        )
    }

    async fn send_record(
        ws: &mut WebSocketStream<DuplexStream>,
        sid: u32,
        flags: u8,
        payload: &[u8],
    ) {
        let record = encode_mux_record(sid, flags, payload);
        let mut wire = Vec::new();
        crate::write_padded_frame_with_mode(&mut wire, &record, 0, PadMode::Random).unwrap();
        ws.send(Message::Binary(wire.into())).await.unwrap();
    }

    async fn recv_record(ws: &mut WebSocketStream<DuplexStream>) -> (u32, u8, Vec<u8>) {
        loop {
            if let Message::Binary(blob) = timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
            {
                return decode_mux_record(&read_padded_frame_into(blob.to_vec()).unwrap()).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn blocked_local_downlink_does_not_block_upload() {
        // Same regression as the original TCP test, now using a deterministic64-byte socket buffer.
        let endpoint = endpoint(true);
        let flow = endpoint.allocate(1, None).unwrap();
        let mut output = endpoint.output_rx.lock().unwrap().take().unwrap();
        let (mut app, local) = tokio::io::duplex(64);
        let running = endpoint.clone();
        let stream = flow.clone();
        let task = tokio::spawn(async move {
            running.bridge(local, 1, stream, Vec::new()).await;
        });
        flow.enqueue(vec![7; 4096], false).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            flow.receive.lock().unwrap().bytes,
            4096,
            "in-progress write stays charged"
        );
        app.write_all(b"upload survives").await.unwrap();
        let command = timeout(Duration::from_secs(1), output.recv())
            .await
            .expect("blocked TCP write must not suspend the independent upload pump")
            .unwrap();
        assert!(
            matches!(command, Output::Record(Record { flags: MUX_FLAG_DATA, payload, .. }) if payload == b"upload survives")
        );
        endpoint.shutdown();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn credit_exhaustion_replenishment_and_malformed_updates() {
        let endpoint = endpoint(true);
        let flow = endpoint.allocate(1, Some(32)).unwrap();
        assert_eq!(flow.take_credit(64).await, 32);
        assert!(timeout(Duration::from_millis(20), flow.take_credit(1))
            .await
            .is_err());
        for bad in [
            vec![],
            vec![1; 3],
            0u32.to_be_bytes().to_vec(),
            33u32.to_be_bytes().to_vec(),
            u32::MAX.to_be_bytes().to_vec(),
        ] {
            assert!(flow.add_credit(&bad).is_err());
        }
        flow.add_credit(&16u32.to_be_bytes()).unwrap();
        assert_eq!(flow.take_credit(32).await, 16);
        flow.add_credit(&32u32.to_be_bytes()).unwrap();
        assert!(
            flow.add_credit(&1u32.to_be_bytes()).is_err(),
            "cannot grow beyond initial window"
        );
    }

    #[tokio::test]
    async fn legacy_never_waits_for_or_validates_credit() {
        let endpoint = endpoint(true);
        let flow = endpoint.allocate(1, None).unwrap();
        flow.add_credit(b"ignored old WIN").unwrap();
        assert_eq!(
            flow.take_credit(2 * MUX_INITIAL_WINDOW as usize).await,
            2 * MUX_INITIAL_WINDOW as usize
        );
    }

    #[tokio::test]
    async fn pending_open_budget_is_reserved_and_reclaimed() {
        let endpoint = endpoint(false);
        let count = RECEIVE_BUDGET / MUX_INITIAL_WINDOW as usize;
        for sid in 1..=count as u32 {
            endpoint.allocate(sid, Some(MUX_INITIAL_WINDOW)).unwrap();
        }
        assert!(endpoint.allocate(1000, Some(MUX_INITIAL_WINDOW)).is_err());
        let flow = endpoint.get(1).unwrap();
        assert!(flow
            .enqueue(vec![0; MUX_INITIAL_WINDOW as usize], false)
            .is_ok());
        assert!(flow.enqueue(vec![0], false).is_err());
        assert!(endpoint.remove(1, flow.epoch));
        drop(flow);
        assert!(endpoint.allocate(1000, Some(MUX_INITIAL_WINDOW)).is_ok());
        endpoint.shutdown();
        assert_eq!(endpoint.receive_budget.available_permits(), RECEIVE_BUDGET);
    }

    #[tokio::test]
    async fn stale_cleanup_and_duplicate_open_keep_current_generation() {
        let endpoint = endpoint(false);
        let first = endpoint.allocate(7, None).unwrap();
        assert!(endpoint.allocate(7, None).is_err());
        assert_eq!(endpoint.get(7).unwrap().epoch, first.epoch);
        assert!(endpoint.remove(7, first.epoch));
        let second = endpoint.allocate(7, None).unwrap();
        assert!(!endpoint.remove(7, first.epoch));
        assert_eq!(endpoint.get(7).unwrap().epoch, second.epoch);
        assert!(!*second.cancelled.borrow());
        assert!(endpoint.remove(7, second.epoch));
    }

    #[tokio::test]
    async fn read_loop_releases_stream_when_ws_queue_closed() {
        let endpoint = endpoint(false);
        let flow = endpoint.allocate(7, None).unwrap();
        drop(endpoint.output_rx.lock().unwrap().take());
        let (mut app, local) = tokio::io::duplex(64);
        app.write_all(b"hello").await.unwrap();
        timeout(
            Duration::from_secs(1),
            endpoint.bridge(local, 7, flow.clone(), Vec::new()),
        )
        .await
        .unwrap();
        assert!(endpoint.get(7).is_none());
        assert!(*flow.cancelled.borrow());
        assert_eq!(app.read(&mut [0; 1]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn read_loop_releases_stream_on_legacy_eof() {
        let endpoint = endpoint(false);
        let flow = endpoint.allocate(7, None).unwrap();
        let (app, local) = tokio::io::duplex(64);
        drop(app);
        timeout(
            Duration::from_secs(1),
            endpoint.bridge(local, 7, flow.clone(), Vec::new()),
        )
        .await
        .unwrap();
        assert!(endpoint.get(7).is_none());
        assert!(*flow.cancelled.borrow());
        assert!(
            flow.output_valid.load(Ordering::Acquire),
            "normal EOF preserves queued FIN"
        );
    }

    #[tokio::test]
    async fn data_fin_is_ordered_and_half_close_keeps_other_direction_alive() {
        let endpoint = endpoint(false);
        let flow = endpoint.allocate(7, Some(MUX_INITIAL_WINDOW)).unwrap();
        let mut output = endpoint.output_rx.lock().unwrap().take().unwrap();
        let (mut app, local) = tokio::io::duplex(64);
        let running = endpoint.clone();
        let stream = flow.clone();
        let task = tokio::spawn(async move {
            running.bridge(local, 7, stream, Vec::new()).await;
        });
        endpoint
            .dispatch(
                7,
                MUX_FLAG_DATA | MUX_FLAG_CLOSE,
                b"request".to_vec(),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        let mut request = Vec::new();
        timeout(Duration::from_secs(1), app.read_to_end(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request, b"request");
        assert!(
            endpoint.get(7).is_some(),
            "peer FIN only closes the local write half"
        );
        app.write_all(b"response after FIN").await.unwrap();
        app.shutdown().await.unwrap();
        let first = timeout(Duration::from_secs(1), output.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(first, Output::Record(Record { flags: MUX_FLAG_DATA, payload, .. }) if payload == b"response after FIN")
        );
        let second = timeout(Duration::from_secs(1), output.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            second,
            Output::Record(Record {
                flags: MUX_FLAG_CLOSE,
                ..
            })
        ));
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(endpoint.get(7).is_none());
    }

    #[tokio::test]
    async fn first_stream_negotiates_and_old_server_fallback_is_latched() {
        let client = endpoint(true);
        let (a, mut old) = ws_pair().await;
        let running = client.clone();
        let task =
            tokio::spawn(async move { running.run(a, None, None, Duration::from_secs(1)).await });
        let (sid, flag, request) = recv_record(&mut old).await;
        assert_eq!((sid, flag), (0, MUX_FLAG_WIN));
        assert_eq!(parse_capability(&request, 1), Some(MUX_INITIAL_WINDOW));
        assert_eq!(client.peer_window().await, None);
        send_record(&mut old, 0, MUX_FLAG_WIN, &capability(2)).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            client.peer_window().await,
            None,
            "late ACK never upgrades a fallback session"
        );
        old.close(None).await.unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn new_peers_negotiate_before_first_open() {
        let client = endpoint(true);
        let server = endpoint(false);
        let (a, b) = ws_pair().await;
        let c = client.clone();
        let s = server.clone();
        let ct = tokio::spawn(async move { c.run(a, None, None, Duration::from_secs(1)).await });
        let st = tokio::spawn(async move { s.run(b, None, None, Duration::from_secs(1)).await });
        assert_eq!(client.peer_window().await, Some(MUX_INITIAL_WINDOW));
        client.shutdown();
        server.shutdown();
        let _ = ct.await;
        let _ = st.await;
    }

    #[tokio::test]
    async fn malformed_credit_resets_only_its_stream() {
        let endpoint = endpoint(false);
        let bad = endpoint.allocate(1, Some(MUX_INITIAL_WINDOW)).unwrap();
        let good = endpoint.allocate(2, Some(MUX_INITIAL_WINDOW)).unwrap();
        endpoint
            .dispatch(
                1,
                MUX_FLAG_WIN,
                1u32.to_be_bytes().to_vec(),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(endpoint.get(1).is_none());
        assert!(*bad.cancelled.borrow());
        assert!(!*good.cancelled.borrow());
        endpoint
            .dispatch(
                2,
                MUX_FLAG_DATA,
                b"healthy".to_vec(),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(good.receive().await.unwrap(), b"healthy");
    }

    #[tokio::test]
    async fn output_bytes_and_control_lane_are_independent() {
        let endpoint = endpoint(true);
        let flow = endpoint.allocate(1, Some(1)).unwrap();
        let permit = endpoint
            .output_budget
            .clone()
            .acquire_many_owned(OUTPUT_BUDGET as u32)
            .await
            .unwrap();
        assert!(timeout(
            Duration::from_millis(20),
            endpoint.send(1, MUX_FLAG_DATA, vec![0], flow.clone())
        )
        .await
        .is_err());
        endpoint
            .control(1, MUX_FLAG_WIN, 1u32.to_be_bytes().to_vec(), Some(flow))
            .unwrap();
        let mut control = endpoint.control_rx.lock().unwrap().take().unwrap();
        assert!(matches!(
            control.try_recv(),
            Ok(Output::Record(Record {
                flags: MUX_FLAG_WIN,
                ..
            }))
        ));
        drop(permit);
        assert_eq!(endpoint.output_budget.available_permits(), OUTPUT_BUDGET);
    }

    #[tokio::test]
    async fn old_client_new_server_transfers_beyond_initial_window_without_win() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let expected = vec![19; 2 * MUX_INITIAL_WINDOW as usize];
        let origin_task = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            write_test_payload(&mut socket, 19, 2 * MUX_INITIAL_WINDOW as usize).await;
        });
        let server = endpoint(false);
        let (mut old, b) = ws_pair().await;
        let running = server.clone();
        let task =
            tokio::spawn(async move { running.run(b, None, None, Duration::from_secs(1)).await });
        send_record(
            &mut old,
            1,
            MUX_FLAG_OPEN,
            &encode_mux_open_target("127.0.0.1", port).unwrap(),
        )
        .await;
        let mut received = Vec::new();
        loop {
            let (_, flags, payload) = recv_record(&mut old).await;
            if flags == MUX_FLAG_DATA {
                received.extend_from_slice(&payload);
            }
            if flags == MUX_FLAG_CLOSE {
                break;
            }
            assert_ne!(
                flags, MUX_FLAG_WIN,
                "legacy stream never needs to interpret credit"
            );
        }
        assert_eq!(received, expected);
        old.close(None).await.unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_reader_routes_healthy_stream_while_another_write_is_blocked() {
        let client = endpoint(true);
        let slow = client.allocate(1, Some(MUX_INITIAL_WINDOW)).unwrap();
        let healthy = client.allocate(2, Some(MUX_INITIAL_WINDOW)).unwrap();
        let (_slow_app, slow_socket) = tokio::io::duplex(64);
        let (mut healthy_app, healthy_socket) = tokio::io::duplex(64);
        let c1 = client.clone();
        let c2 = client.clone();
        let slow_state = slow.clone();
        let p1 = tokio::spawn(async move {
            c1.bridge(slow_socket, 1, slow_state, Vec::new()).await;
        });
        let p2 = tokio::spawn(async move {
            c2.bridge(healthy_socket, 2, healthy, Vec::new()).await;
        });
        let (a, mut peer) = ws_pair().await;
        let running = client.clone();
        let session =
            tokio::spawn(async move { running.run(a, None, None, Duration::from_secs(1)).await });
        let _ = recv_record(&mut peer).await;
        let chunk = vec![1; 16384];
        for _ in 0..MUX_INITIAL_WINDOW as usize / chunk.len() {
            send_record(&mut peer, 1, MUX_FLAG_DATA, &chunk).await;
        }
        send_record(&mut peer, 2, MUX_FLAG_DATA, b"healthy").await;
        let mut marker = [0; 7];
        timeout(Duration::from_secs(1), healthy_app.read_exact(&mut marker))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&marker, b"healthy");
        assert_eq!(
            slow.receive.lock().unwrap().bytes,
            MUX_INITIAL_WINDOW as usize
        );
        assert!(
            client.get(1).is_some(),
            "admitted negotiated stream must stall without reset"
        );
        client.shutdown();
        let _ = session.await;
        p1.await.unwrap();
        p2.await.unwrap();
        drop(slow);
        assert_eq!(client.receive_budget.available_permits(), RECEIVE_BUDGET);
    }

    #[tokio::test]
    async fn new_client_old_server_sends_plain_open_and_unlimited_legacy_upload() {
        let client = endpoint(true);
        let (a, mut old) = ws_pair().await;
        let running = client.clone();
        let session =
            tokio::spawn(async move { running.run(a, None, None, Duration::from_secs(1)).await });
        let _ = recv_record(&mut old).await; // Old server ignores unknown WIN.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (local, _) = listener.accept().await.unwrap();
        client
            .open_stream(local, "example.test".into(), 80, Vec::new())
            .await
            .map_err(|e| e.err)
            .unwrap();
        let (_, flags, _) = recv_record(&mut old).await;
        assert_eq!(flags, MUX_FLAG_OPEN);
        let upload = tokio::spawn(async move {
            write_test_payload(&mut app, 23, 2 * MUX_INITIAL_WINDOW as usize).await;
            app.shutdown().await.unwrap();
        });
        let mut received = 0;
        loop {
            let (_, flags, payload) = recv_record(&mut old).await;
            if flags == MUX_FLAG_CLOSE {
                break;
            }
            assert_eq!(flags, MUX_FLAG_DATA);
            assert!(payload.iter().all(|byte| *byte == 23));
            received += payload.len();
        }
        assert_eq!(received, 2 * MUX_INITIAL_WINDOW as usize);
        upload.await.unwrap();
        old.close(None).await.unwrap();
        timeout(Duration::from_secs(1), session)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn new_peers_transfer_multiple_windows_and_respond_after_request_fin() {
        let client = endpoint(true);
        let server = endpoint(false);
        let (a, b) = ws_pair().await;
        let c = client.clone();
        let s = server.clone();
        let ct = tokio::spawn(async move { c.run(a, None, None, Duration::from_secs(1)).await });
        let st = tokio::spawn(async move { s.run(b, None, None, Duration::from_secs(1)).await });
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let target = tokio::spawn(async move {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, vec![31; 3 * MUX_INITIAL_WINDOW as usize]);
            write_test_payload(&mut socket, 47, 2 * MUX_INITIAL_WINDOW as usize).await;
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (local, _) = listener.accept().await.unwrap();
        client
            .open_stream(local, "127.0.0.1".into(), port, Vec::new())
            .await
            .map_err(|e| e.err)
            .unwrap();
        assert!(
            client.get(1).unwrap().negotiated,
            "the first stream receives negotiated credits"
        );
        timeout(Duration::from_secs(10), async {
            write_test_payload(&mut app, 31, 3 * MUX_INITIAL_WINDOW as usize).await;
            app.shutdown().await.unwrap();
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, vec![47; 2 * MUX_INITIAL_WINDOW as usize]);
            target.await.unwrap();
        })
        .await
        .expect("multiple windows and half-close must complete");
        client.shutdown();
        server.shutdown();
        let _ = ct.await;
        let _ = st.await;
    }

    #[tokio::test]
    async fn aborting_session_releases_streams_and_wakes_blocked_pumps() {
        let client = endpoint(true);
        let (a, mut peer) = ws_pair().await;
        let running = client.clone();
        let session =
            tokio::spawn(async move { running.run(a, None, None, Duration::from_secs(1)).await });
        let _ = recv_record(&mut peer).await;
        let flow = client.allocate(1, Some(MUX_INITIAL_WINDOW)).unwrap();
        let (app, local) = tokio::io::duplex(64);
        let endpoint = client.clone();
        let stream = flow.clone();
        let pump = tokio::spawn(async move {
            endpoint.bridge(local, 1, stream, Vec::new()).await;
        });
        flow.enqueue(vec![7; 4096], false).unwrap();
        session.abort();
        let _ = session.await;
        assert!(
            *flow.cancelled.borrow(),
            "aborting owner task must cancel its stream pumps"
        );
        timeout(Duration::from_secs(1), pump)
            .await
            .unwrap()
            .unwrap();
        drop(flow);
        drop(app);
        assert_eq!(client.receive_budget.available_permits(), RECEIVE_BUDGET);
    }

    #[tokio::test]
    async fn write_completion_after_reset_keeps_byte_accounting_valid() {
        let endpoint = endpoint(false);
        let flow = endpoint.allocate(1, Some(MUX_INITIAL_WINDOW)).unwrap();
        flow.enqueue(vec![7; 32], false).unwrap();
        let data = flow.receive().await.unwrap();
        endpoint.remove(1, flow.epoch);
        // write_all can complete in the same poll as reset; cancellation must not zero this debt.
        flow.consumed(data.len());
        assert_eq!(flow.receive.lock().unwrap().bytes, 0);
        drop(data);
        drop(flow);
        assert_eq!(endpoint.receive_budget.available_permits(), RECEIVE_BUDGET);
    }

    #[tokio::test]
    async fn receive_overflow_resets_only_offending_legacy_or_credit_stream() {
        for window in [None, Some(MUX_INITIAL_WINDOW)] {
            let endpoint = endpoint(false);
            let slow = endpoint.allocate(1, window).unwrap();
            let healthy = endpoint.allocate(2, window).unwrap();
            slow.enqueue(vec![7; MUX_INITIAL_WINDOW as usize], false)
                .unwrap();
            endpoint
                .dispatch(1, MUX_FLAG_DATA, vec![8], Duration::from_secs(1))
                .await
                .unwrap();
            assert!(endpoint.get(1).is_none());
            assert!(*slow.cancelled.borrow());
            endpoint
                .dispatch(
                    2,
                    MUX_FLAG_DATA,
                    b"healthy".to_vec(),
                    Duration::from_secs(1),
                )
                .await
                .unwrap();
            assert_eq!(healthy.receive().await.unwrap(), b"healthy");
            let mut control = endpoint.control_rx.lock().unwrap().take().unwrap();
            assert!(matches!(
                control.try_recv(),
                Ok(Output::Record(Record {
                    sid: 1,
                    flags: MUX_FLAG_RST,
                    ..
                }))
            ));
        }
    }

    #[test]
    fn malformed_capabilities_do_not_negotiate() {
        assert_eq!(
            parse_capability(&capability(1), 1),
            Some(MUX_INITIAL_WINDOW)
        );
        assert_eq!(parse_capability(&capability(2), 1), None);
        for bad in [
            vec![],
            b"BFC1\x01\0\0\0\0".to_vec(),
            b"BFC1\x01\xff\xff\xff\xff".to_vec(),
            b"BFC1\x01\0\0\0\x01junk".to_vec(),
        ] {
            assert_eq!(parse_capability(&bad, 1), None);
        }
    }
}
