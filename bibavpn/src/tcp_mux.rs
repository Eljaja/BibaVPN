//! Multiplex many TCP streams over one WebSocket (after `MUX_OPEN_MAGIC`).

use std::collections::HashMap;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::task::{Context as TaskContext, Poll};

use anyhow::Context;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info, warn};

use crate::crypto_layer::SessionCrypto;
use crate::frame::{AdaptivePadState, PadMode};
use crate::protocol::encode_atyp_host_port;
use crate::retry::{
    maybe_server_ack_and_rtt_mask, maybe_ws_send_jitter, ws_ping_period_duration, ServerWsOutTiming,
    WsSendJitter,
};
use crate::ws_bridge::TunnelEnd;
use crate::{read_padded_frame_into, write_padded_frame_with_mode, write_padded_frame_with_mode_state};

pub type SharedCrypto = Arc<SessionCrypto>;

pub const MUX_OPEN_MAGIC: &[u8] = b"BIBA\x01MUXO\x00";

pub const MUX_FLAG_OPEN: u8 = 0x01;
pub const MUX_FLAG_DATA: u8 = 0x02;
pub const MUX_FLAG_CLOSE: u8 = 0x04;
pub const MUX_FLAG_RST: u8 = 0x08;
pub const MUX_FLAG_WIN: u8 = 0x10;

pub const MUX_INITIAL_WINDOW: u32 = 1024 * 1024;

/// Returned when the mux WebSocket writer task stopped (e.g. reconnect).
#[derive(Debug)]
pub struct MuxWriterStopped;

impl std::fmt::Display for MuxWriterStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tcp mux writer stopped")
    }
}

impl std::error::Error for MuxWriterStopped {}

static UNKNOWN_MUX_DATA_LOG: AtomicU64 = AtomicU64::new(0);
static DUP_OPEN_LOG: crate::log_ratelimit::LogEvery = crate::log_ratelimit::LogEvery::new(8, 64);
static SERVER_FLAGS_LOG: crate::log_ratelimit::LogEvery =
    crate::log_ratelimit::LogEvery::new(8, 64);
static CLIENT_FLAGS_LOG: crate::log_ratelimit::LogEvery =
    crate::log_ratelimit::LogEvery::new(8, 64);

pub fn is_mux_open(data: &[u8]) -> bool {
    data == MUX_OPEN_MAGIC
}

pub fn encode_mux_open() -> Vec<u8> {
    MUX_OPEN_MAGIC.to_vec()
}

pub fn encode_mux_record(stream_id: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 1 + 4 + payload.len());
    write_mux_record_to(&mut v, stream_id, flags, payload);
    v
}

/// Append a mux record header + payload into an existing buffer (avoids extra allocation).
pub fn write_mux_record_to(buf: &mut Vec<u8>, stream_id: u32, flags: u8, payload: &[u8]) {
    buf.extend_from_slice(&stream_id.to_be_bytes());
    buf.push(flags);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
}

pub fn decode_mux_record(data: &[u8]) -> anyhow::Result<(u32, u8, Vec<u8>)> {
    if data.len() < 9 {
        anyhow::bail!("short mux record");
    }
    let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let flags = data[4];
    let plen = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    let total = 9usize.saturating_add(plen);
    if data.len() < total {
        anyhow::bail!("truncated mux payload");
    }
    if data.len() != total {
        anyhow::bail!("mux record length mismatch (trailing bytes)");
    }
    Ok((stream_id, flags, data[9..total].to_vec()))
}

pub fn decode_mux_open_target(payload: &[u8]) -> anyhow::Result<(String, u16)> {
    let (h, p, n) = crate::protocol::decode_atyp_host_port(payload)?;
    if n != payload.len() {
        anyhow::bail!("trailing junk in mux open target");
    }
    Ok((h, p))
}

pub fn encode_mux_open_target(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let mut v = Vec::new();
    encode_atyp_host_port(host, port, &mut v)?;
    Ok(v)
}

const MUX_SERVER_MAX_STREAMS: usize = 256;
const MUX_SERVER_INFLIGHT: usize = 512;
const MUX_PENDING_OPEN_BYTES: usize = 256 * 1024;

/// A stream id may be reused by the peer (buggy client, or wrap-around). Each accepted
/// `MUX_FLAG_OPEN` gets a fresh epoch so a dying stream can tell whether the map entry for
/// its id is still its own before removing it.
enum ServerStreamState {
    Opening {
        epoch: u64,
        buffered: Vec<Vec<u8>>,
        buffered_bytes: usize,
    },
    Open {
        epoch: u64,
        tx: mpsc::Sender<Vec<u8>>,
    },
}

impl ServerStreamState {
    fn epoch(&self) -> u64 {
        match self {
            ServerStreamState::Opening { epoch, .. } => *epoch,
            ServerStreamState::Open { epoch, .. } => *epoch,
        }
    }
}

/// True when the entry currently mapped to a stream id (if any) still belongs to `epoch`.
fn mux_cleanup_should_remove(current: Option<u64>, epoch: u64) -> bool {
    current == Some(epoch)
}

/// Per-stream cleanup: drop the map entry only if it is still this stream's generation.
async fn mux_remove_stream_if_epoch(
    streams: &Arc<Mutex<HashMap<u32, ServerStreamState>>>,
    sid: u32,
    epoch: u64,
) {
    let mut g = streams.lock().await;
    if mux_cleanup_should_remove(g.get(&sid).map(|s| s.epoch()), epoch) {
        g.remove(&sid);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MuxOpenDecision {
    Accept,
    /// `sid` is already tracked; never overwrite a live entry (RST + drop the record).
    RejectDuplicate,
    RejectMaxStreams,
}

fn mux_open_decision(already_tracked: bool, tracked_streams: usize) -> MuxOpenDecision {
    if already_tracked {
        MuxOpenDecision::RejectDuplicate
    } else if tracked_streams >= MUX_SERVER_MAX_STREAMS {
        MuxOpenDecision::RejectMaxStreams
    } else {
        MuxOpenDecision::Accept
    }
}

/// Receive-side flag classification. Flags are a bitmask: a record carrying
/// `DATA|CLOSE` must still deliver its payload before the close is applied.
/// Send side never combines flags, so this is tolerance only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MuxFlags {
    open: bool,
    data: bool,
    close: bool,
    reset: bool,
    /// Bits outside the known set (or no bits at all): warn, but still act on known bits.
    unknown: bool,
}

fn classify_mux_flags(flags: u8) -> MuxFlags {
    const KNOWN: u8 = MUX_FLAG_OPEN | MUX_FLAG_DATA | MUX_FLAG_CLOSE | MUX_FLAG_RST | MUX_FLAG_WIN;
    MuxFlags {
        open: flags & MUX_FLAG_OPEN != 0,
        data: flags & MUX_FLAG_DATA != 0,
        close: flags & MUX_FLAG_CLOSE != 0,
        reset: flags & MUX_FLAG_RST != 0,
        unknown: flags == 0 || flags & !KNOWN != 0,
    }
}

/// Server: after `MUX_OPEN`, dispatch logical streams.
pub async fn bridge_ws_tcp_mux_server<S>(
    ws: WebSocketStream<S>,
    max_pad: u8,
    decoy_max: u8,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    ws_ping_secs: u64,
    ws_ping_jitter_percent: u8,
    ws_binary_send_jitter_ms: u8,
    ws_jitter_min_ms: u8,
    ws_jitter_max_ms: u8,
    pad_mode: PadMode,
    dummy_interval_secs: u64,
    server_out_timing: ServerWsOutTiming,
    mux_connect_timeout: Duration,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let server_adaptive = Arc::new(StdMutex::new(AdaptivePadState::default()));
    let s_timing = server_out_timing;
    let ws_send_jitter = WsSendJitter {
        min_ms: ws_jitter_min_ms,
        max_ms: ws_jitter_max_ms,
        legacy_0_to_max: ws_binary_send_jitter_ms,
    };
    let v2 = crypto.is_some();
    // Inner padded payload is a mux record: 9-byte header + TCP slice (see `encode_mux_record`).
    let max_chunk =
        crate::frame::max_tcp_payload_per_ws_message(v2, decoy_max, max_pad, max_ws_binary)
            .saturating_sub(9)
            .max(256);

    let (mut ws_sink, mut ws_rx) = ws.split();
    const WS_OUT_CAP: usize = 512;
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<Message>(WS_OUT_CAP);
    let ws_out_srv = ws_out_tx.clone();
    let ws_dummy_srv = ws_out_srv.clone();
    let crypto_dummy_srv = crypto.clone();
    drop(ws_out_tx);

    if dummy_interval_secs > 0 {
        let dj = ws_send_jitter;
        let st = s_timing;
        tokio::spawn(mux_server_dummy_task(
            ws_dummy_srv,
            crypto_dummy_srv,
            max_pad,
            pad_mode,
            max_ws_binary,
            dj,
            dummy_interval_secs,
            st,
        ));
    }

    let writer = async move {
        let mut ping_sleep: Option<Pin<Box<tokio::time::Sleep>>> = if ws_ping_secs > 0 {
            Some(Box::pin(sleep(ws_ping_period_duration(
                ws_ping_secs,
                ws_ping_jitter_percent,
            ))))
        } else {
            None
        };
        loop {
            let msg = match ping_sleep.as_mut() {
                Some(sleep_pin) => {
                    tokio::select! {
                        m = ws_out_rx.recv() => m,
                        _ = sleep_pin.as_mut() => {
                            ws_sink
                                .send(Message::Ping(bytes::Bytes::new()))
                                .await
                                .context("ws ping")?;
                            *sleep_pin = Box::pin(sleep(ws_ping_period_duration(
                                ws_ping_secs,
                                ws_ping_jitter_percent,
                            )));
                            continue;
                        }
                    }
                }
                None => ws_out_rx.recv().await,
            };
            let Some(msg) = msg else { break };
            ws_sink.feed(msg).await.context("ws feed")?;
            while let Ok(msg) = ws_out_rx.try_recv() {
                ws_sink.feed(msg).await.context("ws feed")?;
            }
            ws_sink.flush().await.context("ws flush")?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let streams: Arc<Mutex<HashMap<u32, ServerStreamState>>> = Arc::new(Mutex::new(HashMap::new()));
    let sem = Arc::new(Semaphore::new(MUX_SERVER_INFLIGHT));
    let crypto_in = crypto.clone();
    let adaptive_in = server_adaptive.clone();
    let jitter_in = ws_send_jitter;
    let srv_t_in = s_timing;

    let up = async move {
        // Bumped for every accepted OPEN; identifies one generation of a stream id.
        let mut next_epoch: u64 = 0;
        while let Some(m) = ws_rx.next().await {
            let m = m.context("websocket read")?;
            match m {
                Message::Binary(b) => {
                    if b.len() > max_ws_binary.saturating_mul(4) {
                        anyhow::bail!("oversized WS binary");
                    }
                    let raw = match (&crypto_in, TunnelEnd::Server) {
                        (Some(c), _) => c
                            .open_client_to_server(b.as_ref())
                            .context("v2 open c2s mux")?,
                        (None, _) => b.to_vec(),
                    };
                    let inner = read_padded_frame_into(raw).map_err(|e| anyhow::anyhow!("{e}"))?;
                    if inner.is_empty() {
                        continue;
                    }
                    let (sid, flags, payload) = decode_mux_record(&inner)?;
                    let act = classify_mux_flags(flags);
                    if act.unknown && SERVER_FLAGS_LOG.should_emit() {
                        warn!(
                            target: "bibavpn_mux",
                            stream_id = sid,
                            "mux: unknown flags {flags:#x}"
                        );
                    }
                    if act.open {
                        // OPEN carries the target address as its payload, so it is never
                        // combined with DATA on the wire; other bits are ignored here.
                        let permit = sem
                            .clone()
                            .acquire_owned()
                            .await
                            .map_err(|_| anyhow::anyhow!("mux sem"))?;
                        let (host, port) = match decode_mux_open_target(&payload) {
                            Ok(x) => x,
                            Err(e) => {
                                error!("mux open target: {e:#}");
                                drop(permit);
                                continue;
                            }
                        };
                        let epoch = {
                            let mut map = streams.lock().await;
                            match mux_open_decision(map.contains_key(&sid), map.len()) {
                                MuxOpenDecision::Accept => {
                                    next_epoch = next_epoch.wrapping_add(1);
                                    map.insert(
                                        sid,
                                        ServerStreamState::Opening {
                                            epoch: next_epoch,
                                            buffered: Vec::new(),
                                            buffered_bytes: 0,
                                        },
                                    );
                                    Some(next_epoch)
                                }
                                MuxOpenDecision::RejectDuplicate => {
                                    if DUP_OPEN_LOG.should_emit() {
                                        warn!(
                                            target: "bibavpn_mux",
                                            stream_id = sid,
                                            "mux: duplicate OPEN for tracked stream (sending RST)"
                                        );
                                    }
                                    None
                                }
                                MuxOpenDecision::RejectMaxStreams => {
                                    warn!("mux: max streams");
                                    None
                                }
                            }
                        };
                        let Some(epoch) = epoch else {
                            drop(permit);
                            let _ = mux_server_send_record(
                                &ws_out_srv,
                                sid,
                                MUX_FLAG_RST,
                                &[],
                                max_pad,
                                pad_mode,
                                &crypto,
                                max_ws_binary,
                                &adaptive_in,
                                jitter_in,
                                srv_t_in,
                            )
                            .await;
                            continue;
                        };
                        let ws_tx = ws_out_srv.clone();
                        let streams_open = streams.clone();
                        let crypto_clone = crypto.clone();
                        let adaptive_spawn = adaptive_in.clone();
                        let j_spawn = jitter_in;
                        let st_spawn = srv_t_in;
                        tokio::spawn(async move {
                            let _permit = permit;
                            let remote = match tokio::time::timeout(
                                mux_connect_timeout,
                                TcpStream::connect((host.as_str(), port)),
                            )
                            .await
                            {
                                Ok(Ok(t)) => t,
                                Ok(Err(e)) => {
                                    error!("mux connect {host}:{port}: {e:#}");
                                    mux_remove_stream_if_epoch(&streams_open, sid, epoch).await;
                                    let _ = mux_server_send_record(
                                        &ws_tx,
                                        sid,
                                        MUX_FLAG_RST,
                                        &[],
                                        max_pad,
                                        pad_mode,
                                        &crypto_clone,
                                        max_ws_binary,
                                        &adaptive_spawn,
                                        j_spawn,
                                        st_spawn,
                                    )
                                    .await;
                                    return;
                                }
                                Err(_) => {
                                    error!("mux connect {host}:{port}: timeout {:?}", mux_connect_timeout);
                                    mux_remove_stream_if_epoch(&streams_open, sid, epoch).await;
                                    let _ = mux_server_send_record(
                                        &ws_tx,
                                        sid,
                                        MUX_FLAG_RST,
                                        &[],
                                        max_pad,
                                        pad_mode,
                                        &crypto_clone,
                                        max_ws_binary,
                                        &adaptive_spawn,
                                        j_spawn,
                                        st_spawn,
                                    )
                                    .await;
                                    return;
                                }
                            };
                            let _ = remote.set_nodelay(true);
                            let (r, w) = remote.into_split();
                            let (wtx, mut wrx) = mpsc::channel::<Vec<u8>>(256);
                            let pending = {
                                let mut g = streams_open.lock().await;
                                match g.remove(&sid) {
                                    Some(ServerStreamState::Opening {
                                        epoch: e, buffered, ..
                                    }) if e == epoch => {
                                        g.insert(
                                            sid,
                                            ServerStreamState::Open {
                                                epoch,
                                                tx: wtx.clone(),
                                            },
                                        );
                                        buffered
                                    }
                                    // Entry belongs to another generation of this id: leave it alone.
                                    Some(other) => {
                                        g.insert(sid, other);
                                        return;
                                    }
                                    None => return,
                                }
                            };
                            let streams_write = streams_open.clone();
                            tokio::spawn(async move {
                                let mut w = w;
                                while let Some(data) = wrx.recv().await {
                                    if w.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                                mux_remove_stream_if_epoch(&streams_write, sid, epoch).await;
                            });
                            for data in pending {
                                if wtx.send(data).await.is_err() {
                                    mux_remove_stream_if_epoch(&streams_open, sid, epoch).await;
                                    return;
                                }
                            }
                            if let Err(e) = mux_server_stream_read_loop(
                                sid,
                                epoch,
                                r,
                                ws_tx,
                                streams_open,
                                max_pad,
                                pad_mode,
                                crypto_clone,
                                max_ws_binary,
                                adaptive_spawn,
                                j_spawn,
                                st_spawn,
                                max_chunk,
                            )
                            .await
                            {
                                error!("mux read sid {sid}: {e:#}");
                            }
                        });
                    } else {
                        if act.data {
                            let mut maybe_tx: Option<(u64, mpsc::Sender<Vec<u8>>)> = None;
                            let mut payload_opt = Some(payload);
                            let mut rst = false;
                            let mut overflow = false;
                            let mut unknown_stream_data = false;
                            {
                                let mut g = streams.lock().await;
                                match g.get_mut(&sid) {
                                    Some(ServerStreamState::Open { epoch, tx }) => {
                                        maybe_tx = Some((*epoch, tx.clone()));
                                    }
                                    Some(ServerStreamState::Opening {
                                        buffered,
                                        buffered_bytes,
                                        ..
                                    }) => {
                                        let payload_len =
                                            payload_opt.as_ref().map(|p| p.len()).unwrap_or(0);
                                        if buffered_bytes.saturating_add(payload_len)
                                            > MUX_PENDING_OPEN_BYTES
                                        {
                                            overflow = true;
                                        } else {
                                            *buffered_bytes += payload_len;
                                            buffered
                                                .push(payload_opt.take().expect("payload present"));
                                        }
                                    }
                                    None => {
                                        unknown_stream_data = payload_opt
                                            .as_ref()
                                            .map(|p| !p.is_empty())
                                            .unwrap_or(false);
                                    }
                                }
                                if overflow {
                                    // Same lock as the match above, so this is the current generation.
                                    g.remove(&sid);
                                    rst = true;
                                }
                            }
                            if let Some((epoch, tx)) = maybe_tx {
                                if tx
                                    .send(payload_opt.expect("payload present"))
                                    .await
                                    .is_err()
                                {
                                    mux_remove_stream_if_epoch(&streams, sid, epoch).await;
                                }
                            } else if rst {
                                let _ = mux_server_send_record(
                                    &ws_out_srv,
                                    sid,
                                    MUX_FLAG_RST,
                                    &[],
                                    max_pad,
                                    pad_mode,
                                    &crypto,
                                    max_ws_binary,
                                    &adaptive_in,
                                    jitter_in,
                                    srv_t_in,
                                )
                                .await;
                            } else if unknown_stream_data {
                                let n =
                                    UNKNOWN_MUX_DATA_LOG.fetch_add(1, Ordering::Relaxed);
                                if n < 8 || n % 64 == 0 {
                                    warn!(
                                        target: "bibavpn_mux",
                                        stream_id = sid,
                                        "mux: DATA for unknown stream (sending RST)"
                                    );
                                }
                                let _ = mux_server_send_record(
                                    &ws_out_srv,
                                    sid,
                                    MUX_FLAG_RST,
                                    &[],
                                    max_pad,
                                    pad_mode,
                                    &crypto,
                                    max_ws_binary,
                                    &adaptive_in,
                                    jitter_in,
                                    srv_t_in,
                                )
                                .await;
                            }
                        }
                        // Applied after any DATA in the same record. Peer-driven, so whatever
                        // entry is mapped now is the generation being closed.
                        // `MUX_FLAG_WIN` stays a no-op: no side sends window updates.
                        if act.close || act.reset {
                            streams.lock().await.remove(&sid);
                        }
                    }
                }
                Message::Ping(p) => {
                    ws_out_srv.send(Message::Pong(p)).await.context("ws pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(writer, up)?;
    Ok(())
}

async fn mux_server_send_record(
    ws_out: &mpsc::Sender<Message>,
    sid: u32,
    flags: u8,
    payload: &[u8],
    max_pad: u8,
    pad_mode: PadMode,
    crypto: &Option<SharedCrypto>,
    max_ws_binary: usize,
    adaptive: &Arc<StdMutex<AdaptivePadState>>,
    ws_send_jitter: WsSendJitter,
    server_out: ServerWsOutTiming,
) -> anyhow::Result<()> {
    let mut wire = Vec::with_capacity(max_ws_binary.min(256 * 1024));
    let mut rec_buf = Vec::with_capacity(payload.len() + 9);
    write_mux_record_to(&mut rec_buf, sid, flags, payload);
    {
        let mut g = adaptive.lock().map_err(|e| anyhow::anyhow!("adaptive: {e}"))?;
        write_padded_frame_with_mode_state(
            &mut wire,
            &rec_buf,
            max_pad,
            pad_mode,
            Some(&mut *g),
        )
        .context("mux pad")?;
    }
    let blob: Bytes = match crypto {
        Some(c) => Bytes::from(
            c.seal_server_to_client(&wire)
                .context("v2 seal s2c mux")?,
        ),
        None => Bytes::from(std::mem::take(&mut wire)),
    };
    if blob.len() > max_ws_binary {
        anyhow::bail!("mux ws binary too large");
    }
    // RTT mask + WS jitter are for traffic shaping on *small* / control frames.
    // Applying them to every DATA chunk would add 40–500+ ms × thousands of frames and
    // effectively stall bulk transfer (and benchmarks).
    let bulk_data = flags == MUX_FLAG_DATA && !payload.is_empty();
    if !bulk_data {
        maybe_server_ack_and_rtt_mask(server_out).await;
        maybe_ws_send_jitter(ws_send_jitter).await;
    }
    ws_out
        .send(Message::Binary(blob))
        .await
        .context("mux ws queue")?;
    Ok(())
}

async fn mux_server_stream_read_loop(
    sid: u32,
    epoch: u64,
    mut tcp_read: OwnedReadHalf,
    ws_out: mpsc::Sender<Message>,
    streams: Arc<Mutex<HashMap<u32, ServerStreamState>>>,
    max_pad: u8,
    pad_mode: PadMode,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    adaptive: Arc<StdMutex<AdaptivePadState>>,
    ws_send_jitter: WsSendJitter,
    server_out: ServerWsOutTiming,
    max_chunk: usize,
) -> anyhow::Result<()> {
    let read_cap = max_chunk.saturating_mul(8).min(512 * 1024).max(max_chunk);
    let mut buf = vec![0u8; read_cap];
    loop {
        let n = tcp_read.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let mut off = 0usize;
        while off < n {
            let take = (n - off).min(max_chunk);
            mux_server_send_record(
                &ws_out,
                sid,
                MUX_FLAG_DATA,
                &buf[off..off + take],
                max_pad,
                pad_mode,
                &crypto,
                max_ws_binary,
                &adaptive,
                ws_send_jitter,
                server_out,
            )
            .await?;
            off += take;
        }
    }
    let _ = mux_server_send_record(
        &ws_out,
        sid,
        MUX_FLAG_CLOSE,
        &[],
        max_pad,
        pad_mode,
        &crypto,
        max_ws_binary,
        &adaptive,
        ws_send_jitter,
        server_out,
    )
    .await;
    mux_remove_stream_if_epoch(&streams, sid, epoch).await;
    Ok(())
}

// --- Client: shared WebSocket ---

#[derive(Clone)]
pub struct MuxClientConfig {
    pub max_pad: u8,
    pub decoy_max: u8,
    pub max_ws_binary: usize,
    pub ws_ping_secs: u64,
    pub ws_ping_jitter_percent: u8,
    pub ws_binary_send_jitter_ms: u8,
    /// Outbound delay range in ms; when both 0, only `ws_binary_send_jitter_ms` is used.
    pub ws_jitter_min_ms: u8,
    pub ws_jitter_max_ms: u8,
    /// BibaV2 AEAD outer framing (set from `spawn_tcp_mux_client`).
    pub transport_v2: bool,
    pub pad_mode: PadMode,
    /// Idle empty padded frames on the shared mux WSS (0 = off).
    pub dummy_interval_secs: u64,
    /// When set, update on each mux read/write of payload (for idle decoy, etc.).
    pub activity: Option<Arc<crate::activity::ActivityTracker>>,
}

impl MuxClientConfig {
    fn send_jitter(&self) -> WsSendJitter {
        WsSendJitter {
            min_ms: self.ws_jitter_min_ms,
            max_ms: self.ws_jitter_max_ms,
            legacy_0_to_max: self.ws_binary_send_jitter_ms,
        }
    }
}

#[derive(Debug)]
enum MuxWriteCmd {
    Record {
        stream_id: u32,
        flags: u8,
        payload: Vec<u8>,
    },
    Pong(Vec<u8>),
    /// Pre-built WS binary (e.g. idle dummy after padding + optional seal).
    RawBinary(Bytes),
}

/// `open_stream` failed before the bridge task was spawned; `local` is returned so the caller can retry.
pub struct MuxOpenStreamDropped {
    pub local: TcpStream,
    pub err: anyhow::Error,
}

/// Handle to enqueue mux records on the shared WSS (one per SOCKS connection / stream).
#[derive(Clone)]
pub struct TcpMuxClientHandle {
    tx: mpsc::Sender<MuxWriteCmd>,
    next_stream_id: Arc<AtomicU32>,
    down: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    cfg: MuxClientConfig,
}

impl TcpMuxClientHandle {
    async fn send_record(&self, stream_id: u32, flags: u8, payload: Vec<u8>) -> anyhow::Result<()> {
        self.tx
            .send(MuxWriteCmd::Record {
                stream_id,
                flags,
                payload,
            })
            .await
            .map_err(|_| anyhow::Error::new(MuxWriterStopped))
    }

    pub async fn open_stream(
        &self,
        local: TcpStream,
        host: String,
        port: u16,
        tcp_uplink_prefix: Vec<u8>,
    ) -> Result<(), MuxOpenStreamDropped> {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (down_tx, down_rx) = mpsc::channel::<Vec<u8>>(1024);
        self.down.lock().await.insert(stream_id, down_tx);
        let open_pl = match encode_mux_open_target(&host, port) {
            Ok(p) => p,
            Err(e) => {
                self.down.lock().await.remove(&stream_id);
                return Err(MuxOpenStreamDropped { local, err: e });
            }
        };
        if let Err(e) = self.send_record(stream_id, MUX_FLAG_OPEN, open_pl).await {
            self.down.lock().await.remove(&stream_id);
            return Err(MuxOpenStreamDropped { local, err: e });
        }
        let h = self.clone();
        tokio::spawn(async move {
            if let Err(e) =
                mux_client_stream_bridge(local, stream_id, tcp_uplink_prefix, h, down_rx).await
            {
                error!("mux client stream {stream_id}: {e:#}");
            }
        });
        Ok(())
    }
}

static TCP_MUX_SESSION_GEN: AtomicU64 = AtomicU64::new(1);

/// One or more parallel client→server WSS links, each a full `MUX_OPEN` session (round-robin `open_stream`).
pub struct TcpMuxSessionPool {
    pub sessions: Arc<Mutex<Vec<(u64, TcpMuxClientHandle)>>>,
    next: AtomicUsize,
}

impl TcpMuxSessionPool {
    pub fn new_empty() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(Vec::new())),
            next: AtomicUsize::new(0),
        }
    }

    pub fn from_sessions(sessions: Vec<(u64, TcpMuxClientHandle)>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(sessions)),
            next: AtomicUsize::new(0),
        }
    }

    /// `None` if every outer WSS session has been torn down but the slot was not yet cleared.
    pub async fn pick(&self) -> Option<TcpMuxClientHandle> {
        let g = self.sessions.lock().await;
        let n = g.len();
        if n == 0 {
            return None;
        }
        let i = self.next.fetch_add(1, Ordering::Relaxed) % n;
        Some(g[i].1.clone())
    }
}

pub type TcpMuxClientSlot = Arc<tokio::sync::Mutex<Option<TcpMuxSessionPool>>>;

/// Remove one dead outer WSS; clear slot if that was the last session.
pub async fn remove_mux_session(slot: &TcpMuxClientSlot, session_id: u64) {
    let mut g = slot.lock().await;
    let Some(pool) = g.as_mut() else {
        return;
    };
    let mut v = pool.sessions.lock().await;
    let before = v.len();
    v.retain(|(id, _)| *id != session_id);
    if v.is_empty() {
        drop(v);
        *g = None;
        info!("tcp mux: all {before} session(s) ended; slot cleared for reconnect");
    } else {
        info!(
            "tcp mux session {session_id} closed; {} session(s) remain",
            v.len()
        );
    }
}

/// After WebSocket is established and `MUX_OPEN` already sent: spawn reader/writer and return handle.
pub fn spawn_tcp_mux_client<S>(
    ws: WebSocketStream<S>,
    crypto: Option<SharedCrypto>,
    mut cfg: MuxClientConfig,
    tcp_mux_slot: TcpMuxClientSlot,
    mut shutdown: watch::Receiver<bool>,
    tasks: &mut Vec<JoinHandle<()>>,
) -> (u64, TcpMuxClientHandle)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let session_id = TCP_MUX_SESSION_GEN.fetch_add(1, Ordering::Relaxed);
    let slot_w = tcp_mux_slot.clone();
    let slot_r = tcp_mux_slot;
    cfg.transport_v2 = crypto.is_some();
    let (mut ws_sink, ws_rx) = ws.split();
    let (tx, mut rx) = mpsc::channel::<MuxWriteCmd>(512);
    if cfg.dummy_interval_secs > 0 {
        let tx_d = tx.clone();
        let cfg_d = cfg.clone();
        let crypto_d = crypto.clone();
        let mut sd_d = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            mux_client_dummy_task(tx_d, cfg_d, crypto_d, sd_d).await;
        }));
    }
    let tx_reader = tx.clone();
    let down: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let down_r = down.clone();
    let crypto_w = crypto.clone();
    let crypto_r = crypto.clone();
    let cfg_w = cfg.clone();
    let cfg_r = cfg.clone();

    let mut sd_w = shutdown.clone();
    tasks.push(tokio::spawn(async move {
        let mut ping_sleep: Option<Pin<Box<tokio::time::Sleep>>> = if cfg_w.ws_ping_secs > 0 {
            Some(Box::pin(sleep(ws_ping_period_duration(
                cfg_w.ws_ping_secs,
                cfg_w.ws_ping_jitter_percent,
            ))))
        } else {
            None
        };
        let mut wire = Vec::with_capacity(cfg_w.max_ws_binary.min(256 * 1024));
        let mut rec_buf = Vec::with_capacity(cfg_w.max_ws_binary.min(256 * 1024));
        let mut client_adaptive = AdaptivePadState::default();
        let send_j = cfg_w.send_jitter();

        loop {
            if *sd_w.borrow() {
                break;
            }
            let cmd = match ping_sleep.as_mut() {
                Some(sleep_pin) => {
                    tokio::select! {
                        cmd = rx.recv() => cmd,
                        _ = sd_w.changed() => {
                            if *sd_w.borrow() {
                                break;
                            }
                            continue;
                        }
                        _ = sleep_pin.as_mut() => {
                            if ws_sink.send(Message::Ping(Bytes::new())).await.is_err() {
                                break;
                            }
                            *sleep_pin = Box::pin(sleep(ws_ping_period_duration(
                                cfg_w.ws_ping_secs,
                                cfg_w.ws_ping_jitter_percent,
                            )));
                            continue;
                        }
                    }
                }
                None => {
                    tokio::select! {
                        cmd = rx.recv() => cmd,
                        _ = sd_w.changed() => {
                            if *sd_w.borrow() {
                                break;
                            }
                            continue;
                        }
                    }
                }
            };
            let Some(first) = cmd else { break };
            let mut stop = false;
            let mut pending = Some(first);
            loop {
                let cmd = match pending.take() {
                    Some(c) => c,
                    None => match rx.try_recv() {
                        Ok(c) => c,
                        Err(_) => break,
                    },
                };
                match cmd {
                    MuxWriteCmd::Record {
                        stream_id,
                        flags,
                        payload,
                    } => {
                        rec_buf.clear();
                        write_mux_record_to(&mut rec_buf, stream_id, flags, &payload);
                        if write_padded_frame_with_mode_state(
                            &mut wire,
                            &rec_buf,
                            cfg_w.max_pad,
                            cfg_w.pad_mode,
                            Some(&mut client_adaptive),
                        )
                        .is_err()
                        {
                            stop = true;
                            break;
                        }
                        let blob: Bytes = match &crypto_w {
                            Some(c) => match c.seal_client_to_server(&wire) {
                                Ok(b) => {
                                    wire.clear();
                                    Bytes::from(b)
                                }
                                Err(e) => {
                                    error!("mux seal: {e:#}");
                                    stop = true;
                                    break;
                                }
                            },
                            None => Bytes::from(std::mem::take(&mut wire)),
                        };
                        if blob.len() > cfg_w.max_ws_binary {
                            error!("mux ws binary cap");
                            stop = true;
                            break;
                        }
                        if let Some(a) = &cfg_w.activity {
                            a.touch();
                        }
                        let bulk_c2s = flags == MUX_FLAG_DATA && !payload.is_empty();
                        if !bulk_c2s {
                            maybe_ws_send_jitter(send_j).await;
                        }
                        if ws_sink.feed(Message::Binary(blob)).await.is_err() {
                            stop = true;
                            break;
                        }
                    }
                    MuxWriteCmd::Pong(p) => {
                        if ws_sink.feed(Message::Pong(Bytes::from(p))).await.is_err() {
                            stop = true;
                            break;
                        }
                    }
                    MuxWriteCmd::RawBinary(blob) => {
                        maybe_ws_send_jitter(send_j).await;
                        if ws_sink.feed(Message::Binary(blob)).await.is_err() {
                            stop = true;
                            break;
                        }
                    }
                }
            }
            if stop {
                break;
            }
            if ws_sink.flush().await.is_err() {
                break;
            }
        }
        remove_mux_session(&slot_w, session_id).await;
    }));

    let mut sd_r = shutdown;
    tasks.push(tokio::spawn(async move {
        mux_client_reader_loop(
            ws_rx, crypto_r, cfg_r, down_r, tx_reader, session_id, slot_r, sd_r,
        )
        .await;
    }));

    let handle = TcpMuxClientHandle {
        tx,
        next_stream_id: Arc::new(AtomicU32::new(1)),
        down,
        cfg,
    };
    (session_id, handle)
}

async fn mux_client_reader_loop<S>(
    mut ws_rx: futures_util::stream::SplitStream<WebSocketStream<S>>,
    crypto: Option<SharedCrypto>,
    cfg: MuxClientConfig,
    down: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    out_tx: mpsc::Sender<MuxWriteCmd>,
    session_id: u64,
    tcp_mux_slot: TcpMuxClientSlot,
    mut shutdown: watch::Receiver<bool>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use crate::log_ratelimit::LogEvery;
    static DECODE_WARN: LogEvery = LogEvery::new(8, 64);
    let mut decode_failures: u32 = 0;
    loop {
        if *shutdown.borrow() {
            break;
        }
        let m = tokio::select! {
            m = ws_rx.next() => m,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
                continue;
            }
        };
        let Some(m) = m else {
            break;
        };
        let Ok(m) = m else { break };
        match m {
            Message::Binary(b) => {
                if b.len() > cfg.max_ws_binary.saturating_mul(4) {
                    decode_failures = decode_failures.saturating_add(1);
                    if DECODE_WARN.should_emit() {
                        warn!(
                            target: "bibavpn_mux",
                            session_id,
                            "mux client: dropping oversized binary frame"
                        );
                    }
                    if decode_failures >= 24 {
                        warn!(
                            target: "bibavpn_mux",
                            session_id,
                            "mux client: too many bad frames; closing reader"
                        );
                        break;
                    }
                    continue;
                }
                let raw = match &crypto {
                    Some(c) => match c.open_server_to_client(b.as_ref()) {
                        Ok(x) => {
                            decode_failures = 0;
                            x
                        }
                        Err(e) => {
                            decode_failures = decode_failures.saturating_add(1);
                            if DECODE_WARN.should_emit() {
                                warn!(
                                    target: "bibavpn_mux",
                                    session_id,
                                    "mux client: AEAD decrypt failed: {e:#}"
                                );
                            }
                            if decode_failures >= 24 {
                                warn!(
                                    target: "bibavpn_mux",
                                    session_id,
                                    "mux client: too many decrypt failures; closing reader"
                                );
                                break;
                            }
                            continue;
                        }
                    },
                    None => {
                        decode_failures = 0;
                        b.to_vec()
                    }
                };
                let inner = match read_padded_frame_into(raw) {
                    Ok(x) => x,
                    Err(e) => {
                        decode_failures = decode_failures.saturating_add(1);
                        if DECODE_WARN.should_emit() {
                            warn!(
                                target: "bibavpn_mux",
                                session_id,
                                "mux client: bad padded frame: {e}"
                            );
                        }
                        if decode_failures >= 24 {
                            break;
                        }
                        continue;
                    }
                };
                decode_failures = 0;
                if inner.is_empty() {
                    continue;
                }
                let Ok((sid, flags, payload)) = decode_mux_record(&inner) else {
                    decode_failures = decode_failures.saturating_add(1);
                    if decode_failures >= 24 {
                        break;
                    }
                    continue;
                };
                let act = classify_mux_flags(flags);
                if act.unknown && CLIENT_FLAGS_LOG.should_emit() {
                    warn!(
                        target: "bibavpn_mux",
                        stream_id = sid,
                        session_id,
                        "mux client: unknown flags {flags:#x}"
                    );
                }
                if act.data && !payload.is_empty() {
                    if let Some(a) = &cfg.activity {
                        a.touch();
                    }
                }
                if act.data {
                    let tx = {
                        let g = down.lock().await;
                        g.get(&sid).cloned()
                    };
                    if let Some(tx) = tx {
                        if tx.send(payload).await.is_err() {
                            down.lock().await.remove(&sid);
                        }
                    } else if !payload.is_empty() {
                        tracing::debug!(
                            target: "bibavpn_mux",
                            stream_id = sid,
                            session_id,
                            "mux client: DATA for unknown stream (dropping)"
                        );
                    }
                }
                // After DATA from the same record; `MUX_FLAG_WIN` is a no-op (no flow control).
                if act.close || act.reset {
                    down.lock().await.remove(&sid);
                }
            }
            Message::Ping(p) => {
                let _ = out_tx.send(MuxWriteCmd::Pong(p.to_vec())).await;
            }
            Message::Pong(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }
    remove_mux_session(&tcp_mux_slot, session_id).await;
}

async fn mux_client_stream_bridge(
    local: TcpStream,
    stream_id: u32,
    tcp_uplink_prefix: Vec<u8>,
    mux: TcpMuxClientHandle,
    mut down_rx: mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let (tcp_read, mut tcp_write) = local.into_split();
    let mut tcp_read = if tcp_uplink_prefix.is_empty() {
        MuxCliTcpRead::Plain(tcp_read)
    } else {
        MuxCliTcpRead::Prefixed(Prefixed {
            buf: Cursor::new(tcp_uplink_prefix),
            inner: tcp_read,
        })
    };

    let cfg = mux.cfg.clone();
    let max_chunk = crate::frame::max_tcp_payload_per_ws_message(
        cfg.transport_v2,
        cfg.decoy_max,
        cfg.max_pad,
        cfg.max_ws_binary,
    )
    .saturating_sub(9)
    .max(256);
    let read_cap = max_chunk.saturating_mul(8).min(512 * 1024).max(max_chunk);
    let mut rbuf = vec![0u8; read_cap];

    loop {
        tokio::select! {
            r = tcp_read.read(&mut rbuf) => {
                let n = r?;
                if n == 0 {
                    break;
                }
                let mut off = 0usize;
                while off < n {
                    let take = (n - off).min(max_chunk);
                    let pl = rbuf[off..off + take].to_vec();
                    mux.tx
                        .send(MuxWriteCmd::Record {
                            stream_id,
                            flags: MUX_FLAG_DATA,
                            payload: pl,
                        })
                        .await
                        .map_err(|_| anyhow::Error::new(MuxWriterStopped))?;
                    off += take;
                }
            }
            d = down_rx.recv() => {
                let Some(chunk) = d else { break };
                tcp_write.write_all(&chunk).await?;
            }
        }
    }
    let _ = mux
        .tx
        .send(MuxWriteCmd::Record {
            stream_id,
            flags: MUX_FLAG_CLOSE,
            payload: Vec::new(),
        })
        .await;
    mux.down.lock().await.remove(&stream_id);
    Ok(())
}

async fn mux_client_dummy_task(
    tx: mpsc::Sender<MuxWriteCmd>,
    cfg: MuxClientConfig,
    crypto: Option<SharedCrypto>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut wire = Vec::with_capacity(cfg.max_ws_binary.min(256 * 1024));
    loop {
        if *shutdown.borrow() {
            break;
        }
        let lo = cfg
            .dummy_interval_secs
            .saturating_mul(1)
            .saturating_div(2)
            .max(1);
        let hi = cfg
            .dummy_interval_secs
            .saturating_mul(3)
            .saturating_div(2)
            .max(lo);
        let secs = rand::thread_rng().gen_range(lo..=hi);
        tokio::select! {
            _ = sleep(Duration::from_secs(secs)) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
                continue;
            }
        }
        wire.clear();
        if write_padded_frame_with_mode(&mut wire, &[], cfg.max_pad, cfg.pad_mode).is_err() {
            continue;
        }
        let blob: Bytes = match &crypto {
            Some(c) => match c.seal_client_to_server(&wire) {
                Ok(b) => Bytes::from(b),
                Err(_) => continue,
            },
            None => Bytes::from(std::mem::take(&mut wire)),
        };
        if blob.len() > cfg.max_ws_binary {
            continue;
        }
        maybe_ws_send_jitter(cfg.send_jitter()).await;
        if tx.send(MuxWriteCmd::RawBinary(blob)).await.is_err() {
            break;
        }
    }
}

async fn mux_server_dummy_task(
    out: mpsc::Sender<Message>,
    crypto: Option<SharedCrypto>,
    max_pad: u8,
    pad_mode: PadMode,
    max_ws_binary: usize,
    ws_send_jitter: WsSendJitter,
    dummy_interval_secs: u64,
    server_out: ServerWsOutTiming,
) {
    let mut wire = Vec::with_capacity(max_ws_binary.min(256 * 1024));
    loop {
        let lo = dummy_interval_secs
            .saturating_mul(1)
            .saturating_div(2)
            .max(1);
        let hi = dummy_interval_secs
            .saturating_mul(3)
            .saturating_div(2)
            .max(lo);
        let secs = rand::thread_rng().gen_range(lo..=hi);
        sleep(Duration::from_secs(secs)).await;
        wire.clear();
        if write_padded_frame_with_mode(&mut wire, &[], max_pad, pad_mode).is_err() {
            continue;
        }
        let blob: Bytes = match &crypto {
            Some(c) => match c.seal_server_to_client(&wire) {
                Ok(b) => Bytes::from(b),
                Err(_) => continue,
            },
            None => Bytes::from(std::mem::take(&mut wire)),
        };
        if blob.len() > max_ws_binary {
            continue;
        }
        maybe_server_ack_and_rtt_mask(server_out).await;
        maybe_ws_send_jitter(ws_send_jitter).await;
        if out.send(Message::Binary(blob)).await.is_err() {
            break;
        }
    }
}

struct Prefixed {
    buf: Cursor<Vec<u8>>,
    inner: OwnedReadHalf,
}

enum MuxCliTcpRead {
    Plain(OwnedReadHalf),
    Prefixed(Prefixed),
}

impl AsyncRead for MuxCliTcpRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MuxCliTcpRead::Plain(r) => Pin::new(r).poll_read(cx, buf),
            MuxCliTcpRead::Prefixed(p) => {
                let pos = p.buf.position() as usize;
                let v = p.buf.get_ref();
                if pos < v.len() {
                    let rest = &v[pos..];
                    let n = rest.len().min(buf.remaining());
                    buf.put_slice(&rest[..n]);
                    p.buf.set_position((pos + n) as u64);
                    return Poll::Ready(Ok(()));
                }
                Pin::new(&mut p.inner).poll_read(cx, buf)
            }
        }
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn mux_record_rejects_trailing() {
        let mut v = encode_mux_record(3, MUX_FLAG_DATA, b"abc");
        v.push(9);
        assert!(decode_mux_record(&v).is_err());
    }

    #[test]
    fn mux_record_roundtrip() {
        let v = encode_mux_record(9, MUX_FLAG_OPEN, b"");
        let (sid, f, pl) = decode_mux_record(&v).unwrap();
        assert_eq!(sid, 9);
        assert_eq!(f, MUX_FLAG_OPEN);
        assert!(pl.is_empty());
    }
}

#[cfg(test)]
mod pick_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mirrors `TcpMuxSessionPool::pick` index logic (round-robin over n parallel outer WSS).
    fn rr_index(next: &AtomicUsize, n: usize) -> usize {
        next.fetch_add(1, Ordering::Relaxed) % n
    }

    #[test]
    fn round_robin_indices_cycle() {
        let next = AtomicUsize::new(0);
        let n = 3;
        let mut out = Vec::new();
        for _ in 0..9 {
            out.push(rr_index(&next, n));
        }
        assert_eq!(out, vec![0, 1, 2, 0, 1, 2, 0, 1, 2]);
    }
}

#[cfg(test)]
mod open_target_tests {
    use super::*;

    #[test]
    fn mux_open_target_domain_ipv4_ipv6() {
        for (host, port) in [
            ("example.com", 443u16),
            ("127.0.0.1", 8080),
            ("::1", 8443),
            ("2001:db8::53", 53),
        ] {
            let pl = encode_mux_open_target(host, port).unwrap();
            let (h, p) = decode_mux_open_target(&pl).unwrap();
            assert_eq!(h, host, "host {host}");
            assert_eq!(p, port, "port for {host}");
        }
    }

    #[test]
    fn mux_open_target_rejects_trailing() {
        let mut pl = encode_mux_open_target("h", 1).unwrap();
        pl.push(0);
        assert!(decode_mux_open_target(&pl).is_err());
    }

    #[test]
    fn mux_record_large_payload_roundtrip() {
        let payload = vec![0xABu8; 4096];
        let wire = encode_mux_record(99, MUX_FLAG_DATA, &payload);
        let (sid, flags, out) = decode_mux_record(&wire).unwrap();
        assert_eq!(sid, 99);
        assert_eq!(flags, MUX_FLAG_DATA);
        assert_eq!(out, payload);
    }
}

#[cfg(test)]
mod stream_epoch_tests {
    use super::*;

    fn opening(epoch: u64) -> ServerStreamState {
        ServerStreamState::Opening {
            epoch,
            buffered: Vec::new(),
            buffered_bytes: 0,
        }
    }

    #[test]
    fn state_carries_epoch() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        assert_eq!(ServerStreamState::Open { epoch: 42, tx }.epoch(), 42);
        assert_eq!(opening(9).epoch(), 9);
    }

    #[test]
    fn cleanup_only_removes_own_generation() {
        assert!(mux_cleanup_should_remove(Some(7), 7));
        assert!(!mux_cleanup_should_remove(Some(8), 7));
        assert!(!mux_cleanup_should_remove(None, 7));
    }

    #[test]
    fn old_stream_cleanup_keeps_reused_sid_entry() {
        // sid 5 was re-opened as epoch 2 after the epoch 1 stream died; the dying
        // stream's cleanup must not evict the live entry.
        let mut map: HashMap<u32, ServerStreamState> = HashMap::new();
        map.insert(5, opening(2));
        if mux_cleanup_should_remove(map.get(&5).map(|s| s.epoch()), 1) {
            map.remove(&5);
        }
        assert_eq!(map.get(&5).map(|s| s.epoch()), Some(2));
        // The current generation's own cleanup still removes it.
        if mux_cleanup_should_remove(map.get(&5).map(|s| s.epoch()), 2) {
            map.remove(&5);
        }
        assert!(map.get(&5).is_none());
    }

    #[test]
    fn duplicate_open_is_rejected_not_overwritten() {
        assert_eq!(mux_open_decision(false, 0), MuxOpenDecision::Accept);
        assert_eq!(mux_open_decision(true, 1), MuxOpenDecision::RejectDuplicate);
        // Duplicate check wins over the cap check (both answer with RST).
        assert_eq!(
            mux_open_decision(true, MUX_SERVER_MAX_STREAMS),
            MuxOpenDecision::RejectDuplicate
        );
        assert_eq!(
            mux_open_decision(false, MUX_SERVER_MAX_STREAMS),
            MuxOpenDecision::RejectMaxStreams
        );
        assert_eq!(
            mux_open_decision(false, MUX_SERVER_MAX_STREAMS - 1),
            MuxOpenDecision::Accept
        );
    }
}

#[cfg(test)]
mod flag_tests {
    use super::*;

    #[test]
    fn single_flags_classify() {
        let o = classify_mux_flags(MUX_FLAG_OPEN);
        assert!(o.open && !o.data && !o.close && !o.reset && !o.unknown);
        let d = classify_mux_flags(MUX_FLAG_DATA);
        assert!(d.data && !d.open && !d.close && !d.reset && !d.unknown);
        let c = classify_mux_flags(MUX_FLAG_CLOSE);
        assert!(c.close && !c.data && !c.reset && !c.unknown);
        let r = classify_mux_flags(MUX_FLAG_RST);
        assert!(r.reset && !r.data && !r.close && !r.unknown);
        // WIN is accepted and ignored (no flow control implemented).
        let w = classify_mux_flags(MUX_FLAG_WIN);
        assert!(!w.open && !w.data && !w.close && !w.reset && !w.unknown);
    }

    #[test]
    fn data_combined_with_close_or_rst_still_delivers() {
        let dc = classify_mux_flags(MUX_FLAG_DATA | MUX_FLAG_CLOSE);
        assert!(dc.data && dc.close && !dc.reset && !dc.unknown);
        let dr = classify_mux_flags(MUX_FLAG_DATA | MUX_FLAG_RST);
        assert!(dr.data && dr.reset && !dr.close && !dr.unknown);
    }

    #[test]
    fn unknown_bits_warn_but_keep_known_flags() {
        let d = classify_mux_flags(MUX_FLAG_DATA | 0x80);
        assert!(d.data && d.unknown);
        let z = classify_mux_flags(0);
        assert!(z.unknown && !z.open && !z.data && !z.close && !z.reset);
        let u = classify_mux_flags(0x20);
        assert!(u.unknown && !u.data && !u.close);
    }
}
