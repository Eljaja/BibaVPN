//! Multiplex many TCP streams over one WebSocket (after `MUX_OPEN_MAGIC`).

use std::collections::HashMap;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::Context;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{error, info, warn};

use crate::crypto_layer::SessionCrypto;
use crate::frame::PadMode;
use crate::protocol::encode_atyp_host_port;
use crate::retry::{maybe_ws_binary_send_jitter, ws_ping_period_duration};
use crate::ws_bridge::TunnelEnd;
use crate::{read_padded_frame, write_padded_frame_with_mode};

pub type SharedCrypto = Arc<SessionCrypto>;

pub const MUX_OPEN_MAGIC: &[u8] = b"BIBA\x01MUXO\x00";

pub const MUX_FLAG_OPEN: u8 = 0x01;
pub const MUX_FLAG_DATA: u8 = 0x02;
pub const MUX_FLAG_CLOSE: u8 = 0x04;
pub const MUX_FLAG_RST: u8 = 0x08;
pub const MUX_FLAG_WIN: u8 = 0x10;

pub const MUX_INITIAL_WINDOW: u32 = 1024 * 1024;

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
    if data.len() < 9 + plen {
        anyhow::bail!("truncated mux payload");
    }
    Ok((stream_id, flags, data[9..9 + plen].to_vec()))
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

enum ServerStreamState {
    Opening {
        buffered: Vec<Vec<u8>>,
        buffered_bytes: usize,
    },
    Open(mpsc::Sender<Vec<u8>>),
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
    pad_mode: PadMode,
    dummy_interval_secs: u64,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
        tokio::spawn(mux_server_dummy_task(
            ws_dummy_srv,
            crypto_dummy_srv,
            max_pad,
            pad_mode,
            max_ws_binary,
            ws_binary_send_jitter_ms,
            dummy_interval_secs,
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

    let up = async move {
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
                            .await
                            .context("v2 open c2s mux")?,
                        (None, _) => b.to_vec(),
                    };
                    let inner = read_padded_frame(&raw).map_err(|e| anyhow::anyhow!("{e}"))?;
                    if inner.is_empty() {
                        continue;
                    }
                    let (sid, flags, payload) = decode_mux_record(&inner)?;
                    match flags {
                        MUX_FLAG_OPEN => {
                            let permit = sem
                                .clone()
                                .acquire_owned()
                                .await
                                .map_err(|_| anyhow::anyhow!("mux sem"))?;
                            let (host, port) = match decode_mux_open_target(&payload) {
                                Ok(x) => x,
                                Err(e) => {
                                    error!("mux open target: {e:#}");
                                    let _ = permit;
                                    continue;
                                }
                            };
                            {
                                let mut map = streams.lock().await;
                                if map.len() >= MUX_SERVER_MAX_STREAMS {
                                    let _ = permit;
                                    warn!("mux: max streams");
                                    let _ = mux_server_send_record(
                                        &ws_out_srv,
                                        sid,
                                        MUX_FLAG_RST,
                                        &[],
                                        max_pad,
                                        pad_mode,
                                        &crypto,
                                        max_ws_binary,
                                        ws_binary_send_jitter_ms,
                                    )
                                    .await;
                                    continue;
                                }
                                map.insert(
                                    sid,
                                    ServerStreamState::Opening {
                                        buffered: Vec::new(),
                                        buffered_bytes: 0,
                                    },
                                );
                            }
                            let ws_tx = ws_out_srv.clone();
                            let streams_open = streams.clone();
                            let crypto_clone = crypto.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let remote = match tokio::time::timeout(
                                    Duration::from_secs(10),
                                    TcpStream::connect((host.as_str(), port)),
                                )
                                .await
                                {
                                    Ok(Ok(t)) => t,
                                    Ok(Err(e)) => {
                                        error!("mux connect {host}:{port}: {e:#}");
                                        streams_open.lock().await.remove(&sid);
                                        let _ = mux_server_send_record(
                                            &ws_tx,
                                            sid,
                                            MUX_FLAG_RST,
                                            &[],
                                            max_pad,
                                            pad_mode,
                                            &crypto_clone,
                                            max_ws_binary,
                                            ws_binary_send_jitter_ms,
                                        )
                                        .await;
                                        return;
                                    }
                                    Err(_) => {
                                        error!("mux connect {host}:{port}: timeout 10s");
                                        streams_open.lock().await.remove(&sid);
                                        let _ = mux_server_send_record(
                                            &ws_tx,
                                            sid,
                                            MUX_FLAG_RST,
                                            &[],
                                            max_pad,
                                            pad_mode,
                                            &crypto_clone,
                                            max_ws_binary,
                                            ws_binary_send_jitter_ms,
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
                                        Some(ServerStreamState::Opening { buffered, .. }) => {
                                            g.insert(sid, ServerStreamState::Open(wtx.clone()));
                                            buffered
                                        }
                                        Some(ServerStreamState::Open(_)) | None => return,
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
                                    streams_write.lock().await.remove(&sid);
                                });
                                for data in pending {
                                    if wtx.send(data).await.is_err() {
                                        streams_open.lock().await.remove(&sid);
                                        return;
                                    }
                                }
                                if let Err(e) = mux_server_stream_read_loop(
                                    sid,
                                    r,
                                    ws_tx,
                                    streams_open,
                                    max_pad,
                                    pad_mode,
                                    crypto_clone,
                                    max_ws_binary,
                                    ws_binary_send_jitter_ms,
                                    max_chunk,
                                )
                                .await
                                {
                                    error!("mux read sid {sid}: {e:#}");
                                }
                            });
                        }
                        MUX_FLAG_DATA => {
                            let mut maybe_tx = None;
                            let mut payload_opt = Some(payload);
                            let mut rst = false;
                            {
                                let mut g = streams.lock().await;
                                match g.get_mut(&sid) {
                                    Some(ServerStreamState::Open(tx)) => {
                                        maybe_tx = Some(tx.clone());
                                    }
                                    Some(ServerStreamState::Opening {
                                        buffered,
                                        buffered_bytes,
                                    }) => {
                                        let payload_len =
                                            payload_opt.as_ref().map(|p| p.len()).unwrap_or(0);
                                        if buffered_bytes.saturating_add(payload_len)
                                            > MUX_PENDING_OPEN_BYTES
                                        {
                                            g.remove(&sid);
                                            rst = true;
                                        } else {
                                            *buffered_bytes += payload_len;
                                            buffered
                                                .push(payload_opt.take().expect("payload present"));
                                        }
                                    }
                                    None => {}
                                }
                            }
                            if let Some(tx) = maybe_tx {
                                if tx
                                    .send(payload_opt.expect("payload present"))
                                    .await
                                    .is_err()
                                {
                                    streams.lock().await.remove(&sid);
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
                                    ws_binary_send_jitter_ms,
                                )
                                .await;
                            };
                        }
                        MUX_FLAG_CLOSE | MUX_FLAG_RST => {
                            streams.lock().await.remove(&sid);
                        }
                        MUX_FLAG_WIN => {}
                        _ => warn!("mux: unknown flags {flags:#x}"),
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
    ws_binary_send_jitter_ms: u8,
) -> anyhow::Result<()> {
    let mut wire = Vec::with_capacity(max_ws_binary.min(256 * 1024));
    let mut rec_buf = Vec::with_capacity(payload.len() + 9);
    write_mux_record_to(&mut rec_buf, sid, flags, payload);
    write_padded_frame_with_mode(&mut wire, &rec_buf, max_pad, pad_mode).context("mux pad")?;
    let blob: Bytes = match crypto {
        Some(c) => Bytes::from(
            c.seal_server_to_client(&wire)
                .await
                .context("v2 seal s2c mux")?,
        ),
        None => Bytes::from(std::mem::take(&mut wire)),
    };
    if blob.len() > max_ws_binary {
        anyhow::bail!("mux ws binary too large");
    }
    maybe_ws_binary_send_jitter(ws_binary_send_jitter_ms).await;
    ws_out
        .send(Message::Binary(blob))
        .await
        .context("mux ws queue")?;
    Ok(())
}

async fn mux_server_stream_read_loop(
    sid: u32,
    mut tcp_read: OwnedReadHalf,
    ws_out: mpsc::Sender<Message>,
    streams: Arc<Mutex<HashMap<u32, ServerStreamState>>>,
    max_pad: u8,
    pad_mode: PadMode,
    crypto: Option<SharedCrypto>,
    max_ws_binary: usize,
    ws_binary_send_jitter_ms: u8,
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
                ws_binary_send_jitter_ms,
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
        ws_binary_send_jitter_ms,
    )
    .await;
    streams.lock().await.remove(&sid);
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
    /// BibaV2 AEAD outer framing (set from `spawn_tcp_mux_client`).
    pub transport_v2: bool,
    pub pad_mode: PadMode,
    /// Idle empty padded frames on the shared mux WSS (0 = off).
    pub dummy_interval_secs: u64,
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
            .map_err(|_| anyhow::anyhow!("tcp mux writer stopped"))
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

/// When the outer WSS reader or writer task ends, drop the app-wide mux handle so the next SOCKS session opens a new WSS.
pub(crate) async fn clear_tcp_mux_slot_if_current(
    slot: &Arc<tokio::sync::Mutex<Option<(u64, TcpMuxClientHandle)>>>,
    session_id: u64,
) {
    let mut g = slot.lock().await;
    if let Some((id, _)) = *g {
        if id == session_id {
            *g = None;
            info!("tcp mux session {session_id} closed; slot cleared for reconnect");
        }
    }
}

/// After WebSocket is established and `MUX_OPEN` already sent: spawn reader/writer and return handle.
pub fn spawn_tcp_mux_client<S>(
    ws: WebSocketStream<S>,
    crypto: Option<SharedCrypto>,
    mut cfg: MuxClientConfig,
    tcp_mux_slot: Arc<tokio::sync::Mutex<Option<(u64, TcpMuxClientHandle)>>>,
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
        tokio::spawn(mux_client_dummy_task(tx_d, cfg_d, crypto_d));
    }
    let tx_reader = tx.clone();
    let down: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let down_r = down.clone();
    let crypto_w = crypto.clone();
    let crypto_r = crypto.clone();
    let cfg_w = cfg.clone();
    let cfg_r = cfg.clone();

    tokio::spawn(async move {
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

        loop {
            let cmd = match ping_sleep.as_mut() {
                Some(sleep_pin) => {
                    tokio::select! {
                        cmd = rx.recv() => cmd,
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
                None => rx.recv().await,
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
                        if write_padded_frame_with_mode(
                            &mut wire,
                            &rec_buf,
                            cfg_w.max_pad,
                            cfg_w.pad_mode,
                        )
                        .is_err()
                        {
                            stop = true;
                            break;
                        }
                        let blob: Bytes = match &crypto_w {
                            Some(c) => match c.seal_client_to_server(&wire).await {
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
        clear_tcp_mux_slot_if_current(&slot_w, session_id).await;
    });

    tokio::spawn(mux_client_reader_loop(
        ws_rx, crypto_r, cfg_r, down_r, tx_reader, session_id, slot_r,
    ));

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
    tcp_mux_slot: Arc<Mutex<Option<(u64, TcpMuxClientHandle)>>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    while let Some(m) = ws_rx.next().await {
        let Ok(m) = m else { break };
        match m {
            Message::Binary(b) => {
                if b.len() > cfg.max_ws_binary.saturating_mul(4) {
                    continue;
                }
                let raw = match &crypto {
                    Some(c) => match c.open_server_to_client(b.as_ref()).await {
                        Ok(x) => x,
                        Err(_) => continue,
                    },
                    None => b.to_vec(),
                };
                let inner = match read_padded_frame(&raw) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                if inner.is_empty() {
                    continue;
                }
                let Ok((sid, flags, payload)) = decode_mux_record(&inner) else {
                    continue;
                };
                match flags {
                    MUX_FLAG_DATA => {
                        let tx = {
                            let g = down.lock().await;
                            g.get(&sid).cloned()
                        };
                        if let Some(tx) = tx {
                            if tx.try_send(payload).is_err() {
                                down.lock().await.remove(&sid);
                            }
                        }
                    }
                    MUX_FLAG_CLOSE | MUX_FLAG_RST => {
                        down.lock().await.remove(&sid);
                    }
                    _ => {}
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
    clear_tcp_mux_slot_if_current(&tcp_mux_slot, session_id).await;
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
                        .map_err(|_| anyhow::anyhow!("mux writer stopped"))?;
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
) {
    let mut wire = Vec::with_capacity(cfg.max_ws_binary.min(256 * 1024));
    loop {
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
        sleep(Duration::from_secs(secs)).await;
        wire.clear();
        if write_padded_frame_with_mode(&mut wire, &[], cfg.max_pad, cfg.pad_mode).is_err() {
            continue;
        }
        let blob: Bytes = match &crypto {
            Some(c) => match c.seal_client_to_server(&wire).await {
                Ok(b) => Bytes::from(b),
                Err(_) => continue,
            },
            None => Bytes::from(std::mem::take(&mut wire)),
        };
        if blob.len() > cfg.max_ws_binary {
            continue;
        }
        maybe_ws_binary_send_jitter(cfg.ws_binary_send_jitter_ms).await;
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
    ws_binary_send_jitter_ms: u8,
    dummy_interval_secs: u64,
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
            Some(c) => match c.seal_server_to_client(&wire).await {
                Ok(b) => Bytes::from(b),
                Err(_) => continue,
            },
            None => Bytes::from(std::mem::take(&mut wire)),
        };
        if blob.len() > max_ws_binary {
            continue;
        }
        maybe_ws_binary_send_jitter(ws_binary_send_jitter_ms).await;
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
