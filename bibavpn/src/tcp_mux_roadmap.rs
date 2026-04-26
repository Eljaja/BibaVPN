//! Historical design note: one outer WSS carrying many logical TCP streams.
//!
//! > **Current code:** see [`tcp_mux`](crate::tcp_mux) — `MUX_OPEN`, stream IDs, flow control, and
//! > optional **1..=4** parallel outer WSS links (`--ws-parallel`, `TcpMuxSessionPool` round-robin).
//! > The sections below are an **older sketch**; the wire and tasks differ from this document.
//!
//! ## Motivation (historical)
//!
//! A previous concern was: each tunneled TCP using a separate WSS would mean **N TLS+WebSocket
//! handshakes** to the same front. A **stream mux** was proposed: **one** outer connection with
//! logical sub-streams in the Biba framing, similar in spirit to HTTP/2 over one TLS socket.
//!
//! ## Sketch protocol (superseded on the wire by `tcp_mux` + `MUX_OPEN`)
//!
//! - **Outer channel**: unchanged TLS + WSS + optional `HELLO`/`ACK` PSK; first binary after
//!   upgrade is either today’s `OPEN` (legacy) or a new `MUX_OPEN` capability advertisement.
//! - **Control vs data**: small fixed header on each inner frame, e.g. `stream_id: u32`, `flags`,
//!   `length`, then payload. Reuse `write_padded_frame` / AEAD on the **mux record** or per-stream
//!   records (design choice: one AEAD stream vs per-substream keys).
//! - **Lifecycle**: `STREAM_OPEN { id, host, port }` (server performs `connect`), `STREAM_DATA`,
//!   `STREAM_WIN` (flow control), `STREAM_RST` / `STREAM_CLOSE`. Map SOCKS `CONNECT` and HTTP
//!   CONNECT to allocating a `stream_id` on the single mux instead of a new WSS.
//! - **UDP mux**: can remain a separate outer WSS or later ride as `STREAM_DGRAM` / dedicated mux
//!   channel; today’s `UDP_MUX_OPEN` per-datagram server sockets stay valid as a simpler path.
//!
//! ## Server / migration
//!
//! - **Server** (`bibavpn-server`): after first message dispatch, branch on `OPEN` vs `MUX_OPEN`;
//!   mux mode runs one `bridge_ws_tcp_mux_server` task with a `HashMap<StreamId, TcpStream>` (or
//!   bounded pool). Backpressure and fairness need explicit limits (`max_streams`, per-stream
//!   buffers).
//! - **Client** (`local_client` module): SOCKS accept loop allocates `stream_id` from mux handle;
//!   reconnect must replay or resume streams (hard problem) — v1 mux can treat reconnect as “all
//!   streams reset” like today’s full tunnel loss.
//!
//! This file remains **documentation-only** for the old one-WSS design. Do not treat it as the live
//! mux spec — use `PROTOCOL.md` and `tcp_mux.rs` / `local_client` for the implemented path
//! (`--no-mux` legacy `OPEN` vs mux).
