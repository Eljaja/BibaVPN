//! Long-term design: multiplex many logical TCP streams over **one** long-lived WSS (and thus one TLS session).
//!
//! ## Motivation
//!
//! Today each tunneled TCP connection uses a separate `OPEN` → `bridge_ws_tcp_padded` pair, so the
//! client opens **N concurrent TLS+WebSocket handshakes** to the same front. DPI and traffic
//! analytics often flag “many parallel TLS sessions to one host” as non-browser-like. A **stream
//! mux** collapses that to a single outer connection with logical sub-streams inside the binary
//! framing layer (after padding / optional BibaV2), similar in spirit to HTTP/2 or SSH multiplexing
//! but over the existing Biba wire format.
//!
//! ## Sketch protocol (not implemented)
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
//! This module is documentation-only; implementing it is a **breaking protocol change** and should
//! ship with version negotiation and a staged rollout (legacy `OPEN` + new mux on same path).
