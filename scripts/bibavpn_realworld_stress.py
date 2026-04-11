#!/usr/bin/env python3
"""
Stress scenarios inspired by real apps over BibaVPN SOCKS:

- chatgpt_stream: long-lived HTTP/1.1 chunked response (token-like chunks), read via SOCKS.
- slack_ws: one WebSocket; server pushes JSON events every N seconds for the whole run (no client send).
- telegram_voip: sustained UDP echo at high packet rate (VoIP-ish; small payloads).

Default: all three run in parallel threads for --duration-sec.

Depends on bibavpn_e2e.py (same directory) for SOCKS helpers.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import bibavpn_e2e as b  # noqa: E402

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _log(msg: str) -> None:
    print(f"[stress] {msg}", flush=True)


def recv_exact(s: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise RuntimeError(f"short read: got {len(out)}/{n}")
        out += chunk
    return out


def readline_crlf(s: socket.socket, max_len: int = 65536) -> bytes:
    line = b""
    while len(line) < max_len:
        c = s.recv(1)
        if not c:
            break
        line += c
        if line.endswith(b"\r\n"):
            break
    return line


def ws_accept_key(sec_key: str) -> str:
    return base64.b64encode(hashlib.sha1((sec_key + GUID).encode()).digest()).decode()


def run_chunked_stream_server(
    host: str, port: int, stop: threading.Event, chunk_interval: float
) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    srv.settimeout(0.5)

    def handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(30.0)
            buf = b""
            while b"\r\n\r\n" not in buf and not stop.is_set():
                try:
                    d = conn.recv(4096)
                except socket.timeout:
                    continue
                if not d:
                    return
                buf += d
            if stop.is_set():
                return
            hdr = (
                b"HTTP/1.1 200 OK\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Cache-Control: no-cache\r\n"
                b"X-Test: chatgpt-stream\r\n"
                b"Connection: close\r\n\r\n"
            )
            conn.sendall(hdr)
            conn.settimeout(None)
            n = 0
            while not stop.is_set():
                piece = f"token:{n}:{time.time():.3f}\n".encode()
                chunk = f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
                conn.sendall(chunk)
                n += 1
                time.sleep(chunk_interval)
            try:
                conn.sendall(b"0\r\n\r\n")
            except OSError:
                pass
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    finally:
        srv.close()


def streaming_client_via_socks(
    proxy: Tuple[str, int],
    stream_port: int,
    duration_sec: int,
    chunk_interval: float,
) -> None:
    min_chunks = max(3, int((duration_sec / max(chunk_interval, 0.05)) * 0.75))
    _log(
        f"chatgpt_stream: chunked HTTP ~{duration_sec}s via SOCKS ->127.0.0.1:{stream_port} "
        f"(expect >= {min_chunks} chunks)"
    )
    s = b.socks5_tcp_connect(
        proxy[0], proxy[1], "127.0.0.1", stream_port, timeout=float(duration_sec) + 60.0
    )
    try:
        s.settimeout(float(duration_sec) + 90.0)
        req = (
            b"GET /stream HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Accept: text/event-stream, */*\r\n"
            b"Connection: close\r\n\r\n"
        )
        s.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(8192)
            if not d:
                raise RuntimeError("closed before headers")
            buf += d
        if b"200" not in buf.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"bad response: {buf[:120]!r}")

        chunks = 0
        end_wall = time.time() + float(duration_sec)
        while time.time() < end_wall:
            line = readline_crlf(s)
            if not line:
                raise RuntimeError("connection closed mid-chunked-body")
            if line == b"\r\n":
                continue
            try:
                sz = int(line.strip(), 16)
            except ValueError as e:
                raise RuntimeError(f"bad chunk line {line!r}") from e
            if sz == 0:
                break
            recv_exact(s, sz)
            recv_exact(s, 2)  # \r\n
            chunks += 1
        if chunks < min_chunks:
            raise RuntimeError(f"too few chunks: {chunks} < {min_chunks}")
        _log(f"chatgpt_stream OK ({chunks} chunks)")
    finally:
        try:
            s.close()
        except OSError:
            pass


def run_slack_push_ws_server(
    host: str, port: int, stop: threading.Event, push_interval: float
) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    srv.settimeout(0.5)

    def handle_client(conn: socket.socket) -> None:
        try:
            conn.settimeout(30.0)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            lines = buf.decode("latin-1").split("\r\n")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            key = headers.get("sec-websocket-key")
            if not key:
                return
            accept = ws_accept_key(key)
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "\r\n"
            )
            conn.sendall(resp.encode("latin-1"))

            def send_text(payload: bytes) -> None:
                header = bytearray([0x81])
                ln = len(payload)
                if ln < 126:
                    header.append(ln)
                elif ln < 65536:
                    header.append(126)
                    header.extend(struct.pack("!H", ln))
                else:
                    header.append(127)
                    header.extend(struct.pack("!Q", ln))
                conn.sendall(header + payload)

            n = 0
            while not stop.is_set():
                send_text(f'{{"type":"event","seq":{n},"t":{time.time():.3f}}}'.encode())
                n += 1
                t0 = time.time()
                while time.time() - t0 < push_interval and not stop.is_set():
                    time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(c,), daemon=True).start()
    finally:
        srv.close()


def _ws_send_pong(sock: socket.socket, payload: bytes) -> None:
    header = bytearray([0x8A, len(payload)])
    if len(payload) >= 126:
        raise ValueError("pong too long")
    sock.sendall(header + payload)


def _ws_read_frame(sock: socket.socket) -> Tuple[int, bytes]:
    h = recv_exact(sock, 2)
    opcode = h[0] & 0xF
    b2 = h[1]
    masked = (b2 >> 7) & 1
    ln = b2 & 0x7F
    if ln == 126:
        ln = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif ln == 127:
        ln = struct.unpack("!Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, ln)
    if masked and mask:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
    return opcode, payload


def slack_ws_client_via_socks(
    proxy: Tuple[str, int],
    ws_port: int,
    duration_sec: int,
    push_interval: float,
) -> None:
    min_events = max(2, int((duration_sec / max(push_interval, 0.5)) * 0.7))
    _log(
        f"slack_ws: server-push WebSocket ~{duration_sec}s via SOCKS ->127.0.0.1:{ws_port} "
        f"(expect >= {min_events} messages)"
    )
    s = b.socks5_tcp_connect(
        proxy[0], proxy[1], "127.0.0.1", ws_port, timeout=float(duration_sec) + 60.0
    )
    try:
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        req = (
            f"GET /socket HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(4096)
        if b"101" not in buf.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"WS upgrade failed: {buf[:200]!r}")

        end = time.time() + float(duration_sec)
        events = 0
        while time.time() < end:
            s.settimeout(min(90.0, max(15.0, end - time.time())))
            op, pl = _ws_read_frame(s)
            if op == 0x9:
                _ws_send_pong(s, pl)
            elif op == 0x1:
                events += 1
            elif op == 0x8:
                break
            elif op == 0xA:
                continue
            else:
                _log(f"slack_ws: unexpected opcode {op} len={len(pl)}")
        if events < min_events:
            raise RuntimeError(f"too few WS events: {events} < {min_events}")
        _log(f"slack_ws OK ({events} text frames)")
    finally:
        try:
            s.close()
        except OSError:
            pass


def telegram_voip_udp_via_socks(
    proxy: Tuple[str, int],
    echo_port: int,
    duration_sec: int,
    pps: float,
    max_loss_ratio: float,
) -> None:
    _log(
        f"telegram_voip: UDP ~{pps} pps for ~{duration_sec}s via SOCKS ->127.0.0.1:{echo_port} "
        f"(max loss ratio {max_loss_ratio:.0%})"
    )
    ctrl, relay = b.socks5_udp_associate(proxy[0], proxy[1], timeout=float(duration_sec) + 60.0)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(3.0)
    ok = 0
    fail = 0
    seq = 0
    interval = 1.0 / max(pps, 1.0)
    end = time.time() + float(duration_sec)
    try:
        while time.time() < end:
            pl = struct.pack("!IIH", seq, int(time.time() * 1000) & 0xFFFFFFFF, seq & 0xFFFF) + os.urandom(
                max(0, 120 - 10)
            )
            pkt = b._pack_socks_udp_header("127.0.0.1", echo_port, pl)
            udp.sendto(pkt, relay)
            try:
                raw, _ = udp.recvfrom(65535)
                _, _, body = b.parse_socks_udp_reply(raw)
                if body == pl:
                    ok += 1
                else:
                    fail += 1
            except socket.timeout:
                fail += 1
            seq += 1
            time.sleep(interval)
        total = ok + fail
        loss = fail / total if total else 1.0
        if loss > max_loss_ratio:
            raise RuntimeError(f"UDP loss ratio too high: {loss:.1%} (ok={ok} fail={fail})")
        _log(f"telegram_voip OK (ok={ok} fail={fail} loss={loss:.1%})")
    finally:
        try:
            ctrl.close()
        except OSError:
            pass
        try:
            udp.close()
        except OSError:
            pass


def pick_tcp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _, p = s.getsockname()
    s.close()
    return int(p)


def main() -> int:
    ap = argparse.ArgumentParser(description="Real-world-ish BibaVPN stress tests")
    ap.add_argument("--socks-host", default=os.environ.get("BIBAVPN_SOCKS_HOST", "127.0.0.1"))
    ap.add_argument("--socks-port", type=int, default=int(os.environ.get("BIBAVPN_SOCKS_PORT", "11080")))
    ap.add_argument("--duration-sec", type=int, default=int(os.environ.get("BIBAVPN_LONG_SECS", "300")))
    ap.add_argument("--chunk-interval", type=float, default=0.25, help="Chunked HTTP: seconds between chunks")
    ap.add_argument("--slack-interval", type=float, default=4.0, help="Seconds between server WS pushes")
    ap.add_argument("--voip-pps", type=float, default=20.0, help="UDP packets per second")
    ap.add_argument(
        "--max-udp-loss",
        type=float,
        default=0.22,
        help="Allowed UDP loss ratio (parallel TCP/WS adds contention)",
    )
    ap.add_argument("--sequential", action="store_true", help="Run scenarios one after another")
    ap.add_argument("--only", action="append", choices=("stream", "slack", "voip"), help="Repeatable")
    args = ap.parse_args()
    proxy = (args.socks_host, args.socks_port)
    duration = max(5, args.duration_sec)

    only: Optional[List[str]] = args.only if args.only else None

    stop = threading.Event()
    stream_port = pick_tcp_port()
    ws_port = pick_tcp_port()
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    udp_port = int(udp_sock.getsockname()[1])

    t_stream = threading.Thread(
        target=run_chunked_stream_server,
        args=("127.0.0.1", stream_port, stop, args.chunk_interval),
        daemon=True,
    )
    t_slack = threading.Thread(
        target=run_slack_push_ws_server,
        args=("127.0.0.1", ws_port, stop, args.slack_interval),
        daemon=True,
    )
    t_udp = threading.Thread(target=b.run_udp_echo_server, args=(udp_sock, stop), daemon=True)
    t_stream.start()
    t_slack.start()
    t_udp.start()
    time.sleep(0.25)

    errs: List[BaseException] = []
    err_lock = threading.Lock()

    def want(name: str) -> bool:
        return only is None or name in only

    try:

        def run_stream() -> None:
            if want("stream"):
                streaming_client_via_socks(proxy, stream_port, duration, args.chunk_interval)

        def run_slack() -> None:
            if want("slack"):
                slack_ws_client_via_socks(proxy, ws_port, duration, args.slack_interval)

        def run_voip() -> None:
            if want("voip"):
                telegram_voip_udp_via_socks(
                    proxy, udp_port, duration, args.voip_pps, args.max_udp_loss
                )

        def record_exc(e: BaseException) -> None:
            with err_lock:
                errs.append(e)

        if args.sequential:
            for fn in (run_stream, run_slack, run_voip):
                try:
                    fn()
                except BaseException as e:
                    record_exc(e)
        else:
            threads: List[threading.Thread] = []

            def wrap(f) -> None:
                try:
                    f()
                except BaseException as e:
                    record_exc(e)

            for fn in (run_stream, run_slack, run_voip):
                th = threading.Thread(target=wrap, args=(fn,), daemon=True)
                threads.append(th)
                th.start()
            join_deadline = time.time() + float(duration) + 180.0
            for th in threads:
                remaining = max(0.1, join_deadline - time.time())
                th.join(timeout=remaining)
                if th.is_alive():
                    record_exc(RuntimeError(f"thread {th.name!r} still alive after deadline"))

        if errs:
            for e in errs:
                _log(f"FAILED: {e}")
            return 1
        _log("ALL STRESS SCENARIOS PASSED")
        return 0
    finally:
        stop.set()
        time.sleep(0.4)


if __name__ == "__main__":
    raise SystemExit(main())
