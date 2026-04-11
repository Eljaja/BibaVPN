#!/usr/bin/env python3
"""
End-to-end checks for BibaVPN: traffic through SOCKS5 after bibavpn-client is running.

Tests: TCP bulk echo, TCP after long idle, many short TCP round-trips, UDP echo,
optional WebSocket ping-pong (chat-like long-lived TCP + framed messages).

Requires Python 3.9+ (stdlib only).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
import secrets
import socket
import struct
import threading
import time
from typing import Optional, Tuple

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _log(msg: str) -> None:
    print(f"[e2e] {msg}", flush=True)


def socks5_tcp_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 30.0,
) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_host, proxy_port))
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 method negotiation failed")

    # BUILD CONNECT request: VER CMD RSV ATYP ADDR PORT
    host_b = dest_host.encode("ascii")
    if len(host_b) > 255:
        raise ValueError("host too long for SOCKS5 domain ATYP")
    req = bytearray([5, 1, 0, 3, len(host_b)])
    req.extend(host_b)
    req.extend(struct.pack("!H", dest_port))
    s.sendall(req)
    resp = s.recv(10)
    if len(resp) < 10 or resp[1] != 0:
        raise RuntimeError(f"SOCKS5 CONNECT failed: {resp!r}")
    return s


def _pack_socks_udp_header(dest_host: str, dest_port: int, payload: bytes) -> bytes:
    """RSV+FRAG+ATYP+ADDR+PORT+payload (matches bibavpn protocol::build_socks5_udp_datagram)."""
    out = bytearray([0, 0, 0])
    try:
        ip = socket.inet_pton(socket.AF_INET, dest_host)
        out.append(1)
        out.extend(ip)
    except OSError:
        try:
            ip = socket.inet_pton(socket.AF_INET6, dest_host)
            out.append(4)
            out.extend(ip)
        except OSError:
            b = dest_host.encode("utf-8")
            if len(b) > 255:
                raise ValueError("domain too long")
            out.append(3)
            out.append(len(b))
            out.extend(b)
    out.extend(struct.pack("!H", dest_port))
    out.extend(payload)
    return bytes(out)


def socks5_udp_associate(
    proxy_host: str, proxy_port: int, timeout: float = 30.0
) -> Tuple[socket.socket, Tuple[str, int]]:
    """Returns (control_tcp, (relay_ip, relay_port)) for UDP datagrams."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((proxy_host, proxy_port))
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 method negotiation failed")
    # UDP ASSOCIATE: VER CMD RSV ATYP DST.ADDR DST.PORT (0.0.0.0:0)
    s.sendall(bytes([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
    hdr = s.recv(4)
    if len(hdr) < 4:
        raise RuntimeError("short SOCKS5 UDP ASSOCIATE reply")
    if hdr[0] != 5 or hdr[1] != 0:
        raise RuntimeError(f"SOCKS5 UDP ASSOCIATE failed: {hdr!r}")
    atyp = hdr[3]
    if atyp == 1:
        rest = s.recv(6)
        ip = socket.inet_ntop(socket.AF_INET, rest[:4])
        rport = struct.unpack("!H", rest[4:6])[0]
    elif atyp == 3:
        ln_b = s.recv(1)
        ln = ln_b[0]
        rest = s.recv(ln + 2)
        ip = rest[:ln].decode("utf-8")
        rport = struct.unpack("!H", rest[ln : ln + 2])[0]
    elif atyp == 4:
        rest = s.recv(18)
        ip = socket.inet_ntop(socket.AF_INET6, rest[:16])
        rport = struct.unpack("!H", rest[16:18])[0]
    else:
        raise RuntimeError(f"bad ATYP {atyp}")
    relay_ip = ip
    if relay_ip in ("0.0.0.0", "::"):
        relay_ip = proxy_host
    return s, (relay_ip, rport)


def parse_socks_udp_reply(data: bytes) -> Tuple[str, int, bytes]:
    if len(data) < 4 or data[0] != 0 or data[1] != 0 or data[2] != 0:
        raise ValueError("bad SOCKS UDP header")
    body = data[3:]
    off = 0
    at = body[off]
    off += 1
    if at == 1:
        host = socket.inet_ntop(socket.AF_INET, body[off : off + 4])
        off += 4
    elif at == 3:
        ln = body[off]
        off += 1
        host = body[off : off + ln].decode("utf-8")
        off += ln
    elif at == 4:
        host = socket.inet_ntop(socket.AF_INET6, body[off : off + 16])
        off += 16
    else:
        raise ValueError(f"ATYP {at}")
    port = struct.unpack("!H", body[off : off + 2])[0]
    off += 2
    return host, port, body[off:]


def run_tcp_echo_server(host: str, port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(32)
    srv.settimeout(0.5)

    def handle(c: socket.socket) -> None:
        try:
            c.settimeout(120.0)
            while not stop.is_set():
                try:
                    d = c.recv(65536)
                except socket.timeout:
                    continue
                if not d:
                    break
                c.sendall(d)
        finally:
            try:
                c.close()
            except OSError:
                pass

    try:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    finally:
        srv.close()


def run_udp_echo_server(u: socket.socket, stop: threading.Event) -> None:
    """`u` must already be bound (e.g. host + port 0)."""
    u.settimeout(0.5)
    try:
        while not stop.is_set():
            try:
                data, addr = u.recvfrom(65535)
            except socket.timeout:
                continue
            u.sendto(data, addr)
    finally:
        try:
            u.close()
        except OSError:
            pass


def ws_accept_key(sec_key: str) -> str:
    return base64.b64encode(hashlib.sha1((sec_key + GUID).encode()).digest()).decode()


def run_ws_echo_server(host: str, port: int, stop: threading.Event) -> None:
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
            head, _, _ = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
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

            def read_frame() -> Optional[Tuple[int, bytes]]:
                h = conn.recv(2)
                if len(h) < 2:
                    return None
                b2 = h[1]
                masked = (b2 >> 7) & 1
                ln = b2 & 0x7F
                if ln == 126:
                    e = conn.recv(2)
                    ln = struct.unpack("!H", e)[0]
                elif ln == 127:
                    e = conn.recv(8)
                    ln = struct.unpack("!Q", e)[0]
                mask = conn.recv(4) if masked else b""
                payload = conn.recv(ln) if ln else b""
                if masked and mask:
                    payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
                opcode = h[0] & 0xF
                return opcode, payload

            def send_text(payload: bytes) -> None:
                # server → client unmasked
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

            while not stop.is_set():
                r = read_frame()
                if r is None:
                    break
                op, pl = r
                if op == 8:
                    break
                if op == 1 or op == 2:
                    send_text(pl)
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


def ws_client_over_tcp(sock: socket.socket, messages: int) -> None:
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    req = (
        f"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += sock.recv(4096)
    if b"101" not in buf.split(b"\r\n", 1)[0]:
        raise RuntimeError(f"WS upgrade failed: {buf[:200]!r}")

    def send_masked_text(payload: bytes) -> None:
        mask = secrets.token_bytes(4)
        masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
        header = bytearray([0x81, 0x80 | len(payload)])
        if len(payload) >= 126:
            raise ValueError("payload too long for this test")
        sock.sendall(header + mask + masked)

    def read_text_frame() -> bytes:
        h = sock.recv(2)
        if len(h) < 2:
            return b""
        b2 = h[1]
        masked = (b2 >> 7) & 1
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack("!H", sock.recv(2))[0]
        elif ln == 127:
            ln = struct.unpack("!Q", sock.recv(8))[0]
        mask = sock.recv(4) if masked else b""
        payload = sock.recv(ln)
        if masked and mask:
            payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
        return payload

    for i in range(messages):
        msg = f"chat-{i}-{random.randint(0, 1_000_000)}".encode()
        send_masked_text(msg)
        got = read_text_frame()
        if got != msg:
            raise RuntimeError(f"WS echo mismatch: {got!r} vs {msg!r}")


def test_tcp_bulk(
    proxy: Tuple[str, int], echo_port: int, nbytes: int
) -> None:
    _log(f"TCP bulk: {nbytes} bytes via SOCKS ->127.0.0.1:{echo_port}")
    s = socks5_tcp_connect(proxy[0], proxy[1], "127.0.0.1", echo_port)
    try:
        s.settimeout(60.0)
        data = os.urandom(nbytes)
        s.sendall(data)
        got = b""
        while len(got) < nbytes:
            chunk = s.recv(min(65536, nbytes - len(got)))
            if not chunk:
                raise RuntimeError("short read")
            got += chunk
        if got != data:
            raise RuntimeError("TCP bulk payload mismatch")
    finally:
        s.close()
    _log("TCP bulk OK")


def test_tcp_idle(
    proxy: Tuple[str, int], echo_port: int, idle_secs: float
) -> None:
    _log(f"TCP long idle: {idle_secs}s then echo byte")
    s = socks5_tcp_connect(proxy[0], proxy[1], "127.0.0.1", echo_port)
    try:
        s.settimeout(idle_secs + 30.0)
        time.sleep(idle_secs)
        s.sendall(b"Z")
        assert s.recv(1) == b"Z"
    finally:
        s.close()
    _log("TCP idle OK")


def test_tcp_many_short(proxy: Tuple[str, int], echo_port: int, n: int) -> None:
    _log(f"TCP many short round-trips: {n}")
    for i in range(n):
        s = socks5_tcp_connect(proxy[0], proxy[1], "127.0.0.1", echo_port, timeout=15.0)
        try:
            s.settimeout(15.0)
            p = struct.pack("!I", i)
            s.sendall(p)
            assert s.recv(4) == p
        finally:
            s.close()
    _log("TCP many short OK")


def test_udp_echo(
    proxy: Tuple[str, int], echo_port: int, payloads: int
) -> None:
    _log(f"UDP echo: {payloads} datagrams -> 127.0.0.1:{echo_port}")
    ctrl, relay = socks5_udp_associate(proxy[0], proxy[1])
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(30.0)
        for _ in range(payloads):
            pl = os.urandom(random.randint(32, 1400))
            pkt = _pack_socks_udp_header("127.0.0.1", echo_port, pl)
            udp.sendto(pkt, relay)
            raw, _ = udp.recvfrom(65535)
            _, _, body = parse_socks_udp_reply(raw)
            if body != pl:
                raise RuntimeError("UDP body mismatch")
    finally:
        try:
            ctrl.close()
        except OSError:
            pass
        try:
            udp.close()
        except OSError:
            pass
    _log("UDP echo OK")


def test_ws_chat(proxy: Tuple[str, int], ws_port: int, rounds: int) -> None:
    _log(f"WebSocket chat-like: {rounds} messages via SOCKS")
    s = socks5_tcp_connect(proxy[0], proxy[1], "127.0.0.1", ws_port)
    try:
        s.settimeout(60.0)
        ws_client_over_tcp(s, rounds)
    finally:
        s.close()
    _log("WebSocket OK")


def pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _, p = s.getsockname()
    s.close()
    return int(p)


def main() -> int:
    ap = argparse.ArgumentParser(description="BibaVPN SOCKS e2e tests")
    ap.add_argument("--socks-host", default=os.environ.get("BIBAVPN_SOCKS_HOST", "127.0.0.1"))
    ap.add_argument("--socks-port", type=int, default=int(os.environ.get("BIBAVPN_SOCKS_PORT", "11080")))
    ap.add_argument("--tcp-bytes", type=int, default=512 * 1024)
    ap.add_argument("--idle-secs", type=float, default=12.0)
    ap.add_argument("--short-count", type=int, default=40)
    ap.add_argument("--udp-datagrams", type=int, default=25)
    ap.add_argument("--ws-rounds", type=int, default=15)
    ap.add_argument("--skip-ws", action="store_true")
    args = ap.parse_args()
    proxy = (args.socks_host, args.socks_port)

    stop = threading.Event()
    tcp_port = pick_port()
    ws_port = pick_port()
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))
    udp_port = int(udp_sock.getsockname()[1])

    t_tcp = threading.Thread(
        target=run_tcp_echo_server, args=("127.0.0.1", tcp_port, stop), daemon=True
    )
    t_udp = threading.Thread(
        target=run_udp_echo_server, args=(udp_sock, stop), daemon=True
    )
    t_ws = threading.Thread(
        target=run_ws_echo_server, args=("127.0.0.1", ws_port, stop), daemon=True
    )
    t_tcp.start()
    t_udp.start()
    t_ws.start()
    time.sleep(0.2)

    try:
        test_tcp_bulk(proxy, tcp_port, args.tcp_bytes)
        test_tcp_idle(proxy, tcp_port, args.idle_secs)
        test_tcp_many_short(proxy, tcp_port, args.short_count)
        test_udp_echo(proxy, udp_port, args.udp_datagrams)
        if not args.skip_ws:
            test_ws_chat(proxy, ws_port, args.ws_rounds)
        _log("ALL TESTS PASSED")
        return 0
    except Exception as e:
        _log(f"FAILED: {e}")
        return 1
    finally:
        stop.set()
        time.sleep(0.3)


if __name__ == "__main__":
    raise SystemExit(main())
