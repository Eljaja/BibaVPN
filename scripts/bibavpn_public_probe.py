#!/usr/bin/env python3
"""
SOCKS5 probes that work when bibavpn-server is remote: targets must be reachable
from the *server* exit (public Internet), not 127.0.0.1 on the test machine.

Uses: HTTP chunked-ish drip from httpbin, DNS UDP to Cloudflare, short TCP fetches.
Stdlib only; reuses bibavpn_e2e SOCKS helpers.
"""
from __future__ import annotations

import argparse
import os
import random
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import List, Tuple

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import bibavpn_e2e as b  # noqa: E402


def _log(msg: str) -> None:
    print(f"[probe] {msg}", flush=True)


def recv_until(s: socket.socket, n: int, timeout: float) -> bytes:
    s.settimeout(timeout)
    out = b""
    while len(out) < n:
        chunk = s.recv(min(65536, n - len(out)))
        if not chunk:
            break
        out += chunk
    return out


def probe_http_drip(
    proxy: Tuple[str, int],
    drip_sec: int,
    numbytes: int,
    connect_timeout: float,
    read_timeout: float,
    min_body_ratio: float = 0.72,
) -> None:
    """httpbin /drip — body arrives gradually (streaming-ish over one TCP connection)."""
    host = "httpbin.org"
    _log(f"HTTP drip: {host}:80 drip {drip_sec}s ~{numbytes}B via SOCKS (real exit path)")
    s = b.socks5_tcp_connect(proxy[0], proxy[1], host, 80, timeout=connect_timeout)
    try:
        req = (
            f"GET /drip?duration={drip_sec}&numbytes={numbytes}&code=200&delay=0.05 "
            f"HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        ).encode()
        s.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(8192)
            if len(buf) > 262144:
                raise RuntimeError("headers too long / no end")
        if b"200" not in buf.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"bad status: {buf[:120]!r}")
        # body follows; read at least most of numbytes
        body = buf.split(b"\r\n\r\n", 1)[1]
        deadline = time.time() + drip_sec + 45.0
        need = numbytes * min_body_ratio
        while len(body) < need and time.time() < deadline:
            s.settimeout(read_timeout)
            more = s.recv(65536)
            if not more:
                break
            body += more
        if len(body) < need:
            raise RuntimeError(f"drip short read: {len(body)} < {int(need)}")
        _log(f"HTTP drip OK ({len(body)} bytes body)")
    finally:
        s.close()


def build_dns_query(domain: str) -> bytes:
    tid = random.randint(1, 65535)
    flags = 0x0100
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b""
    for part in domain.encode("ascii").split(b"."):
        qname += bytes([len(part)]) + part
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def probe_dns_udp(
    proxy: Tuple[str, int],
    dns_ip: str,
    queries: int,
    timeout_per: float,
) -> None:
    _log(f"DNS UDP: {queries}x A? one.one.one.one -> {dns_ip}:53 via SOCKS")
    ctrl, relay = b.socks5_udp_associate(proxy[0], proxy[1], timeout=30.0)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout_per)
    pkt = build_dns_query("one.one.one.one")
    ok = 0
    try:
        for _ in range(queries):
            frame = b._pack_socks_udp_header(dns_ip, 53, pkt)
            udp.sendto(frame, relay)
            try:
                raw, _ = udp.recvfrom(65535)
                _, _, body = b.parse_socks_udp_reply(raw)
                if len(body) > 12 and body[:2] == pkt[:2]:
                    ok += 1
            except socket.timeout:
                pass
        if ok < max(1, int(queries * 0.6)):
            raise RuntimeError(f"DNS too few replies: {ok}/{queries}")
        _log(f"DNS UDP OK ({ok}/{queries})")
    finally:
        try:
            ctrl.close()
        except OSError:
            pass
        udp.close()


def probe_short_tcp_fetches(proxy: Tuple[str, int], n: int, timeout: float) -> None:
    host = "example.com"
    _log(f"short TCP x{n}: {host}:80 via SOCKS")
    for i in range(n):
        s = b.socks5_tcp_connect(proxy[0], proxy[1], host, 80, timeout=timeout)
        try:
            s.settimeout(timeout)
            s.sendall(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            )
            data = recv_until(s, 512, timeout)
            if b"Example" not in data and b"example" not in data.lower():
                raise RuntimeError(f"unexpected response #{i}: {data[:80]!r}")
        finally:
            s.close()
    _log("short TCP OK")


def probe_longish_idle_then_byte(
    proxy: Tuple[str, int], idle_sec: float, connect_timeout: float
) -> None:
    """One TCP connection, idle, then one read (drip with long initial delay)."""
    host = "httpbin.org"
    delay_ms = int(max(1000, idle_sec * 1000))
    numbytes = 64
    _log(f"idle+read: httpbin delay={delay_ms}ms then {numbytes}B via SOCKS")
    s = b.socks5_tcp_connect(proxy[0], proxy[1], host, 80, timeout=connect_timeout)
    try:
        req = (
            f"GET /drip?duration=1&numbytes={numbytes}&code=200&delay={delay_ms / 1000.0} "
            f"HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode()
        s.sendall(req)
        buf = b""
        s.settimeout(idle_sec + 60.0)
        while b"\r\n\r\n" not in buf:
            buf += s.recv(4096)
        body = buf.split(b"\r\n\r\n", 1)[1]
        while len(body) < numbytes * 0.8:
            chunk = s.recv(4096)
            if not chunk:
                break
            body += chunk
        if len(body) < numbytes * 0.5:
            raise RuntimeError(f"idle drip short: got {len(body)}")
        _log("idle+read OK")
    finally:
        s.close()


def run_parallel_stress(
    proxy: Tuple[str, int],
    sec: int,
    connect_timeout: float,
    read_timeout: float,
) -> None:
    """HTTP drip + DNS + repeated short TCP concurrently (mixed load)."""
    _log(f"parallel stress ~{sec}s (drip + DNS + short TCP)")
    errs: List[BaseException] = []
    lock = threading.Lock()

    def record(e: BaseException) -> None:
        with lock:
            errs.append(e)

    def drip_worker() -> None:
        try:
            # httpbin often truncates very long drips; cap bytes and effective rate.
            eff = min(float(sec), 120.0)
            nb = max(10_000, min(55_000, int(eff * 600)))
            probe_http_drip(
                proxy,
                sec,
                nb,
                connect_timeout,
                read_timeout,
                min_body_ratio=0.34,
            )
        except BaseException as e:
            record(e)

    def dns_worker() -> None:
        try:
            probe_dns_udp(
                proxy, "1.1.1.1", max(20, min(150, sec * 2)), 8.0
            )
        except BaseException as e:
            record(e)

    def tcp_worker() -> None:
        try:
            end = time.time() + float(sec)
            per_op = min(75.0, max(30.0, connect_timeout * 0.25))
            while time.time() < end:
                with lock:
                    if errs:
                        return
                probe_short_tcp_fetches(proxy, 2, per_op)
                time.sleep(1.25)
        except BaseException as e:
            record(e)

    threads = [
        threading.Thread(target=drip_worker, daemon=True),
        threading.Thread(target=dns_worker, daemon=True),
        threading.Thread(target=tcp_worker, daemon=True),
    ]
    for t in threads:
        t.start()
    join_until = time.time() + float(sec) + 360.0
    for t in threads:
        remaining = max(1.0, join_until - time.time())
        t.join(timeout=remaining)
        if t.is_alive():
            record(RuntimeError(f"stress thread still alive: {t.name!r}"))
    if errs:
        raise errs[0]


def main() -> int:
    ap = argparse.ArgumentParser(description="Public-Internet SOCKS probes (remote VPN exit)")
    ap.add_argument("--socks-host", default=os.environ.get("BIBAVPN_SOCKS_HOST", "127.0.0.1"))
    ap.add_argument("--socks-port", type=int, default=int(os.environ.get("BIBAVPN_SOCKS_PORT", "11781")))
    ap.add_argument("--drip-sec", type=int, default=25, help="httpbin drip duration")
    ap.add_argument("--drip-bytes", type=int, default=12000)
    ap.add_argument("--dns-queries", type=int, default=15)
    ap.add_argument("--short-fetches", type=int, default=12)
    ap.add_argument("--idle-sec", type=float, default=15.0)
    ap.add_argument(
        "--connect-timeout",
        type=float,
        default=float(os.environ.get("BIBAVPN_CONNECT_TIMEOUT", "180")),
    )
    ap.add_argument("--read-timeout", type=float, default=30.0)
    ap.add_argument(
        "--parallel-sec",
        type=int,
        default=0,
        help="After sequential probes, run mixed parallel load for N seconds (0=skip)",
    )
    args = ap.parse_args()
    proxy = (args.socks_host, args.socks_port)

    try:
        probe_short_tcp_fetches(proxy, args.short_fetches, args.connect_timeout)
        probe_dns_udp(proxy, "1.1.1.1", args.dns_queries, min(15.0, args.read_timeout))
        probe_http_drip(
            proxy,
            args.drip_sec,
            args.drip_bytes,
            args.connect_timeout,
            args.read_timeout,
        )
        probe_longish_idle_then_byte(proxy, args.idle_sec, args.connect_timeout)
        if args.parallel_sec > 0:
            run_parallel_stress(
                proxy, args.parallel_sec, args.connect_timeout, args.read_timeout
            )
        _log("ALL PUBLIC PROBES PASSED")
        return 0
    except Exception as e:
        _log(f"FAILED: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
