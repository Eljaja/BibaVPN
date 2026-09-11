#!/usr/bin/env python3
"""Local regression: new proxy requests survive a full mux session.

Run after cargo build -p bibavpn --bins:
    python3 bibavpn/tests/mux_capacity.py target/debug
"""
import argparse
import contextlib
import os
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def receive(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        assert part, f"connection closed after {len(data)}/{count} bytes"
        data += part
    return data


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


@contextlib.contextmanager
def process(args, log):
    with log.open("wb") as output:
        child = subprocess.Popen(args, stdout=output, stderr=output,
                                 env={**os.environ, "RUST_LOG": "info", "NO_COLOR": "1"})
        try:
            yield child
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def ready(port, child):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert child.poll() is None, "test process exited before listening"
        try:
            with socket.create_connection(("127.0.0.1", port), 0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("test listener did not start")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", type=Path)
    args = parser.parse_args()
    binaries = args.binaries.resolve()
    with tempfile.TemporaryDirectory(prefix="biba-capacity-test-") as temporary:
        logs = Path(temporary)
        with contextlib.ExitStack() as stack:
            echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
            echo.daemon_threads = True
            stack.callback(echo.server_close)
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            stack.callback(echo.shutdown)
            server_port, socks_port, http_port = (free_port() for _ in range(3))
            token, psk = secrets.token_hex(32), secrets.token_hex(32)
            server = stack.enter_context(process([
                str(binaries / "bibavpn-server"), "--listen", f"127.0.0.1:{server_port}",
                "--self-signed-san", "localhost", "--token", token, "--psk", psk,
            ], logs / "server.log"))
            ready(server_port, server)
            client = stack.enter_context(process([
                str(binaries / "bibavpn-client"), "--server", f"127.0.0.1:{server_port}",
                "--sni", "localhost", "--insecure", "--token", token, "--psk", psk,
                "--socks5", f"127.0.0.1:{socks_port}",
                "--http-proxy", f"127.0.0.1:{http_port}", "--ws-parallel", "1",
            ], logs / "client.log"))
            ready(socks_port, client)
            # libc resolves this abbreviated IPv4 locally; the proxy sees a domain,
            # avoiding its intentional direct bypass for literal private addresses.
            target = "127.1"
            target_port = echo.server_address[1]

            def connect_socks():
                sock = stack.enter_context(socket.create_connection(("127.0.0.1", socks_port), 5))
                sock.sendall(b"\x05\x01\x00")
                assert receive(sock, 2) == b"\x05\x00"
                host = target.encode()
                sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", target_port))
                assert receive(sock, 10)[1] == 0
                return sock

            held = []
            for index in range(64):
                sock = connect_socks()
                sock.sendall(b"held")
                assert receive(sock, 4) == b"held", f"stream {index + 1}"
                held.append(sock)
            client_log = re.sub(r"\x1b\[[0-9;]*m", "", (logs / "client.log").read_text())
            assert "credit_negotiated=true" in client_log, client_log[-2000:]
            print("64 mux streams held open", flush=True)
            for kind in ("HTTP CONNECT", "SOCKS"):
                if kind == "SOCKS":
                    sock = connect_socks()
                else:
                    sock = stack.enter_context(socket.create_connection(("127.0.0.1", http_port), 5))
                    sock.sendall(f"CONNECT {target}:{target_port} HTTP/1.1\r\nHost: {target}:{target_port}\r\n\r\n".encode())
                    header = b""
                    while not header.endswith(b"\r\n\r\n"):
                        header += receive(sock, 1)
                    assert b"200" in header.split(b"\r\n")[0]
                sock.sendall(b"overflow")
                assert receive(sock, 8) == b"overflow", kind
                print(f"{kind} overflow request succeeded", flush=True)
            forward = stack.enter_context(socket.create_connection(("127.0.0.1", http_port), 5))
            forward.sendall(f"GET http://{target}:{target_port}/prefetch HTTP/1.1\r\nHost: {target}:{target_port}\r\n\r\n".encode())
            request_line = b"GET /prefetch HTTP/1.1\r\n"
            received = receive(forward, len(request_line))
            assert received == request_line, received
            print("HTTP forward preserved its request prefix", flush=True)
            for sock in held:
                sock.sendall(b"still alive")
                assert receive(sock, 11) == b"still alive"
            print("Original 64 streams remain usable", flush=True)


if __name__ == "__main__":
    main()
