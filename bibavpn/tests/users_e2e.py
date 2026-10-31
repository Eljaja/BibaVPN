#!/usr/bin/env python3
"""Exercise live multi-user authentication, session limits and registry reload."""
import contextlib
import json
import secrets
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

from mux_capacity import Echo, free_port, process, ready, receive


def connect(socks_port, target_port):
    sock = socket.create_connection(("127.0.0.1", socks_port), 3)
    sock.settimeout(3)
    sock.sendall(b"\x05\x01\x00")
    assert receive(sock, 2) == b"\x05\x00"
    host = b"127.1"
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", target_port))
    assert receive(sock, 10)[1] == 0
    sock.sendall(b"probe")
    assert receive(sock, 5) == b"probe"
    return sock


def rejected(socks_port, target_port):
    try:
        sock = connect(socks_port, target_port)
    except (OSError, AssertionError):
        return True
    else:
        sock.close()
        return False


def main():
    binaries = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="bibavpn-users-e2e-") as temp, contextlib.ExitStack() as stack:
        root = Path(temp)
        echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        echo.daemon_threads = True
        stack.callback(echo.server_close)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        stack.callback(echo.shutdown)
        target = echo.server_address[1]
        server_port = free_port()
        alice, bob, psk = (secrets.token_hex(32) for _ in range(3))
        users = {"users": [
            {"label": "alice", "token": alice, "enabled": True, "max_concurrent": 1},
            {"label": "bob", "token": bob, "enabled": True, "max_concurrent": 1},
        ]}
        registry = root / "users.json"
        registry.write_text(json.dumps(users))
        server = stack.enter_context(process([
            str(binaries / "bibavpn-server"), "--listen", f"127.0.0.1:{server_port}",
            "--self-signed-san", "localhost", "--users-file", str(registry), "--psk", psk,
            "--no-auth-rate-limit",
        ], root / "server.log"))
        ready(server_port, server)

        def client(token, label):
            port = free_port()
            child = stack.enter_context(process([
                str(binaries / "bibavpn-client"), "--server", f"127.0.0.1:{server_port}",
                "--sni", "localhost", "--insecure", "--token", token, "--psk", psk,
                "--socks5", f"127.0.0.1:{port}", "--no-mux",
            ], root / f"{label}.log"))
            ready(port, child)
            return port

        alice_port, bob_port = client(alice, "alice"), client(bob, "bob")
        held = stack.enter_context(connect(alice_port, target))
        assert rejected(alice_port, target), "alice exceeded her session limit"
        bob_sock = stack.enter_context(connect(bob_port, target))
        users["users"][0]["enabled"] = False
        # Match the administration tool's atomic replacement.
        replacement = root / "replacement.json"
        replacement.write_text(json.dumps(users))
        replacement.replace(registry)
        assert rejected(alice_port, target), "disabled alice connected"
        held.sendall(b"alive")
        assert receive(held, 5) == b"alive", "disable unexpectedly ended an existing session"
        held.close()
        assert rejected(alice_port, target), "disabled alice reconnected after closing her session"
        users["users"][0]["enabled"] = True
        replacement.write_text(json.dumps(users))
        replacement.replace(registry)
        deadline = time.monotonic() + 5
        while True:
            try:
                restored = connect(alice_port, target)
                restored.close()
                break
            except (OSError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        bob_sock.sendall(b"alive")
        assert receive(bob_sock, 5) == b"alive"
        print("user isolation, session limit, live disable and enable: OK")


if __name__ == "__main__":
    main()
