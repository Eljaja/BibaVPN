#!/usr/bin/env python3
"""Speedtest via SOCKS5 (e.g. bibavpn). Deps: pip install speedtest-cli pysocks"""
import argparse
import socket
import sys

import socks


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--socks-host", default="127.0.0.1")
    p.add_argument("--socks-port", type=int, default=11090)
    args = p.parse_args()

    socks.set_default_proxy(socks.SOCKS5, args.socks_host, args.socks_port)
    socket.socket = socks.socksocket  # type: ignore[misc, assignment]

    import speedtest

    print(f"Speedtest via SOCKS5 {args.socks_host}:{args.socks_port} ...", flush=True)
    st = speedtest.Speedtest(secure=True)
    st.get_best_server()
    srv = st.results.server
    print(
        "Server:",
        srv.get("sponsor", ""),
        srv.get("name", ""),
        flush=True,
    )
    print("Download ...", flush=True)
    d = st.download()
    print(f"Download: {d / 1e6:.2f} Mbit/s", flush=True)
    print("Upload ...", flush=True)
    u = st.upload()
    print(f"Upload:   {u / 1e6:.2f} Mbit/s", flush=True)
    print(f"Ping:     {st.results.ping:.0f} ms", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
