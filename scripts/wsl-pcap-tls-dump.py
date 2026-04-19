#!/usr/bin/env python3
"""Quick TLS ClientHello summary from a pcap (lab helper; requires scapy)."""
from __future__ import annotations

import sys

from scapy.all import IP, Raw, TCP, rdpcap
from scapy.layers.tls.extensions import TLS_Ext_ALPN, TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("usage: wsl-pcap-tls-dump.py <file.pcap> [dport]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    dport = int(sys.argv[2]) if len(sys.argv) == 3 else 18443
    pkts = rdpcap(path)
    found: list[tuple[float, TLSClientHello]] = []
    for p in pkts:
        if not p.haslayer(TCP) or not p.haslayer(Raw):
            continue
        tcp = p[TCP]
        if tcp.dport != dport:
            continue
        load = bytes(p[Raw].load)
        try:
            t = TLS(load) if TLS not in p else p[TLS]
        except Exception:
            continue
        if not t.haslayer(TLSClientHello):
            continue
        ch = t[TLSClientHello]
        found.append((float(p.time), ch))

    print(f"packets={len(pkts)} client_hellos_to_{dport}={len(found)}")
    for ts, ch in found[:5]:
        print("--- ClientHello ---")
        print("  time", ts)
        print("  version", getattr(ch, "version", None))
        ciphers = ch.ciphers
        print("  cipher_count", len(ciphers) if ciphers is not None else 0)
        sni_val = None
        alpn_val = None
        for e in ch.ext or []:
            if e.haslayer(TLS_Ext_ServerName):
                sn = e[TLS_Ext_ServerName]
                names = getattr(sn, "servernames", None) or []
                sni_val = [bytes(x.servername).decode("utf-8", "replace") for x in names]
            if e.haslayer(TLS_Ext_ALPN):
                ap = e[TLS_Ext_ALPN]
                protos = getattr(ap, "protocols", None) or getattr(ap, "alpn_proto", None) or []
                if protos and isinstance(protos[0], (bytes, bytearray)):
                    alpn_val = [bytes(p).decode("utf-8", "replace") for p in protos]
                else:
                    alpn_val = [
                        bytes(x.protocol).decode("utf-8", "replace") for x in protos
                    ]
        print("  SNI", sni_val)
        print("  ALPN", alpn_val)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
