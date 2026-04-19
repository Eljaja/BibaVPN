#!/usr/bin/env python3
"""
TCP behavior metrics from a PCAP (lab helper for BibaVPN outer TLS port).

Focus: duration, volume, uplink/downlink asymmetry, outer-connection churn (flow count).
Requires scapy. Tested with captures from `tcpdump -i any`.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Any

from scapy.all import IP, Raw, TCP, rdpcap


@dataclass
class FlowStats:
    flow_id: int
    client: str
    server: str
    t_first: float
    t_last: float
    payload_c2s: int
    payload_s2c: int
    pkts_c2s: int
    pkts_s2c: int

    @property
    def duration_sec(self) -> float:
        return max(0.0, self.t_last - self.t_first)

    @property
    def total_payload(self) -> int:
        return self.payload_c2s + self.payload_s2c

    @property
    def asymmetry_ratio(self) -> float | None:
        """max(uplink,downlink)/min(...); None if min is 0."""
        a, b = self.payload_c2s, self.payload_s2c
        if a == 0 and b == 0:
            return None
        lo, hi = (a, b) if a <= b else (b, a)
        if lo == 0:
            return None
        return hi / lo


def _flow_key(pkt: Any, srv_port: int) -> tuple[str, int, str, int] | None:
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None
    ip = pkt[IP]
    tcp = pkt[TCP]
    if int(tcp.dport) == srv_port:
        return (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
    if int(tcp.sport) == srv_port:
        return (ip.dst, int(tcp.dport), ip.src, int(tcp.sport))
    return None


def _payload_len(pkt: Any) -> int:
    if not pkt.haslayer(Raw):
        return 0
    return len(bytes(pkt[Raw].load))


def analyze(pcap_path: str, srv_port: int) -> dict[str, Any]:
    pkts = rdpcap(pcap_path)
    flows: dict[tuple[str, int, str, int], list[Any]] = defaultdict(list)
    for p in pkts:
        k = _flow_key(p, srv_port)
        if k is None:
            continue
        flows[k].append(p)

    stats: list[FlowStats] = []
    for i, (k, plist) in enumerate(sorted(flows.items(), key=lambda x: min(float(p.time) for p in x[1]))):
        client_ip, client_port, server_ip, server_port = k
        t_first = min(float(p.time) for p in plist)
        t_last = max(float(p.time) for p in plist)
        c2s_b = c2s_n = s2c_b = s2c_n = 0
        for p in plist:
            if not p.haslayer(IP) or not p.haslayer(TCP):
                continue
            ip = p[IP]
            tcp = p[TCP]
            plen = _payload_len(p)
            if plen == 0:
                continue
            if ip.src == client_ip and int(tcp.sport) == client_port:
                c2s_b += plen
                c2s_n += 1
            elif ip.src == server_ip and int(tcp.sport) == server_port:
                s2c_b += plen
                s2c_n += 1
        stats.append(
            FlowStats(
                flow_id=i + 1,
                client=f"{client_ip}:{client_port}",
                server=f"{server_ip}:{server_port}",
                t_first=t_first,
                t_last=t_last,
                payload_c2s=c2s_b,
                payload_s2c=s2c_b,
                pkts_c2s=c2s_n,
                pkts_s2c=s2c_n,
            )
        )

    wall_first = min((s.t_first for s in stats), default=0.0)
    wall_last = max((s.t_last for s in stats), default=0.0)
    sum_c2s = sum(s.payload_c2s for s in stats)
    sum_s2c = sum(s.payload_s2c for s in stats)

    return {
        "pcap": pcap_path,
        "server_port": srv_port,
        "flow_count": len(stats),
        "wall_duration_sec": max(0.0, wall_last - wall_first),
        "total_payload_c2s": sum_c2s,
        "total_payload_s2c": sum_s2c,
        "flows": [asdict(s) | {"duration_sec": s.duration_sec, "asymmetry_ratio": s.asymmetry_ratio} for s in stats],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Behavior-oriented TCP stats for a single server port.")
    ap.add_argument("pcap")
    ap.add_argument("port", type=int)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    r = analyze(args.pcap, args.port)
    if args.json:
        print(json.dumps(r, indent=2))
        return 0
    print(f"pcap={r['pcap']} port={r['server_port']}")
    print(f"flows={r['flow_count']} wall_duration_s={r['wall_duration_sec']:.3f}")
    print(
        f"total_payload_c2s={r['total_payload_c2s']} total_payload_s2c={r['total_payload_s2c']} "
        f"ratio_s2c_c2s={(r['total_payload_s2c'] / r['total_payload_c2s']) if r['total_payload_c2s'] else 'n/a'}"
    )
    for s in r["flows"]:
        print(
            f"  flow {s['flow_id']} {s['client']} -> {s['server']} "
            f"dur={s['duration_sec']:.3f}s "
            f"c2s={s['payload_c2s']}B/{s['pkts_c2s']}pkts "
            f"s2c={s['payload_s2c']}B/{s['pkts_s2c']}pkts "
            f"asym={s['asymmetry_ratio']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
