#!/usr/bin/env bash
# Zapret cannot be linked into bibavpn binaries: it needs Linux netfilter/NFQUEUE or OpenWrt.
# Typical setup: run nfqws/tpws on the router (see ../zapret in this mono-repo), then route
# browsers through bibavpn-client SOCKS, or terminate WSS on a VPS and forward to the open web.
#
# Example only — tune nfqws flags for your ISP (https://github.com/bol-van/zapret docs).
#
# export IFACE=eth0
# /path/to/zapret/nfq/nfqws --qnum=200 --filter-tcp=80 --dpi-desync=fake ...
# iptables -t mangle -A POSTROUTING -o "$IFACE" -p tcp --dport 443 -j NFQUEUE --queue-num 200
echo "Copy and adapt this script on Linux/OpenWrt; see zapret/docs/readme.en.md"
