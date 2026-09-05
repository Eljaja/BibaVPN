# Second performance pass

Baseline: `fbf682b` (the first throughput PR). Buffer candidate: `ab292cf`.
Configurable-window candidate: `3aac4b0`. All measurements use release builds;
they compare these commits, not the older production image.

## Credit-window experiment

Each sample transfers exactly 32 MiB through SOCKS, TLS, WebSocket and mux.
A transparent Python proxy delays application bytes by 10/25/50 ms in each
direction, using separate bounded reader/writer queues. Three samples per
combination; values below are median Mbit/s, including HTTPS connection setup.
Stopping the tunnel server must make a subsequent SOCKS request fail with zero
payload bytes. All nine combinations passed this negative control.

| Added round-trip application delay | 1 MiB window | 2 MiB window | 4 MiB window |
| ---: | ---: | ---: | ---: |
| 20 ms | 334.33 | 662.06 | 1,197.32 |
| 50 ms | 148.83 | 282.06 | 501.06 |
| 100 ms | 76.75 | 144.01 | 261.48 |

This demonstrates the mux credit-window limit and its configurability. It
**does not emulate TCP packet loss, congestion control or kernel ACK timing**:
the proxy terminates TCP on each side and delays the encrypted application
bytes. `netem` was unavailable in this host kernel. These are not VPS speeds.
Python scheduling, proxy buffering and transfer setup also affect the results.

The default remains 1 MiB. Client and server each advertise their own receive
window; changing the client's window primarily affects downloads, and changing
the server's primarily affects uploads. The peer's setting governs send credit.
Each WSS retains a 64 MiB logical receive budget and a 128 MiB DATA backing bound,
plus separately bounded staging/output/metadata. Admission is 64/32/21/16 streams
for windows of 1/2/3/4 MiB. Larger windows are an explicit capacity tradeoff.

## Buffer and RNG measurements

The fused path removes the intermediate mux-record and padded-frame payload
copies. It still copies from the read scratch into the queued command payload,
then once into the final encrypted frame. It is not an end-to-end zero-copy
transport. Incoming uniquely owned buffers are reused; sliced buffers may need
a normalizing move, shared/static buffers may need a copy, and oversized backing
still triggers compaction before queue admission.

`cargo run --release -p bibavpn --example mux_pipeline_bench` compares the old
serialization sequence with the new fused sequence using the same current RNG
and actual production modules. Five-run median improvements were 2.9%, 5.0%
and 6.1% for 1,400-, 16,384- and 65,536-byte inputs. Both paths allocate twice per
frame in this workload: queued payload and final wire; the old intermediate
scratch allocations are reused. Raw output: `pipeline-microbench.txt`.

The public seal-only benchmark, run three times against frozen before/after
binaries, improved from 4,657.5 to 5,641.3 Mbit/s at 1,400 bytes (about 21%).
It remained around 16 Gbit/s at 64 KiB. Both versions already allocate once
per seal. This isolates crypto/framing work, not network throughput.

Full transfers inside a private Docker network gave these medians:

| Workload | Baseline Gbit/s | Buffer candidate Gbit/s |
| --- | ---: | ---: |
| 256 MiB, default frame cap, decoys off | 6.274 | 6.183 |
| 64 MiB, 1,400-byte cap, decoys off | 2.083 | 2.074 |
| 64 MiB, 1,400-byte cap, decoy max 32 | 1.985 | 2.020 |

These small, overlapping samples establish **no material full-tunnel speedup
from the buffer changes alone**. The CPU microbenchmark improvements must not
be presented as equivalent network gains. Direct origin samples are retained
alongside mux samples; every transfer validates HTTP status and exact bytes.

## Reproduction

The adjacent Python scripts are Linux lab fixtures, not production services.
They require Docker with cached `python:3.12-slim`, Python 3, curl and openssl.
They generate independent test credentials/certificates, use uniquely named
containers/networks, validate transfers and clean their own resources.

`container-bench.py` runs the origin, server and client in the private Docker
network with no published ports. On Linux x86_64 it mounts `/usr/bin/curl` and
`/lib/x86_64-linux-gnu` read-only into the client container, using the host loader
for curl. This avoids the workstation's variable host-loopback packet filtering.
It does not change host routing or firewall settings.

```sh
BENCH_CLIENT=/absolute/path/to/bibavpn-client \
BENCH_SERVER=/absolute/path/to/bibavpn-server \
BENCH_LABEL=candidate python3 benchmarks/2026-09-06-stage2/container-bench.py
```

Optional environment settings: `BENCH_BYTES` (default 256 MiB), `BENCH_REPEATS`
(3), `BENCH_FRAME` (262144), `BENCH_DECOY` (0), and `BENCH_WINDOW` (omitted).
Set `BENCH_FRAME=1400 BENCH_DECOY=32 BENCH_BYTES=67108864` for the small-frame
decoy workload. Use separately saved release binaries for before/after runs.

For the application-delay experiment, both fixture files must remain together:

```sh
DELAY_MS=50 BENCH_WINDOW=4 python3 benchmarks/2026-09-06-stage2/delay-bench.py \
  --client /absolute/path/to/bibavpn-client \
  --server /absolute/path/to/bibavpn-server \
  --bytes 33554432 --repeats 3 --origin-mss 1200 \
  --client-arg=--mux-window-mib --client-arg=4
```

`DELAY_MS` is per direction. `BENCH_WINDOW` sets the test server; client
arguments set the client. The optional MSS affects only the temporary HTTPS
origin socket. The private origin hostname resolves only server-side, and
SOCKS requests explicitly disable `NO_PROXY` bypass. Setup records include
client-listener readiness and full HTTPS readiness separately where measured.

## VPS and concurrent startup verification

At `e293028`, one 64 MiB download reached 87.64 Mbit/s with defaults and
89.68 Mbit/s with `--mux-window-mib 4 --ws-parallel 4` on the client and a
4 MiB server window. Direct HTTPS immediately afterward reached 89.28 Mbit/s.
The earlier first-pass baseline median was 85.47 Mbit/s (three runs); direct
before was 87.38 Mbit/s. These observations show no material WAN gain beyond
the available path speed. All transfers completed exact byte counts; no OOM.
The VPS production container and configuration were left unchanged.

With four WSS sessions and 100 ms added round-trip application delay, local
listener readiness changed from 1.508 to 0.605 seconds; full HTTPS readiness
from 1.7352 to 0.8847 seconds. Each is one startup sample, not a distribution.
This checks first-ready startup; it does not measure reconnect reliability.

Final review found and fixed a startup race: concurrent callers queued behind
background session creation now wake as soon as the first pool is published.
The regression test passes; `cargo test -p bibavpn` passes 303 tests and
`cargo test -p biba --locked` passes 5 tests. Release build, proto smoke and
Docker Compose smoke pass (the latter on retry after an initial curl52).
Independent final review approved the fix. Existing unrelated lint warnings
remain. The measurements above precede this narrowly scoped startup fix.

Final `ec74db0` release verification on the isolated VPS completed 64 MiB at
88.67 Mbit/s with four WSS and 4 MiB windows. This is one verification
sample. Test containers, network and remote directory were removed; the
production container was confirmed running afterward.
