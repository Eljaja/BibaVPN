# Mux throughput and isolation measurements

Baseline: `b369b21`. Transport candidate: `de8ae93` (negotiated byte
credits, independent stream pumps, buffer changes). Intermediate mux-only
rows use `f8db4f6`. Measurements are small samples from one Linux workstation
and one shared, single-vCPU VPS; they are not universal performance promises.

## Results

| Measurement | Baseline | Candidate |
| --- | ---: | ---: |
| Local Docker mux, median of three 64 MiB transfers | 4.983 Gbit/s | 5.455 Gbit/s |
| Public AEAD seal allocations per frame | about 3.97 | 1.00 |
| VPS mux, median of three 64 MiB transfers | 88.41 Mbit/s | 84.35 Mbit/s |
| Same-WSS 64 KiB request while another download stops reading | timeout after 8.01 s, zero bytes | success in 0.265 s |
| Client RSS during that stalled-download probe | 133,480 KiB | 8,900 KiB |

The local throughput difference is about 9.5%, with overlapping ranges and
short samples. The VPS results **do not establish a throughput improvement**:
direct HTTPS was 87.00 Mbit/s before and 86.74 Mbit/s after, and the host's
other workload changed during the experiment. Candidate results ranged
81.14–86.89 Mbit/s. Four concurrent streams on one WSS completed at
86.96 Mbit/s aggregate. The demonstrated benefits are stalled-stream
isolation, bounded buffering, and reduced allocation cost.

Old-client/new-server and new-client/old-server each transferred the full
64 MiB. A new client also transferred 64 MiB through a separate container
using the production image (revision `5c3af36`); the production container
was not modified.

After the configuration fixes (`cb0b57d`, transport unchanged), the final
release pair transferred 64 MiB on the VPS at 86.86 Mbit/s (`final-config-build`
in `vps.json`). This is a verification sample, not another three-run comparison.

## Method

- Release binaries were frozen separately for before/after runs. No production
  token, PSK, hostname or IP is present in these artifacts.
- Local test: separate Docker server and Python HTTPS origin, a private Docker
  DNS alias, ephemeral localhost ports, pinned temporary certificate, one WSS,
  262,144-byte frame ceiling, 64-byte maximum padding, 32-byte maximum decoy,
  adaptive padding. Direct requests use the same origin. `NO_PROXY` is disabled
  for SOCKS requests. Every successful sample contains exactly 64 MiB.
- The origin hostname resolves only inside the Docker network. Stopping the
  tunnel server makes the SOCKS request fail (negative control, curl exit 28);
  it cannot silently become a direct download.
- VPS: separate server/origin containers and private network with synthetic data
  and independent credentials. HTTPS origin and tunnel ports were separate from
  production. Client cap and server cap were both 262,144 bytes. Ordinary
  transfers use one WSS; the four-stream sample uses four 16 MiB transfers on
  that same WSS. CPU percentages are process CPU time divided by wall time;
  they include startup/measurement noise and are not capacity estimates.
- Stalled test: start a 1 GiB HTTPS response over SOCKS with a 4 KiB socket
  receive buffer, read one byte, then stop reading for 35 seconds. Attempt a
  separate 64 KiB HTTPS response through the same client/WSS with an 8-second
  timeout. RSS is a process snapshot, not a peak-memory measurement.
- Existing local packet-filter software was left unchanged. One intermediate
  **direct** sample failed with zero bytes and was excluded; it is not included
  in either before/after median. Failed transfers must never count as throughput.

The maintained `scripts/wsl-local-bench.sh` reproduces the local topology and
negative control; use its help for binary overrides and sample sizes. The raw
local files here came from its precursor harness with the same topology.
The maintained harness completed a separate 64 MiB direct/mux/negative-control
run with `--origin-mss 1200`. A later direct 64 MiB run timed out even with
that fixture option; it was reported as a failure, not a throughput sample.
The optional MSS setting therefore does not eliminate local filter variability.

## AEAD-only microbenchmark

`cargo run --release -p bibavpn --example crypto_alloc_bench` counts global
allocator calls during public `seal_client_to_server` loops. Each size seals
approximately 256 MiB; the table gives medians of three runs. The baseline
used the identical benchmark source against the baseline crate. These rates
exclude WebSocket, TLS, networking, receiving and application work.

| Input bytes/frame | Baseline Mbit/s | Candidate Mbit/s |
| ---: | ---: | ---: |
| 1,400 | 4,500.30 | 4,667.85 |
| 16,384 | 13,043.37 | 13,580.43 |
| 65,536 | 8,216.46 | 15,944.31 |
| 262,000 | 5,711.92 | 16,432.39 |

Raw results are the adjacent JSON files. Rates use decimal bits per second;
payload sizes and RSS use binary units.

## Operational limits

Each WSS now admits at most 64 streams, including pending connects, with a
1 MiB directional credit window per negotiated stream and a 64 MiB logical
receive reservation pool. Retained DATA backing is bounded by 128 MiB, plus
bounded metadata, staging and output queues. Additional streams are rejected
cleanly. `--ws-parallel 4` offers up to 256 streams distributed across four
sessions; it does not split one stream across sessions. A 1 MiB window may
limit a single stream on a high-bandwidth, high-RTT route. See `PROTOCOL.md`
for exact negotiation, fallback and half-close semantics.

## Verification

- `cargo test -p bibavpn -p biba --locked`: passed, including 265 library,
  3 client, 20 integration and 6 `biba` tests; no filtered-out tests.
- Release client/server/example build: passed.
- `scripts/wsl-proto-v3-smoke.sh`: passed with proxy bypass disabled.
  Its historical second label says v2, but both invocations use current proto 3;
  mixed-version interoperability is covered by the separate VPS runs above.
- `scripts/docker-smoke.sh`: passed with a unique Compose project, matching
  lab credentials and 1,400-byte caps. The first attempt returned curl 52;
  subsequent explicit SOCKS/HTTP CONNECT probes and the full retry passed.
- Maintained benchmark: final binaries passed exact 1,048,583-byte direct and
  mux transfers plus server-stop negative control. The 64 MiB local failure
  described above remains an environmental limitation.
- `cargo clippy -p bibavpn -- -D warnings`: fails on the same baseline issues
  in `biba/src/parrot.rs` (unused import) and `biba/src/parse.rs`
  (`manual_is_multiple_of`). Normal clippy completes with existing warnings;
  this change does not claim a warning-free repository.
