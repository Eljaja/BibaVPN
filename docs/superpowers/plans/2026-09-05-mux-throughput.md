# Mux throughput implementation plan

> Use superpowers:subagent-driven-development task by task with independent review.

**Goal:** Implement the user-approved performance improvements and validate on isolated VPS infrastructure before PR.
**Architecture:** Optional negotiated per-stream flow control over existing mux records; independent duplex pumps; bounded byte ownership; owned frame buffers and explicit config precedence.
**Tech Stack:** Rust, Tokio, tungstenite, ChaCha20-Poly1305, Python benchmark, Docker test containers.
**Spec:** docs/superpowers/specs/2026-09-05-mux-throughput.md

## Global Constraints
- Preserve production server and active client config; use throwaway VPS containers with random test credentials.
- Preserve proto-3 cryptographic wire format and old-peer interoperability.
- No unbounded queues, per-frame task spawning, or silent DATA drops; bound memory in bytes.
- Run cargo test -p bibavpn and wire smoke/e2e after changes; explain any baseline failures.
- English commit messages, no secrets in repository or reports; preserve original worktree README edit.

### Task 1: Mux flow control and duplex isolation
- Files: tcp_mux.rs, optional focused mux helper module, PROTOCOL.md, regression tests.
- First reproduce blocked duplex/common reader under bounded queues.
- Implement explicit compatible capability negotiation; byte-credit bookkeeping and bounded receive/output memory; independent per-stream read/write pumps with ordered teardown.
- Validate credit overflow/invalid records, slow-stream progress, simultaneous duplex, old peers and cancellation. Commit only owned files and report evidence.

### Task 2: Buffer pipeline
- Files: crypto_layer.rs, frame.rs, tcp_mux.rs and their tests.
- Establish format/round-trip tests against legacy encrypt/decrypt and malformed inputs.
- Encrypt in place in an owned output buffer; remove extra prefix memmoves via Bytes slices; reuse server scratch where possible without retaining unbounded buffers.
- Retain public compatibility wrappers when needed. Run focused tests and commit.

### Task 3: Effective config and trustworthy benchmarks
- Files: start_json_config.rs, bin/client.rs, config tests, scripts/wsl-local-bench.sh and Python benchmark helper.
- Reproduce explicit performance settings being overridden by invite; distinguish absent vs explicit zero/default values.
- Fix precedence for relevant performance knobs; test omitted vs explicit overrides.
- Benchmark must use a hostname resolved only at server, disable curl proxy bypass, validate full bytes, and fail negative control when tunnel stops. Use unique ports/paths, cleanup and finite deadlines.
- Run targeted tests and benchmark and commit.

### Task 4: Integrated verification and PR
- Fix baseline test read assumption if still reproduced; keep separate commit.
- Full crate tests, clippy, proto smoke, compose smoke when available, old/new VPS compatibility and same-origin baseline/candidate comparison, slow-stream/duplex regression tests.
- Independent final review, resolve defects, remove temporary VPS resources.
- Commit sanitized results; push codex branch and open PR with measured results and limitations.
