# Throughput and mux isolation

User approved implementing the five findings from the performance review, testing on an isolated VPS server, and opening a PR. Production container and credentials must remain unchanged.

Implement independent TCP directions; negotiated per-stream credit flow control and byte budgets that prevent a stalled stream blocking shared reads; reduce allocations/copies without changing proto-3 AEAD layout; make explicit performance overrides take precedence over invites; replace the misleading localhost benchmark with one that proves traffic traverses the tunnel.

Compatibility: old peers must continue working with bounded legacy behavior. Use an optional extension carried by previously ignored WIN records and explicit negotiation; never assume old peers return credits. Keep DATA ordered, preserve FIN/close semantics and epoch safety, bound tasks and memory, validate credits against overflows. Do not use unbounded queues or spawn a task per frame. New/new peers should receive flow control from their first stream. Document negotiation and fallback.

Tests must cover slow-stream isolation, simultaneous upload/download, credit exhaustion/replenishment, malformed credits, teardown, old/new compatibility, config override precedence including explicit defaults/zero, and unchanged crypto format. Benchmarks report complete transfers, CPU and throughput; no unsupported claims about the VPS path's existing ~90 Mbps ceiling.
