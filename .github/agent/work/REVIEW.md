VERDICT: PASS

- Request-target sanitization, private/reserved origin denylist (`allow_private` default false), 1 MiB / 5 s origin caps, and `--camouflage-allow-private` match SPEC.md; fallback on pre-byte failure is unchanged.
- Named helper and tokio tests from the spec are present in `bibavpn/src/incoming.rs` (sanitize accept/reject, IP denylist, absolute-form, origin-form `/ok`, private deny/allow, huge origin, slow origin). Slow-origin tests keep the accepted `TcpStream` alive with `pending().await` so the inner timeout is what ends the session.
- Diff stays in the listed files (`incoming.rs`, `server.rs`, README/AGENTS/PROTOCOL). No extra crates, client/wire/Docker changes, or secrets.
