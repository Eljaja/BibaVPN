# Server users and parser fuzzing

**Goal:** Add individually managed server credentials and bounded parser fuzzing.

**Architecture:** A private file-backed user registry is reloaded for every new authentication; a shared in-process counter enforces per-user limits for the lifetime of each session. Existing single-token operation stays unchanged. The existing invite generator mints a selected user's invite. Fuzz targets exercise public byte decoders with bounded PR jobs.

**Constraints:** No wire-format change; invalid registry fails closed; disabled users cannot open sessions; user tokens never appear in logs; both REALITY and v3 must use the same user policy; active sessions may finish after disable; avoid exposing credentials in examples.

1. Add registry parsing, validation, active-session accounting, atomic private registry updates, and tests for missing, disabled, duplicate and concurrent users.
2. Integrate registry authentication and lifetime accounting into both v3 and REALITY paths, preserving single-token behavior and rejecting incompatible legacy authentication. Test end-to-end including reload and concurrency.
3. Add administrative add/list/enable/disable/mint commands and operator documentation; test their behavior and file permissions.
4. Add seeded frame, protocol and ClientHello fuzz targets and a time-bounded path-scoped CI job; run each target locally.
5. Run the Rust core test suite, formatting checks on changed Rust files, and inspect the diff for accidental secrets and compatibility regressions.
