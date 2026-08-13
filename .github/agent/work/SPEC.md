# Spec

Harden `--camouflage-dir` path resolution so URL paths cannot escape the configured directory via Windows backslash segments, drive/prefix components, or in-tree symlinks. Rejections keep the existing nginx-style 404. No wire-format change.

## Summary

`safe_static_path_under_base` in `bibavpn/src/incoming.rs` is the only boundary for `--camouflage-dir`. It splits the request path on `/` only, rejects the exact segment `..`, then `PathBuf::push`es and checks `starts_with(base_canon)` **without** canonicalizing the result.

That leaves two holes:

1. **Backslash / prefix (Windows semantics, testable on Linux).** A target such as `GET /..\..\..\windows\win.ini` is one segment. `PathBuf::push` treats `\` as a separator on Windows; `starts_with` can still pass; `tokio::fs::read` then walks `..`. Drive-style segments (`C:`) are the same class of bug. httparse leaves `\` in the path, so the function sees it raw.
2. **Symlinks (any OS).** A symlink inside the camouflage dir that points outside is not resolved before the prefix check, so `read` follows it.

`serve_camouflage_http` already maps `serve_static_file` → `None` to `write_camouflage_status(..., 404)`. Keep that mapping; do not add a distinct status, body, or header set.

## In scope

Change only `safe_static_path_under_base` (and `serve_static_file` only if the canonicalize step is cleaner there). Behavior:

1. Strip the query string and a single leading `/` as today. Empty path or a trailing `/` still maps to `index.html` (do not change directory-index mapping).
2. Split remaining relative path on `/` only. Skip empty segments (today’s `//` behavior).
3. **Reject a segment** unless it is exactly one `std::path::Component::Normal`, **and** it contains none of: `\`, `\0`, or a Windows drive/prefix (`X:` at the start of the segment, e.g. `C:`). Reject `.` and `..` via `Component` (CurDir / ParentDir), not only the string `".."`.
4. After joining onto the canonical base, keep the existing `starts_with(&base_canon)` check.
5. **`std::fs::canonicalize` the joined path** (file must exist). Re-check `canon.starts_with(&base_canon)`. Return `Some(canon)` only if both checks pass. Missing files, dangling symlinks, and escapes all become `None` (HTTP 404 via the existing caller).
6. Legitimate files and in-tree symlinks that canonicalize **inside** the base still serve as today.

Do not percent-decode the request-target in this PR: httparse does not decode today, so `%2e%2e` is a filename, not traversal. Decode-then-validate is a follow-up.

## Out of scope

- Percent-decoding / `%2e` / `%2f` / `%5c` handling.
- Changing `/subdir/` → `index.html` at the **base** (pre-existing mapping).
- `--camouflage-url` reverse-proxy paths, WS upgrade paths, or `camouflage.rs` bodies.
- Distinct 403/400, extra headers, or security log lines that could fingerprint a blocked path.
- TOCTOU between canonicalize and `read`; `openat`-style hardening.
- PROTOCOL.md, CLI flags, invites, desktop/Android UI.
- Windows CI job or privileged Windows symlink creation.

## Files to change

- `bibavpn/src/incoming.rs` — `safe_static_path_under_base`; `serve_static_file` only if canonicalize is applied there instead of (or in addition to) the helper. Extend `safe_static_path_blocks_traversal` and add a unix symlink test next to `static_file_carries_real_mtime_and_size`.

No other crates or docs.

## Tests

Run:

```bash
cargo test -p bibavpn
```

Targeted filters (same crate tests, no new harness):

```bash
cargo test -p bibavpn --lib safe_static_path_blocks_traversal
cargo test -p bibavpn --lib static_file_symlink_escape_is_rejected
cargo test -p bibavpn --lib error_404_keeps_the_404_body
cargo test -p bibavpn --lib static_file_carries_real_mtime_and_size
```

In `safe_static_path_blocks_traversal` (temp dir with `index.html`, as today):

- Keep: `"/"` is `Some`; `"/../etc/passwd"` and `"/subdir/../../outside"` are `None`.
- Add, **runnable on Linux**: mixed separators (`"/..\\..\\windows\\win.ini"`, `"/foo\\bar"`) and drive prefixes (`"/C:/Windows/win.ini"`, `"/C:\\Windows\\win.ini"`). All `None`.
- Optional: a NUL byte in a segment → `None`.

New `#[tokio::test]` (unix only is enough for CI): write a file **outside** the camouflage dir, `std::os::unix::fs::symlink` it **inside**, call `serve_static_file`. Must be `None`. A regular in-dir file (existing `static_file_carries_real_mtime_and_size`) must still be `Some`.

Do not add Docker/smoke/pcap harnesses.

## Acceptance criteria

- Backslash, mixed-separator, and drive-prefix URL paths are rejected by `safe_static_path_under_base` on Linux CI (no Windows-only asserts).
- A symlink inside `--camouflage-dir` pointing outside is not served (`serve_static_file` / the helper returns `None`).
- `serve_camouflage_http` still uses `write_camouflage_status(..., 404)` on `None`; body remains `camouflage::NOT_FOUND_HTML` (`error_404_keeps_the_404_body` still passes).
- Valid files under the base still serve; `cargo test -p bibavpn` passes.

## Non-goals

- Closing encoded-dot / encoded-slash traversal.
- Making camouflage a full static site server (directory indexes, range behavior, MIME list).
- Changing default camouflage when `--camouflage-dir` is unset.
- Fingerprint or DPI work beyond “failed static lookup looks like nginx 404”.
