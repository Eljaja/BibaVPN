# Embedded split-tunnel / bypass-domains list

CI runs [`.github/scripts/ci-fetch-bypass-domains.sh`](../../../../.github/scripts/ci-fetch-bypass-domains.sh)
before building desktop / Android clients. That script downloads the JSON from the
`BIBA_BYPASS_DOMAINS_URL` repository secret into `bypass_domains.json` (gitignored).

`build.rs` copies that file (or `bypass_domains.empty.json` as a fallback) into
`OUT_DIR` so `bypass_domains.rs` can `include_str!` it at compile time.

Local builds without the secret still compile; split-tunnel presets stay empty until
runtime fetch succeeds.
