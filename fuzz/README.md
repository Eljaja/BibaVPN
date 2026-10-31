# Parser fuzzing

Install the nightly Rust toolchain and `cargo-fuzz`, then run a target from the repository root:

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
cargo +nightly fuzz run frame -- -max_total_time=30 -max_len=65536
cargo +nightly fuzz run protocol -- -max_total_time=30 -max_len=65536
cargo +nightly fuzz run clienthello -- -max_total_time=30 -max_len=65536
```

The checked-in corpus contains synthetic examples; never add captures with credentials or personal traffic. Fuzzer-generated inputs are added to the corpus directory while running. Review and minimize any useful additions before committing them. Crashes are saved in `fuzz/artifacts/`; reproduce one with `cargo +nightly fuzz run <target> <artifact>`.

The PR workflow runs each target for 30 seconds. A bounded run can find parser defects but cannot establish their absence.
