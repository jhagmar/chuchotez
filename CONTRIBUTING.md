# Contributing

Thank you for contributing to Chuchotez.

## Bootstrap

Rust 1.98, including the `wasm32-unknown-unknown` target.

Once per clone, enable the pre-commit hook so `cargo fmt --all` runs before each commit:

```bash
git config core.hooksPath .githooks
```

CI still runs `cargo fmt --all -- --check`. The hook is a local convenience.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo clippy --workspace --locked --target wasm32-unknown-unknown -- -D warnings
cargo test --workspace --locked
python3 scripts/layering.py
cargo deny check
cargo build --workspace --locked --target wasm32-unknown-unknown
cargo llvm-cov --workspace --locked --fail-under-lines 100 --lcov --output-path lcov.info
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps
```

CI runs those commands. Line coverage on measured crates is 100%. `crates/chuchotez-domain` has no crates.io dependencies.

The [README](README.md) is the short entry. [docs/book.md](docs/book.md) is the complete guide.

## Pull requests

1. Keep `chuchotez-domain` free of third-party crates and of host IO (`std::fs`, `std::net`, threads, `SystemTime`, `Instant`). Do not implement `Rng` in this workspace.
2. A change that compiles only on the host is unfinished. `wasm32-unknown-unknown` is a first-class target.
3. Fill in the pull request template.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
