# Local required checks

From the product root, with Docker running:

```bash
docker compose run --rm ci
docker compose run --rm codeql
```

`compose.yaml` builds `ci/Dockerfile` and bind-mounts this tree at `/src`.

## `ci`

`ci/ci.sh` is the `ci` service command. It matches the GitHub required job, plus
`reuse lint`:

1. REUSE
2. `cargo fmt --all -- --check`
3. Clippy on the host and on `wasm32-unknown-unknown` (`-D warnings`)
4. `scripts/layering.py`
5. `cargo deny check`
6. `cargo test --workspace --locked`
7. `cargo build --workspace --locked --target wasm32-unknown-unknown`
8. `cargo doc --workspace --locked --no-deps` with `RUSTDOCFLAGS='-D warnings'`
9. `cargo llvm-cov --workspace --locked --fail-under-lines 100`

`CARGO_INCREMENTAL` is `0`, matching GitHub Actions. Named volume `ci-target`
holds `/src/target`. After a large source move, `docker volume rm
chuchotez_ci-target` (or `docker compose down -v`) rebuilds that cache.

## CodeQL

`docker compose run --rm codeql` writes `ci/out/codeql.sarif` via `ci/codeql.sh`.
Codecov upload stays on GitHub.

`ci/Dockerfile` pins Ubuntu 24.04, Rust 1.98.0, cargo-llvm-cov, cargo-deny,
reuse, and CodeQL bundle 2.27.0.
