#!/bin/sh
set -eu
cd /src

# GitHub's reuse-action lints a checkout. This bind mount is a submodule
# whose gitdir sits outside /src, so reuse cannot honour .gitignore and
# would scan target/ and ci/out/.
reuse_tree=/tmp/reuse-tree
mkdir -p "$reuse_tree"
tar -C /src \
    --exclude=./target \
    --exclude=./ci/out \
    --exclude=./.git \
    -cf - . | tar -C "$reuse_tree" -xf -
(cd "$reuse_tree" && reuse lint)

cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo clippy --workspace --locked --target wasm32-unknown-unknown -- -D warnings
python3 scripts/layering.py
cargo deny check
cargo test --workspace --locked
cargo build --workspace --locked --target wasm32-unknown-unknown
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps
cargo llvm-cov --workspace --locked --fail-under-lines 100
