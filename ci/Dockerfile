# Toolchain image for the GitHub required checks. Source is bind-mounted at
# run; this file only pins the runner.
#
# Ubuntu 24.04 matches ubuntu-latest. Rust 1.98.0 matches rust-toolchain.toml
# and .github/workflows/ci.yml. CodeQL bundle 2.27.0 matches
# github/codeql-action v4.38.0. reuse 6.2.0 matches fsfe/reuse-action v6
# (image fsfe/reuse:6).

FROM ubuntu:24.04 AS ci

ARG RUST_VERSION=1.98.0
ARG CARGO_LLVM_COV=0.9.1
ARG CARGO_DENY=0.20.2
ARG REUSE=6.2.0

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV CARGO_TERM_COLOR=always

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        file \
        git \
        libclang-dev \
        libssl-dev \
        pkg-config \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
        -y \
        --default-toolchain "${RUST_VERSION}" \
        --profile minimal \
        --component rustfmt,clippy,llvm-tools-preview \
        --target wasm32-unknown-unknown \
        --no-modify-path

RUN cargo install cargo-llvm-cov --version "${CARGO_LLVM_COV}" --locked \
    && cargo install cargo-deny --version "${CARGO_DENY}" --locked \
    && pip3 install --break-system-packages --no-cache-dir "reuse[charset-normalizer]==${REUSE}"

WORKDIR /src
CMD ["/src/ci/ci.sh"]

FROM ci AS codeql

ARG CODEQL_BUNDLE=2.27.0

RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) bundle=codeql-bundle-linux64.tar.gz ;; \
      arm64) bundle=codeql-bundle-linux-arm64.tar.gz ;; \
      *) echo "unsupported dpkg architecture"; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_BUNDLE}/${bundle}" \
        | tar -xz -C /opt

ENV PATH=/opt/codeql:$PATH
CMD ["/src/ci/codeql.sh"]
