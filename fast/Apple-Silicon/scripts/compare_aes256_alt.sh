#!/usr/bin/env bash
# Compare the Apple-Silicon AES-256 alternative output against the baseline
# `cryptography::Aes256` implementation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VECTORS="${1:-5000}"

cd "$ROOT"
cargo run --release --manifest-path fast/Apple-Silicon/aarch64-alt/Cargo.toml --bin compare_aes256 -- "$VECTORS"
