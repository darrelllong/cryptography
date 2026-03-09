#!/usr/bin/env bash
# Compare the Apple-Silicon SHA-256 alternative output against the baseline
# `cryptography::Sha256` implementation.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MANIFEST="$ROOT_DIR/fast/Apple-Silicon/aarch64-alt/Cargo.toml"
VECTORS="${1:-5000}"

cd "$ROOT_DIR"
cargo run --release \
    --manifest-path "$MANIFEST" \
    --bin compare_sha256 \
    -- "$VECTORS"
