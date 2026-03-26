#!/usr/bin/env bash
# Compare the x86 AES-128 alternative output against the baseline
# `cryptography::Aes128` implementation.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MANIFEST="$ROOT_DIR/fast/x86/x86-alt/Cargo.toml"
VECTORS="${1:-5000}"

cd "$ROOT_DIR"
cargo run --release \
    --manifest-path "$MANIFEST" \
    --bin compare_aes128 \
    -- "$VECTORS"
