#!/usr/bin/env bash
# Compare the x86 GHASH alternative output against the reference GHASH
# multipliers used for correctness/performance baselines.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MANIFEST="$ROOT_DIR/fast/x86/x86-alt/Cargo.toml"
VECTORS="${1:-5000}"

cd "$ROOT_DIR"
cargo run --release \
    --manifest-path "$MANIFEST" \
    --bin compare_ghash \
    -- "$VECTORS"
