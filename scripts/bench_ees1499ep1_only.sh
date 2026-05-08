#!/usr/bin/env bash
# Run pilot-bench against just the EES1499EP1 operations.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
PK="${PILOT_PK_BIN:-$ROOT_DIR/target/release/pilot_pk}"
PILOT_PRESET="${PILOT_PRESET:-quick}"
PILOT_PK_ITERS_PERCENT="${PILOT_PK_ITERS_PERCENT:-25}"
export PILOT_PK_ITERS_PERCENT

measure() {
    local name=$1
    local out mean ci rounds
    out=$("$BENCH" run_program --preset "$PILOT_PRESET" \
          --pi "${name},ms/op,0,1,1" \
          -- "$PK" "$name" 2>&1)
    mean=$(echo  "$out" | awk '/Reading mean/{print $5}')
    ci=$(echo    "$out" | awk '/Reading CI/{print $5}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2}')
    printf "| %-32s | %10s | %10s | %5s |\n" \
           "$name" "$mean" "±$ci" "$rounds"
}

echo ""
echo "### NTRUEncrypt EES1499EP1"
echo ""
echo "| Operation                        |   ms/op    | ±CI (95%)  | Runs  |"
echo "|----------------------------------|------------|------------|-------|"
measure ntruees1499ep1_keygen
measure ntruees1499ep1_encrypt
measure ntruees1499ep1_decrypt
echo ""
