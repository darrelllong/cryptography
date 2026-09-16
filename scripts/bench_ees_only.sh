#!/usr/bin/env bash
# Run pilot-bench against just one NTRUEncrypt EES parameter set.
#
# Usage: scripts/bench_ees_only.sh <set>
#   where <set> is one of: 401ep1 443ep1 449ep1 541ep1 677ep1
#                          1087ep1 1087ep2 1171ep1 1499ep1
#
# Honors the same environment variables as bench_all_pk.sh
# (PILOT_BENCH_CLI, PILOT_PK_BIN, PILOT_PRESET, PILOT_PK_ITERS_PERCENT,
# PILOT_CONFIDENCE_LEVEL).
set -euo pipefail

SET="${1:-}"
case "$SET" in
    401ep1|443ep1|449ep1|541ep1|677ep1|1087ep1|1087ep2|1171ep1|1499ep1) ;;
    *)  echo "usage: $0 <set>  (401ep1 443ep1 449ep1 541ep1 677ep1 1087ep1 1087ep2 1171ep1 1499ep1)" >&2
        exit 2 ;;
esac

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
PK="${PILOT_PK_BIN:-$ROOT_DIR/target/release/pilot_pk}"
PILOT_PRESET="${PILOT_PRESET:-quick}"
PILOT_PK_ITERS_PERCENT="${PILOT_PK_ITERS_PERCENT:-25}"
PILOT_CONFIDENCE_LEVEL="${PILOT_CONFIDENCE_LEVEL:-}"
export PILOT_PK_ITERS_PERCENT
# Displayed confidence percent: pilot-bench defaults to 95% unless the env
# var overrides it.
CI_PCT=95
if [[ -n "${PILOT_CONFIDENCE_LEVEL}" ]]; then
    CI_PCT=$(awk -v c="${PILOT_CONFIDENCE_LEVEL}" 'BEGIN { printf "%g", c * 100 }')
fi

measure() {
    local name=$1
    local out mean ci rounds
    local extra=()
    if [[ -n "${PILOT_CONFIDENCE_LEVEL}" ]]; then
        extra+=(--confidence-level "${PILOT_CONFIDENCE_LEVEL}")
    fi
    out=$("$BENCH" run_program --preset "$PILOT_PRESET" "${extra[@]}" \
          --pi "${name},ms/op,0,1,1" \
          -- "$PK" "$name" 2>&1)
    mean=$(echo  "$out" | awk '/Reading mean/{print $5}')
    ci=$(echo    "$out" | awk '/Reading CI/{print $5}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2}')
    if [[ -z "$mean" || -z "$ci" || -z "$rounds" ]]; then
        echo "pilot-bench output for $name carried no mean, CI or round count:" >&2
        echo "$out" >&2
        exit 1
    fi
    printf "| %-32s | %10s | %10s | %5s |\n" \
           "$name" "$mean" "±$ci" "$rounds"
}

LABEL="EES$(echo "$SET" | tr '[:lower:]' '[:upper:]')"

echo ""
echo "### NTRUEncrypt $LABEL"
echo ""
echo "| Operation                        |   ms/op    | ±CI (${CI_PCT}%)  | Runs  |"
echo "|----------------------------------|------------|------------|-------|"
measure "ntruees${SET}_keygen"
measure "ntruees${SET}_encrypt"
measure "ntruees${SET}_decrypt"
echo ""
