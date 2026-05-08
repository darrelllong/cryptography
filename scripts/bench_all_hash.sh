#!/usr/bin/env bash
# Run every hash function / XOF through pilot-bench and emit a Markdown table.
# Columns: hash, output bits, MB/s mean, ±CI, runs-to-CI.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
HASH="${PILOT_HASH_BIN:-$ROOT_DIR/target/release/pilot_hash}"
PILOT_PRESET="${PILOT_PRESET:-quick}"
PILOT_HASH_BYTES="${PILOT_HASH_BYTES:-262144}"
PILOT_HASH_XOF_OUT="${PILOT_HASH_XOF_OUT:-32}"
PILOT_CONFIDENCE_LEVEL="${PILOT_CONFIDENCE_LEVEL:-}"
export PILOT_HASH_BYTES PILOT_HASH_XOF_OUT

measure() {
    local name=$1 outbits=$2
    local out mean ci rounds
    local extra=()
    if [[ -n "${PILOT_CONFIDENCE_LEVEL}" ]]; then
        extra+=(--confidence-level "${PILOT_CONFIDENCE_LEVEL}")
    fi
    out=$("$BENCH" run_program --preset "$PILOT_PRESET" "${extra[@]}" \
          --pi "${name},MB/s,0,1,1" \
          -- "$HASH" "$name" 2>&1)
    mean=$(echo  "$out" | awk '/Reading mean/{print $5}')
    ci=$(echo    "$out" | awk '/Reading CI/{print $5}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2}')
    printf "| %-12s | %5s | %8s | %8s | %5s |\n" \
           "$name" "$outbits" "$mean" "±$ci" "$rounds"
}

sep() { echo "|--------------|-------|----------|----------|-------|"; }

hdr() {
    echo ""
    echo "### $1"
    echo ""
    echo "| Hash         |  Out  |   MB/s   | ±CI      | Runs  |"
    sep
}

hdr "MD5 / SHA-1 / RIPEMD-160 (legacy)"
measure md5        128
measure sha1       160
measure ripemd160  160

hdr "SHA-2 (FIPS 180-4)"
measure sha224      224
measure sha256      256
measure sha384      384
measure sha512      512
measure sha512_224  224
measure sha512_256  256

hdr "SHA-3 (FIPS 202)"
measure sha3_224    224
measure sha3_256    256
measure sha3_384    384
measure sha3_512    512

hdr "SHAKE XOFs (FIPS 202; ${PILOT_HASH_XOF_OUT}-byte squeeze)"
measure shake128    "xof"
measure shake256    "xof"

echo ""
