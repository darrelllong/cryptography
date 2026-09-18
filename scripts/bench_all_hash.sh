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
# A case whose confidence interval will not converge — public-key key
# generation searches for primes, so its timing has a long tail — would
# otherwise run until someone notices. Each case gets a session limit; a case
# that reaches it is reported with the estimate it had and a mark, not dropped
# and not left running.
PILOT_SESSION_LIMIT="${PILOT_SESSION_LIMIT:-600}"

export PILOT_HASH_BYTES PILOT_HASH_XOF_OUT

# Displayed confidence percent: pilot-bench defaults to 95% unless the env
# var overrides it.
CI_PCT=95
if [[ -n "${PILOT_CONFIDENCE_LEVEL}" ]]; then
    CI_PCT=$(awk -v c="${PILOT_CONFIDENCE_LEVEL}" 'BEGIN { printf "%g", c * 100 }')
fi

measure() {
    local name=$1 outbits=$2
    local out mean ci rounds
    local extra=()
    if [[ -n "${PILOT_CONFIDENCE_LEVEL}" ]]; then
        extra+=(--confidence-level "${PILOT_CONFIDENCE_LEVEL}")
    fi
    extra+=(--session-limit "${PILOT_SESSION_LIMIT}")
    local status=0
    out=$("$BENCH" run_program --preset "$PILOT_PRESET" "${extra[@]}" \
          --pi "${name},MB/s,0,1,1" \
          -- "$HASH" "$name" 2>&1) || status=$?
    mean=$(echo  "$out" | awk '/Reading mean/{print $5}')
    ci=$(echo    "$out" | awk '/Reading CI/{print $5}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2}')
    local mark=""
    if [[ "$status" -eq 13 ]]; then
        # Pilot's session-limit code: the numbers are what it had when time ran
        # out, so they are reported with a mark rather than as a converged CI.
        mark=" (limit)"
    elif [[ "$status" -ne 0 ]]; then
        echo "pilot-bench failed for $name with status $status:" >&2
        echo "$out" >&2
        exit 1
    fi
    if [[ -z "$mean" || -z "$ci" || -z "$rounds" ]]; then
        echo "pilot-bench output for $name carried no mean, CI or round count:" >&2
        echo "$out" >&2
        exit 1
    fi
    printf "| %-12s | %5s | %8s | %8s | %5s%s |\n" \
           "$name" "$outbits" "$mean" "±$ci" "$rounds" "$mark"
}

sep() { echo "|--------------|-------|----------|----------|-------|"; }

hdr() {
    echo ""
    echo "### $1"
    echo ""
    echo "| Hash         |  Out  |   MB/s   | ±CI (${CI_PCT}%) | Runs  |"
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
