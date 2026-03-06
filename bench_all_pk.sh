#!/usr/bin/env bash
# Run the publication-facing EC / Edwards public-key operations through
# pilot-bench and emit a Markdown table.
# Columns: operation, ms/op mean, ±CI (95%), runs-to-CI
# Heavy integer-arithmetic families stay on the legacy bench_public_key path.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="${PILOT_BENCH_CLI:-$HOME/pilot-bench/build/cli/bench}"
PK="${PILOT_PK_BIN:-$ROOT_DIR/target/release/pilot_pk}"

measure() {
    local name=$1
    local out mean ci rounds
    out=$("$BENCH" run_program --preset quick \
          --pi "${name},ms/op,0,1,1" \
          -- "$PK" "$name" 2>&1)
    mean=$(echo  "$out" | awk '/Reading mean/{print $5}')
    ci=$(echo    "$out" | awk '/Reading CI/{print $5}')
    rounds=$(echo "$out" | awk '/^Rounds:/{print $2}')
    printf "| %-32s | %10s | %10s | %5s |\n" \
           "$name" "$mean" "±$ci" "$rounds"
}

sep() { echo "|----------------------------------|------------|------------|-------|"; }

hdr() {
    echo ""
    echo "### $1"
    echo ""
    echo "| Operation                        |   ms/op    | ±CI (95%)  | Runs  |"
    sep
}

hdr "ECDSA / ECDH (P-256)"
measure ecdsa_keygen
measure ecdsa_sign
measure ecdsa_verify
measure ecdh_keygen
measure ecdh_agree
measure ecdh_serialize

hdr "ECIES / EC ElGamal (P-256)"
measure ecies_keygen
measure ecies_encrypt
measure ecies_decrypt
measure ec_elgamal_keygen
measure ec_elgamal_encrypt
measure ec_elgamal_decrypt

hdr "Ed25519 / Edwards DH / Edwards ElGamal"
measure ed25519_keygen
measure ed25519_sign
measure ed25519_verify
measure edwards_dh_keygen
measure edwards_dh_agree
measure edwards_dh_serialize
measure edwards_elgamal_keygen
measure edwards_elgamal_encrypt
measure edwards_elgamal_decrypt

echo ""
